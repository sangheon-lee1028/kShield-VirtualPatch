// SPDX-License-Identifier: GPL-2.0
/*
 * kshield_vpatch.c — 사용자 공간 로더
 *
 * kshield_vpatch.bpf.c가 탐지한 두 종류의 이벤트를 perf buffer로부터
 * 수신하여 콘솔에 출력한다.
 *   - SHADOW_EXEC: AI 워커 계보가 의심 바이너리(curl/wget/nc 등)를 실행
 *   - SHADOW_CONNECT: AI 워커 계보가 신뢰되지 않은 목적지로 아웃바운드
 *     연결을 시도 (바이너리 종류와 무관하게 포착)
 * 실제 프로세스 종료(SIGKILL)는 커널 측 BPF 프로그램에서 즉시 수행되며,
 * 이 사용자 공간 프로그램은 로깅/모니터링 역할만 담당한다.
 *
 * --audit-only 플래그를 주면 탐지 이벤트는 그대로 로그로 남기되 실제
 * SIGKILL은 보내지 않는다(BPF 쪽 enforce_mode 전역 변수를 0으로 설정).
 * WAF 신규 룰을 먼저 감사(alert-only)로 배포해 오탐을 관찰한 뒤 차단으로
 * 전환하는 업계 관행을 반영한 것으로, 재컴파일 없이 실행 시점에 설정된다.
 *
 * v8: trusted_dst_ipv4_map을 /sys/fs/bpf/kshield_trusted_ips_v3에 핀해 둔다.
 * 신뢰 목적지 IP를 운영 중에 추가/삭제하려면 별도 유틸리티 kshield_ctl을
 * 쓴다 — 이 로더 자체는 맵을 만들고 핀하기만 하고, 이후의 add/del/list는
 * 전부 kshield_ctl이 담당한다.
 *
 * v9: --syslog 플래그를 주면 탐지 이벤트를 사람이 읽는 콘솔 출력에 더해
 * syslog(LOG_AUTHPRIV)로도 JSON 한 줄씩 남긴다. 기업 환경에는 이미 SIEM에
 * 로그를 모으는 rsyslog/journald 파이프라인이 있는 경우가 대부분이므로,
 * 이 프로그램만을 위한 전용 연동을 새로 만드는 대신 이미 있는 그 통로에
 * 올라타는 쪽을 택했다 — Falco 등 기존 런타임 보안 도구도 syslog를 출력
 * 채널 중 하나로 지원한다.
 *
 * v10: watched_parents_map/watched_self_map/suspicious_bins_map도
 * trusted_dst_ipv4_map과 동일하게 bpffs에 핀한다. 맵이 "새로 생성되는"
 * 경우에만(핀 경로가 아직 없을 때) 기존 PoC 기본값(raylet/ray::IDLE/
 * python3, nc/ncat 등)을 시드로 채우고, 재시작 시에는 운영자가
 * kshield_ctl로 바꿔둔 값을 그대로 둔다. exempt_cgroups_map은
 * exempt_uids_map과 동일한 목적으로 핀하되(UID보다 세밀한 컨테이너/파드
 * 단위 예외) 기본값 시드는 없다.
 */
#include <stdio.h>
#include <signal.h>
#include <unistd.h>
#include <time.h>
#include <string.h>
#include <errno.h>
#include <stdlib.h>
#include <dirent.h>
#include <syslog.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include "kshield_vpatch.skel.h"

#define MAX_COMM_LEN 16
#define MAX_PATH_LEN 64

#define EVT_SHADOW_EXEC    1
#define EVT_SHADOW_CONNECT 2

struct shadow_event {
    unsigned int type;
    unsigned int pid;
    unsigned int ppid;
    char comm[MAX_COMM_LEN];
    char parent_comm[MAX_COMM_LEN];
    char filename[MAX_PATH_LEN];
    unsigned int dst_addr;
    unsigned short dst_port;
    unsigned int enforced;
};

static volatile sig_atomic_t exiting = 0;
static int use_syslog = 0;

static void sig_handler(int signo)
{
    exiting = 1;
}

/* comm/filename은 공격자가 통제하는 프로세스 이름·경로에서 온 값이라,
 * JSON 문자열에 그대로 꽂으면 따옴표/제어문자로 로그 구조 자체를 깨뜨릴
 * 수 있다(로그 인젝션). 최소한의 이스케이프로 이를 막는다. */
static void json_escape(char *out, size_t out_sz, const char *in)
{
    size_t o = 0;
    for (size_t i = 0; in[i] != '\0' && o + 2 < out_sz; i++) {
        unsigned char c = (unsigned char)in[i];
        if (c == '"' || c == '\\') {
            out[o++] = '\\';
            out[o++] = (char)c;
        } else if (c < 0x20) {
            out[o++] = ' ';
        } else {
            out[o++] = (char)c;
        }
    }
    out[o] = '\0';
}

static void handle_event(void *ctx, int cpu, void *data, __u32 data_sz)
{
    struct shadow_event *e = data;
    time_t now = time(NULL);
    char ts[32];
    strftime(ts, sizeof(ts), "%H:%M:%S", localtime(&now));

    const char *action = e->enforced ? "SIGKILL 전송" : "[AUDIT-ONLY] 차단 안 함(로그만)";

    char parent_esc[MAX_COMM_LEN * 2] = {};
    char comm_esc[MAX_COMM_LEN * 2] = {};
    if (use_syslog) {
        json_escape(parent_esc, sizeof(parent_esc), e->parent_comm);
        json_escape(comm_esc, sizeof(comm_esc), e->comm);
    }

    if (e->type == EVT_SHADOW_EXEC) {
        printf("[%s] SHADOW_EXEC 탐지! parent=%s(pid=%u) -> child=%s(pid=%u) exec=%s => %s\n",
               ts, e->parent_comm, e->ppid, e->comm, e->pid, e->filename, action);
        if (use_syslog) {
            char file_esc[MAX_PATH_LEN * 2] = {};
            json_escape(file_esc, sizeof(file_esc), e->filename);
            syslog(LOG_ALERT,
                "{\"tool\":\"kshield_vpatch\",\"event\":\"SHADOW_EXEC\",\"parent_comm\":\"%s\",\"ppid\":%u,\"comm\":\"%s\",\"pid\":%u,\"filename\":\"%s\",\"enforced\":%s}",
                parent_esc, e->ppid, comm_esc, e->pid, file_esc, e->enforced ? "true" : "false");
        }
    } else if (e->type == EVT_SHADOW_CONNECT) {
        struct in_addr addr = { .s_addr = htonl(e->dst_addr) };
        char ip_str[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &addr, ip_str, sizeof(ip_str));
        printf("[%s] SHADOW_CONNECT 탐지! parent=%s -> proc=%s(pid=%u) dst=%s:%u => %s\n",
               ts, e->parent_comm, e->comm, e->pid, ip_str, e->dst_port, action);
        if (use_syslog) {
            syslog(LOG_ALERT,
                "{\"tool\":\"kshield_vpatch\",\"event\":\"SHADOW_CONNECT\",\"parent_comm\":\"%s\",\"comm\":\"%s\",\"pid\":%u,\"dst_ip\":\"%s\",\"dst_port\":%u,\"enforced\":%s}",
                parent_esc, comm_esc, e->pid, ip_str, e->dst_port, e->enforced ? "true" : "false");
        }
    }
    fflush(stdout);
}

static void handle_lost(void *ctx, int cpu, unsigned long long cnt)
{
    fprintf(stderr, "이벤트 유실: cpu=%d count=%llu\n", cpu, cnt);
}

static int libbpf_print_fn(enum libbpf_print_level level, const char *fmt, va_list args)
{
    return vfprintf(stderr, fmt, args);
}

/* v10: watched_parents[]/watched_self[]가 rodata에서 BPF map으로 바뀌면서
 * (아래 seed_str_map 주변 주석 참고), 더 이상 skel->rodata에서 판정 기준
 * 문자열을 읽어올 수 없다. path_exists()로 맵이 "새로 생성되는" 경우인지
 * 확인해, 그 경우에만 기존 PoC 기본값을 시드로 채운다 — 데몬이 재시작될
 * 때는 이미 핀되어 있던 맵을 그대로 재사용하므로(libbpf의 표준 동작),
 * 운영자가 kshield_ctl로 바꿔둔 값을 덮어쓰지 않는다. */
static int path_exists(const char *path)
{
    return access(path, F_OK) == 0;
}

static const char *default_watched_parents[] = { "raylet", "ray::IDLE", "python3" };
static const char *default_watched_self[]    = { "raylet", "ray::IDLE" };
static const char *default_suspicious_bins[] = { "/bin/nc", "/usr/bin/nc", "/usr/bin/ncat" };

static void seed_str_map(int fd, const char *const *values, int count, int key_len)
{
    for (int i = 0; i < count; i++) {
        char key[MAX_PATH_LEN] = {};
        strncpy(key, values[i], key_len - 1);
        __u8 flag = 1;
        bpf_map_update_elem(fd, key, &flag, BPF_ANY);
    }
}

/*
 * v7: 데몬이 이미 실행 중인 클러스터에 나중에 붙거나(최초 기동), 크래시나
 * 업데이트로 재시작되면 ai_worker_lineage map은 빈 상태로 다시 시작한다.
 * 이 map은 sched_process_fork 훅이 "새로 fork되는 순간"에만 채우므로,
 * 데몬이 뜨기 전부터 이미 떠 있던 워커의 자손 프로세스는 자기 자신이
 * 다시 fork하기 전까지 어느 훅에도 계보로 인식되지 않는다 — v6에서 고친
 * "감시 대상 자신의 직접 행위" 공백과 같은 계열의 문제이며, 트리거가
 * "재시작/최초 기동"이라는 점만 다르다.
 *
 * 커널 BPF 프로그램을 건드리지 않고(맵 스키마·훅 로직 불변) 유저스페이스
 * 로더에서 /proc을 스캔해 이미 떠 있는 프로세스들의 계보를 동일한
 * ai_worker_lineage map에 직접 채워 넣는다. 판정 기준(watched_parents_map/
 * watched_self_map)은 v10부터 BPF map 조회로 확인한다 — rodata를 읽던
 * 시절과 달리, 지금 이 순간 운영자가 kshield_ctl로 설정해 둔 최신 값을
 * 그대로 따른다.
 */
struct proc_info {
    int pid;
    int ppid;
    char comm[MAX_COMM_LEN];
};

/* /proc/PID/stat의 comm 필드는 괄호로 감싸여 있고 그 안에 공백/괄호가
 * 섞일 수 있으므로, 반드시 *마지막* ')' 뒤부터 나머지 필드를 파싱해야
 * 한다. */
static int read_proc_stat(int pid, char *comm_out, int *ppid_out)
{
    char path[64];
    snprintf(path, sizeof(path), "/proc/%d/stat", pid);
    FILE *f = fopen(path, "r");
    if (!f)
        return -1;

    char buf[512];
    size_t n = fread(buf, 1, sizeof(buf) - 1, f);
    fclose(f);
    if (n == 0)
        return -1;
    buf[n] = '\0';

    char *open_paren  = strchr(buf, '(');
    char *close_paren = strrchr(buf, ')');
    if (!open_paren || !close_paren || close_paren < open_paren)
        return -1;

    int comm_len = (int)(close_paren - open_paren - 1);
    if (comm_len < 0)
        comm_len = 0;
    if (comm_len >= MAX_COMM_LEN)
        comm_len = MAX_COMM_LEN - 1;
    memcpy(comm_out, open_paren + 1, comm_len);
    comm_out[comm_len] = '\0';

    int ppid = 0;
    if (sscanf(close_paren + 1, " %*c %d", &ppid) != 1)
        return -1;
    *ppid_out = ppid;
    return 0;
}

#define MAX_BACKFILL_PROCS 65536
#define MAX_ANCESTOR_DEPTH 64

static void backfill_existing_lineage(int lineage_map_fd,
                                       int watched_parents_fd, int watched_self_fd)
{
    struct proc_info *procs = calloc(MAX_BACKFILL_PROCS, sizeof(*procs));
    if (!procs) {
        fprintf(stderr, "[경고] 계보 백필용 메모리 할당 실패, 건너뜀\n");
        return;
    }

    DIR *d = opendir("/proc");
    if (!d) {
        fprintf(stderr, "[경고] /proc 열기 실패: %s (계보 백필 건너뜀)\n", strerror(errno));
        free(procs);
        return;
    }

    int count = 0;
    struct dirent *ent;
    while (count < MAX_BACKFILL_PROCS && (ent = readdir(d)) != NULL) {
        if (ent->d_name[0] < '0' || ent->d_name[0] > '9')
            continue;
        int pid = atoi(ent->d_name);
        char comm[MAX_COMM_LEN] = {};
        int ppid = 0;
        if (read_proc_stat(pid, comm, &ppid) != 0)
            continue; /* 스캔 도중 종료된 프로세스 등은 조용히 건너뜀 */
        procs[count].pid = pid;
        procs[count].ppid = ppid;
        memcpy(procs[count].comm, comm, MAX_COMM_LEN);
        count++;
    }
    closedir(d);

    /* 프로세스 테이블 규모(단일 호스트 기준 수백~수천)에서는 조상 탐색을
     * O(count)로 반복해도 문제없다 — 상시 훅이 아니라 데몬 기동 시 1회만
     * 실행되는 경로다. */
    int backfilled = 0;
    for (int i = 0; i < count; i++) {
        int is_lineage = 0;
        __u8 val;

        char self_key[MAX_COMM_LEN] = {};
        memcpy(self_key, procs[i].comm, MAX_COMM_LEN);
        if (bpf_map_lookup_elem(watched_self_fd, self_key, &val) == 0)
            is_lineage = 1;

        if (!is_lineage) {
            int cur_pid = procs[i].ppid;
            for (int depth = 0; depth < MAX_ANCESTOR_DEPTH && cur_pid > 1; depth++) {
                int found_idx = -1;
                for (int j = 0; j < count; j++) {
                    if (procs[j].pid == cur_pid) { found_idx = j; break; }
                }
                if (found_idx < 0)
                    break;

                char parent_key[MAX_COMM_LEN] = {};
                memcpy(parent_key, procs[found_idx].comm, MAX_COMM_LEN);
                if (bpf_map_lookup_elem(watched_parents_fd, parent_key, &val) == 0) {
                    is_lineage = 1;
                    break;
                }
                cur_pid = procs[found_idx].ppid;
            }
        }

        if (is_lineage) {
            __u32 pid_key = (__u32)procs[i].pid;
            __u8 flag = 1;
            if (bpf_map_update_elem(lineage_map_fd, &pid_key, &flag, BPF_ANY) == 0)
                backfilled++;
        }
    }

    if (backfilled > 0)
        printf("계보 백필: 데몬 기동 전부터 이미 실행 중이던 AI 워커 계보 프로세스 %d개를 편입함\n",
               backfilled);

    free(procs);
}

int main(int argc, char **argv)
{
    struct kshield_vpatch_bpf *skel;
    struct perf_buffer *pb = NULL;
    int err;
    int audit_only = 0;

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--audit-only") == 0)
            audit_only = 1;
        else if (strcmp(argv[i], "--syslog") == 0)
            use_syslog = 1;
    }

    if (use_syslog)
        openlog("kshield_vpatch", LOG_PID, LOG_AUTHPRIV);

    libbpf_set_print(libbpf_print_fn);

    skel = kshield_vpatch_bpf__open();
    if (!skel) {
        fprintf(stderr, "BPF 스켈레톤 open 실패\n");
        return 1;
    }

    skel->data->enforce_mode = audit_only ? 0 : 1;

    /* v8: trusted_dst_ipv4_map을 bpffs에 핀(pin)해, kshield_ctl 같은 별도
     * 프로세스가 데몬 재시작 없이 신뢰 목적지 IP를 add/del할 수 있게 한다.
     * 이전 실행에서 이미 핀되어 있었다면(예: 데몬 재시작) libbpf가 기존
     * 맵을 그대로 재사용하므로, 신뢰 목적지 목록도 재시작 사이에 유지된다. */
    if (bpf_map__set_pin_path(skel->maps.trusted_dst_ipv4_map, "/sys/fs/bpf/kshield_trusted_ips_v3")) {
        fprintf(stderr, "[경고] trusted_dst_ipv4_map pin 경로 설정 실패: %s\n", strerror(errno));
    }

    /* v9: exempt_uids_map도 동일한 이유로 핀한다 — GPU를 오래 점유하는
     * job을 오탐으로 죽였을 때의 비용이 크므로, 검증된 사용자(UID) 단위로
     * 감시 자체를 예외 처리할 수 있어야 한다는 지적을 반영하였다.
     * kshield_ctl exempt-add/exempt-del/exempt-list로 운영 중에 관리한다. */
    if (bpf_map__set_pin_path(skel->maps.exempt_uids_map, "/sys/fs/bpf/kshield_exempt_uids_v3")) {
        fprintf(stderr, "[경고] exempt_uids_map pin 경로 설정 실패: %s\n", strerror(errno));
    }

    /* v10: 네 개 맵을 추가로 핀한다. 앞의 세 개(watched_parents_map/
     * watched_self_map/suspicious_bins_map)는 "새로 생성되는" 경우에만
     * 기본값을 시드로 채운다 — 핀 경로가 이미 있었는지를 로드 *전에*
     * 확인해 둬야 "새로 생성됨"인지 "기존 걸 재사용함"인지 구분할 수
     * 있다. exempt_cgroups_map은 exempt_uids_map처럼 기본값 시드가
     * 없다(처음엔 아무도 예외가 아님). */
    int watched_parents_is_new = !path_exists("/sys/fs/bpf/kshield_watched_parents_v3");
    int watched_self_is_new    = !path_exists("/sys/fs/bpf/kshield_watched_self_v3");
    int suspicious_bins_is_new = !path_exists("/sys/fs/bpf/kshield_suspicious_bins_v3");

    if (bpf_map__set_pin_path(skel->maps.watched_parents_map, "/sys/fs/bpf/kshield_watched_parents_v3"))
        fprintf(stderr, "[경고] watched_parents_map pin 경로 설정 실패: %s\n", strerror(errno));
    if (bpf_map__set_pin_path(skel->maps.watched_self_map, "/sys/fs/bpf/kshield_watched_self_v3"))
        fprintf(stderr, "[경고] watched_self_map pin 경로 설정 실패: %s\n", strerror(errno));
    if (bpf_map__set_pin_path(skel->maps.suspicious_bins_map, "/sys/fs/bpf/kshield_suspicious_bins_v3"))
        fprintf(stderr, "[경고] suspicious_bins_map pin 경로 설정 실패: %s\n", strerror(errno));
    if (bpf_map__set_pin_path(skel->maps.exempt_cgroups_map, "/sys/fs/bpf/kshield_exempt_cgroups_v3"))
        fprintf(stderr, "[경고] exempt_cgroups_map pin 경로 설정 실패: %s\n", strerror(errno));

    err = kshield_vpatch_bpf__load(skel);
    if (err) {
        fprintf(stderr, "BPF 스켈레톤 로드 실패: %d\n", err);
        goto cleanup;
    }

    if (watched_parents_is_new)
        seed_str_map(bpf_map__fd(skel->maps.watched_parents_map), default_watched_parents,
                     sizeof(default_watched_parents) / sizeof(default_watched_parents[0]), MAX_COMM_LEN);
    if (watched_self_is_new)
        seed_str_map(bpf_map__fd(skel->maps.watched_self_map), default_watched_self,
                     sizeof(default_watched_self) / sizeof(default_watched_self[0]), MAX_COMM_LEN);
    if (suspicious_bins_is_new)
        seed_str_map(bpf_map__fd(skel->maps.suspicious_bins_map), default_suspicious_bins,
                     sizeof(default_suspicious_bins) / sizeof(default_suspicious_bins[0]), MAX_PATH_LEN);

    err = kshield_vpatch_bpf__attach(skel);
    if (err) {
        fprintf(stderr, "BPF 프로그램 attach 실패: %d\n", err);
        goto cleanup;
    }

    backfill_existing_lineage(bpf_map__fd(skel->maps.ai_worker_lineage),
                               bpf_map__fd(skel->maps.watched_parents_map),
                               bpf_map__fd(skel->maps.watched_self_map));

    pb = perf_buffer__new(bpf_map__fd(skel->maps.events), 16,
                           handle_event, handle_lost, NULL, NULL);
    if (!pb) {
        err = -1;
        fprintf(stderr, "perf buffer 생성 실패\n");
        goto cleanup;
    }

    if (signal(SIGINT, sig_handler) == SIG_ERR) {
        fprintf(stderr, "시그널 핸들러 등록 실패: %s\n", strerror(errno));
        goto cleanup;
    }

    printf("kShield-VirtualPatch 실행 중... (Ctrl+C로 종료)\n");
    printf("모드: %s\n", audit_only ? "AUDIT-ONLY (탐지만, 차단 안 함)" : "ENFORCE (탐지 즉시 SIGKILL)");
    printf("syslog 연동: %s\n", use_syslog ? "켜짐 (LOG_AUTHPRIV, JSON)" : "꺼짐 (--syslog로 활성화)");
    printf("감시 1: watched_parents[] 계보가 suspicious_bins[]를 실행하는지 (SHADOW_EXEC)\n");
    printf("감시 2: watched_parents[] 계보가 신뢰되지 않은 목적지로 connect()하는지 (SHADOW_CONNECT)\n\n");

    while (!exiting) {
        err = perf_buffer__poll(pb, 100);
        if (err < 0 && err != -EINTR) {
            fprintf(stderr, "perf buffer poll 오류: %s\n", strerror(-err));
            break;
        }
    }
    err = 0;

cleanup:
    perf_buffer__free(pb);
    kshield_vpatch_bpf__destroy(skel);
    if (use_syslog)
        closelog();
    return -err;
}
