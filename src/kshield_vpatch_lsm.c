// SPDX-License-Identifier: GPL-2.0
/*
 * kshield_vpatch_lsm.c — LSM 기반 사전 차단 사용자 공간 로더
 *
 * kshield_vpatch_lsm.bpf.c가 security_bprm_check_security /
 * security_socket_connect LSM 훅에서 동기적으로 -EPERM을 반환하여
 * 막은 시도를 perf buffer로부터 수신해 콘솔에 출력한다. 이 프로그램은
 * 로깅만 담당하며, 실제 차단은 이미 커널의 BPF LSM 프로그램이 시스템
 * 콜 반환값을 대체하는 방식으로 완료한 뒤이다(kshield_vpatch.c의
 * SIGKILL 방식과 달리, 이쪽은 "죽이기 전에 막기").
 *
 * --audit-only 플래그를 주면 탐지 이벤트는 로그로 남기되 실제 -EPERM은
 * 반환하지 않아 execve()/connect()가 정상 진행되게 둔다(BPF 쪽
 * enforce_mode 전역 변수를 0으로 설정, 재컴파일 불필요).
 */
#include <stdio.h>
#include <signal.h>
#include <unistd.h>
#include <time.h>
#include <string.h>
#include <errno.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <bpf/libbpf.h>
#include "kshield_vpatch_lsm.skel.h"

#define MAX_COMM_LEN 16
#define MAX_PATH_LEN 64

#define EVT_LSM_EXEC_BLOCK    3
#define EVT_LSM_CONNECT_BLOCK 4

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

static void sig_handler(int signo)
{
    exiting = 1;
}

/* CONFIG_BPF_LSM=y이고 활성 LSM 목록에 "bpf"가 있는지 미리 확인한다.
 * 이 확인 없이 바로 attach를 시도하면 libbpf가 내는 저수준 오류만
 * 보이고 원인(부팅 파라미터 미설정)을 알기 어렵다. */
static int check_bpf_lsm_active(void)
{
    FILE *f = fopen("/sys/kernel/security/lsm", "r");
    if (!f) {
        fprintf(stderr, "[경고] /sys/kernel/security/lsm 읽기 실패: %s\n", strerror(errno));
        return -1;
    }
    char buf[256] = {};
    size_t n = fread(buf, 1, sizeof(buf) - 1, f);
    fclose(f);
    (void)n;

    if (!strstr(buf, "bpf")) {
        fprintf(stderr,
            "[오류] 현재 활성 LSM 목록에 \"bpf\"가 없습니다: %s\n"
            "이 프로그램은 BPF_PROG_TYPE_LSM을 사용하므로, 커널 부팅\n"
            "파라미터에 lsm=...,bpf 가 포함되어야 동작합니다.\n"
            "  1) sudo nano /etc/default/grub 에서 GRUB_CMDLINE_LINUX에\n"
            "     lsm=...(기존 목록),bpf 를 추가\n"
            "  2) sudo update-grub\n"
            "  3) sudo reboot\n"
            "이 저장소의 코드는 부팅/보안 설정을 자동으로 변경하지 않으므로\n"
            "위 절차는 직접 수행해야 합니다. (kshield_vpatch, 즉 kprobe 기반\n"
            "v3는 이 설정 없이도 동작하니 그쪽을 계속 사용할 수 있습니다.)\n",
            buf);
        return -1;
    }
    printf("BPF LSM 활성 확인됨: %s", buf);
    return 0;
}

static void handle_event(void *ctx, int cpu, void *data, __u32 data_sz)
{
    struct shadow_event *e = data;
    time_t now = time(NULL);
    char ts[32];
    strftime(ts, sizeof(ts), "%H:%M:%S", localtime(&now));

    if (e->type == EVT_LSM_EXEC_BLOCK) {
        const char *action = e->enforced ? "execve() -EPERM" : "[AUDIT-ONLY] execve() 허용됨(로그만)";
        printf("[%s] LSM_EXEC_BLOCK 탐지! proc=%s(pid=%u) parent=%s exec=%s => %s\n",
               ts, e->comm, e->pid, e->parent_comm, e->filename, action);
    } else if (e->type == EVT_LSM_CONNECT_BLOCK) {
        struct in_addr addr = { .s_addr = htonl(e->dst_addr) };
        char ip_str[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &addr, ip_str, sizeof(ip_str));
        const char *action = e->enforced ? "connect() -EPERM" : "[AUDIT-ONLY] connect() 허용됨(로그만)";
        printf("[%s] LSM_CONNECT_BLOCK 탐지! proc=%s(pid=%u) parent=%s dst=%s:%u => %s\n",
               ts, e->comm, e->pid, e->parent_comm, ip_str, e->dst_port, action);
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

int main(int argc, char **argv)
{
    struct kshield_vpatch_lsm_bpf *skel;
    struct perf_buffer *pb = NULL;
    int err;
    int audit_only = 0;

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--audit-only") == 0)
            audit_only = 1;
    }

    libbpf_set_print(libbpf_print_fn);

    if (check_bpf_lsm_active() != 0)
        return 1;

    skel = kshield_vpatch_lsm_bpf__open();
    if (!skel) {
        fprintf(stderr, "BPF 스켈레톤 open 실패: %s\n", strerror(errno));
        return 1;
    }

    skel->data->enforce_mode = audit_only ? 0 : 1;

    err = kshield_vpatch_lsm_bpf__load(skel);
    if (err) {
        fprintf(stderr,
            "BPF 스켈레톤 로드 실패. CONFIG_BPF_LSM=y 커널인지,\n"
            "sudo로 실행했는지 확인하세요: %d (%s)\n", err, strerror(-err));
        goto cleanup;
    }

    err = kshield_vpatch_lsm_bpf__attach(skel);
    if (err) {
        fprintf(stderr,
            "BPF 프로그램 attach 실패: %d (%s)\n"
            "LSM 훅 attach는 CONFIG_BPF_LSM 및 lsm=...,bpf 부팅 설정에\n"
            "의존적입니다. 위 안내에 따라 확인하세요.\n", err, strerror(-err));
        goto cleanup;
    }

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

    printf("kShield-VirtualPatch-LSM 실행 중... (Ctrl+C로 종료)\n");
    printf("모드: %s\n", audit_only ? "AUDIT-ONLY (탐지만, -EPERM 반환 안 함)" : "ENFORCE (탐지 즉시 -EPERM)");
    printf("감시 1: watched_parents[] 계보의 execve()가 suspicious_bins[]이면 사전 차단 (bprm_check_security)\n");
    printf("감시 2: watched_parents[] 계보의 connect()가 신뢰되지 않은 목적지면 사전 차단 (socket_connect)\n");
    printf("메인 구현(kshield_vpatch, kprobe+SIGKILL)과 달리 시스템 콜 자체가 즉시 실패한다.\n\n");

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
    kshield_vpatch_lsm_bpf__destroy(skel);
    return -err;
}
