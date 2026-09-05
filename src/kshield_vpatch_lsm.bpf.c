// SPDX-License-Identifier: GPL-2.0
/*
 * kshield_vpatch_lsm.bpf.c
 *
 * LSM 훅 기반 "동기적 사전 차단"(synchronous pre-block) 실험 구현.
 *
 * kshield_vpatch.bpf.c(v3, 메인 구현)는 kprobe(tcp_v4_connect/
 * tcp_v6_connect)와 tracepoint(sched_process_exec)로 이상 행위를
 * "감지한 뒤" bpf_send_signal(9)로 비동기 SIGKILL을 보낸다. 이 방식의
 * 근본적 한계는, connect()/execve()가 이미 커널 안에서 진행 중이거나
 * 심지어 완료된 뒤에 신호가 도착할 수 있다는 점이다 — 즉 "사후 킬"이지
 * "사전 차단"이 아니다. (이 한계는 kshield_vpatch.bpf.c 헤더 주석과
 * paper_draft.md 5장 향후연구에 명시되어 있었다.)
 *
 * 이 파일은 그 향후연구 항목을 실제로 구현한 것이다. BPF_PROG_TYPE_LSM
 * 프로그램은 커널의 실제 LSM 훅 지점(fmod_ret 트램폴린)에 붙어 원래
 * 함수의 반환값 자체를 대체할 수 있다 — 즉 connect()/execve() 시스템
 * 콜이 커널 내부에서 더 진행되기 *전에* -EPERM을 반환시켜 그 자체를
 * 막는다. 데이터가 한 바이트도 나가지 않고, 의심 바이너리는 단 한
 * 줄의 코드도 실행되지 않는다.
 *
 * 왜 메인 구현(kshield_vpatch.bpf.c)과 별도 파일/별도 바이너리인가:
 *   - BPF_PROG_TYPE_LSM은 CONFIG_BPF_LSM=y 커널과, 활성 LSM 목록
 *     (/sys/kernel/security/lsm)에 "bpf"가 포함되어야 attach가
 *     성공한다. 이는 배포 환경 의존적이라 메인 kprobe/tracepoint
 *     구현처럼 어디서나 attach 가능하다고 보장할 수 없다.
 *   - 따라서 검증된 v3 PoC를 건드리지 않고, 이 LSM 버전을 독립된
 *     실험적 상위 계층으로 추가한다. 두 프로그램을 동시에 로드해도
 *     충돌하지 않는다 — LSM 훅이 커널 호출 경로상 더 앞단이므로,
 *     이 프로그램이 먼저 -EPERM으로 막으면 connect()/execve()가
 *     tcp_v4_connect()/sched_process_exec 지점까지 도달하지 않아
 *     메인 구현의 탐지 로직은 애초에 발동되지 않는다(정상 동작).
 *     즉 "이 계층이 막으면 아래 계층은 볼 일이 없다"는 관계이며,
 *     LSM 훅 attach에 실패하는 환경에서는 메인 구현이 계속 방어망
 *     역할을 한다.
 *
 * 검증 완료: VM 실측으로 빌드·attach(attach_type lsm_mac)·기능
 * (execve()/connect() 사전 차단, 정상 job 오탐 없음)·성능 오버헤드까지
 * 확인하였다(paper_draft.md 3.5절, 4.4절 참고). 빌드/실행 전 아래 커널
 * 요구사항은 여전히 유효하다.
 *   1) zgrep 'CONFIG_BPF_LSM' /boot/config-$(uname -r)  ->  =y 여야 함
 *   2) cat /sys/kernel/security/lsm  ->  "bpf"가 포함되어야 함
 *      포함되어 있지 않다면, /etc/default/grub의 GRUB_CMDLINE_LINUX에
 *      lsm=...,bpf 를 추가하고 sudo update-grub && reboot 해야 한다.
 *      (이는 보안 설정 변경이므로 사용자가 직접 수행해야 하며, 이
 *      저장소의 어떤 코드도 부팅 설정을 자동으로 바꾸지 않는다.)
 *   attach 실패 시 사용자 공간 로더(kshield_vpatch_lsm.c)가 원인을
 *   진단할 수 있는 메시지를 출력하도록 작성되어 있다.
 */
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_endian.h>

char LICENSE[] SEC("license") = "GPL";

#define EPERM 1

#define MAX_COMM_LEN        16
#define MAX_WATCHED_PARENT   8
#define MAX_SUSPICIOUS_BIN   8
#define MAX_PATH_LEN         64
#define MAX_TRUSTED_IPS      8

#define EVT_LSM_EXEC_BLOCK    3
#define EVT_LSM_CONNECT_BLOCK 4

/* kshield_vpatch.bpf.c와 동일한 감시 목록. 이 파일은 독립된 BPF
 * 오브젝트이므로 맵/설정을 공유하지 않고 자체 사본을 둔다 — 메인
 * 구현과 서로 영향을 주지 않고 단독으로도 빌드·테스트 가능해야
 * 하기 때문이다. */
const volatile char watched_parents[MAX_WATCHED_PARENT][MAX_COMM_LEN] = {
    "raylet",
    "ray::IDLE",
    "python3",
};

/* v4 재검토: curl/wget은 여기 포함하지 않는다(kshield_vpatch.bpf.c와
 * 동일한 재검토 — 상세 근거는 그 파일 헤더 주석 참고). AI 워커가 모델
 * 가중치·데이터셋을 curl/wget으로 내려받는 것은 정상 운영이므로, 실행
 * 파일 이름만으로 exec 자체를 막으면 정당한 다운로드 job까지 오탐으로
 * 막는다. curl/wget의 위험 판단은 목적지를 아는 socket_connect 훅에
 * 전적으로 맡긴다 — exec은 통과시키고, 신뢰 안 된 목적지로 connect를
 * 시도할 때 그 자리에서 막는다. nc/ncat은 AI 워커 계보에서 합법적
 * 용도가 사실상 없어 exec 즉시 차단을 유지한다.
 *
 * /bin과 /usr/bin이 실제로는 같은 파일(심볼릭 링크)을 가리키는
 * 배포판(Ubuntu 등)에서도, execve()에 넘어가는 경로 문자열 자체는
 * 다르다. 쉘의 $PATH 탐색이 앞선 경로에서 거부당하면 뒤 경로로
 * 재시도하는 경우가 있어(VM 실측으로 실제 확인됨: /usr/bin/curl 거부
 * 후 /bin/curl로 재시도해 통과), 각 바이너리의 /bin, /usr/bin 두 경로
 * 모두 등록해야 한다. */
const volatile char suspicious_bins[MAX_SUSPICIOUS_BIN][MAX_PATH_LEN] = {
    "/bin/nc",
    "/usr/bin/nc",
    "/usr/bin/ncat",
};

const volatile __u32 trusted_dst_ipv4[MAX_TRUSTED_IPS] = {};

/* v5: audit-only(감사 전용) 모드. kshield_vpatch.bpf.c와 동일한 목적 —
 * 신규 룰을 먼저 "탐지만 하고 차단은 안 함"으로 배포해 오탐을 관찰한 뒤
 * 실제 차단(-EPERM)으로 전환할 수 있게 한다. 1(기본값)이면 기존과 동일하게
 * -EPERM으로 execve()/connect()를 실패시키고, 0이면 이벤트만 기록하고
 * 0을 반환해(허용) 원래 시스템 콜이 그대로 진행되게 둔다. const가 아닌
 * 일반 전역 변수(.data 섹션)라 재컴파일 없이 유저스페이스 로더 실행
 * 시점에 값을 설정할 수 있다 — kshield_vpatch_lsm.c의
 * skel->data->enforce_mode 참고. */
volatile __u32 enforce_mode = 1;

struct shadow_event {
    __u32 type;       /* EVT_LSM_EXEC_BLOCK 또는 EVT_LSM_CONNECT_BLOCK */
    __u32 pid;
    __u32 ppid;
    char  comm[MAX_COMM_LEN];
    char  parent_comm[MAX_COMM_LEN];
    char  filename[MAX_PATH_LEN];
    __u32 dst_addr;
    __u16 dst_port;
    __u32 enforced;   /* 1=실제 -EPERM 반환함, 0=audit-only(로그만, 통과시킴) */
};

struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(key_size, sizeof(int));
    __uint(value_size, sizeof(int));
} events SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10240);
    __type(key, __u32);
    __type(value, __u8);
} ai_worker_lineage SEC(".maps");

static __always_inline int str_eq(const char *a, const volatile char *b, int max_len)
{
    for (int i = 0; i < max_len; i++) {
        if (a[i] != b[i])
            return 0;
        if (a[i] == '\0')
            return 1;
    }
    return 1;
}

static __always_inline int is_watched_comm(const char *comm)
{
    for (int i = 0; i < MAX_WATCHED_PARENT; i++) {
        if (str_eq(comm, watched_parents[i], MAX_COMM_LEN))
            return 1;
    }
    return 0;
}

static __always_inline int current_is_watched(char (*parent_comm_out)[MAX_COMM_LEN])
{
    __u32 pid = bpf_get_current_pid_tgid() >> 32;
    __u8 *in_lineage = bpf_map_lookup_elem(&ai_worker_lineage, &pid);

    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    struct task_struct *parent = BPF_CORE_READ(task, real_parent);
    /* 주의: BPF_CORE_READ_STR_INTO는 목적지 버퍼 크기를 sizeof(*dst)로
     * 추론하므로 반드시 배열 포인터(char (*)[N]) 타입으로 넘겨야 한다
     * (kshield_vpatch.bpf.c에서 실측으로 발견된 버그와 동일한 함정). */
    BPF_CORE_READ_STR_INTO(parent_comm_out, parent, comm);

    return (in_lineage != NULL) || is_watched_comm(*parent_comm_out);
}

static __always_inline int is_loopback_or_trusted(__u32 addr_host_order)
{
    if ((addr_host_order >> 24) == 127) /* 127.0.0.0/8 */
        return 1;
    for (int i = 0; i < MAX_TRUSTED_IPS; i++) {
        if (trusted_dst_ipv4[i] != 0 && trusted_dst_ipv4[i] == addr_host_order)
            return 1;
    }
    return 0;
}

SEC("tp/sched/sched_process_fork")
int trace_lineage_fork(struct trace_event_raw_sched_process_fork *ctx)
{
    __u32 parent_pid = ctx->parent_pid;
    __u32 child_pid  = ctx->child_pid;

    __u8 *already_in_lineage = bpf_map_lookup_elem(&ai_worker_lineage, &parent_pid);

    char parent_comm[MAX_COMM_LEN] = {};
    bpf_probe_read_kernel_str(&parent_comm, sizeof(parent_comm), ctx->parent_comm);

    if (already_in_lineage || is_watched_comm(parent_comm)) {
        __u8 flag = 1;
        bpf_map_update_elem(&ai_worker_lineage, &child_pid, &flag, BPF_ANY);
    }

    return 0;
}

SEC("tp/sched/sched_process_exit")
int trace_lineage_exit(void *ctx)
{
    __u32 pid = bpf_get_current_pid_tgid() >> 32;
    bpf_map_delete_elem(&ai_worker_lineage, &pid);
    return 0;
}

/*
 * security_bprm_check_security 훅: execve()가 새 프로그램 이미지로
 * 실제 교체되기 *전에* 호출된다. 여기서 -EPERM을 반환하면 execve()
 * 시스템 콜 자체가 실패하며, 의심 바이너리는 단 한 명령어도 실행되지
 * 않는다. (대응하는 메인 구현의 SHADOW_EXEC는 exec *이후* tracepoint에서
 * 잡아 SIGKILL을 보내므로, 이 프로그램이 성공적으로 attach된 환경에서는
 * 이 훅이 항상 더 먼저/더 강하게 작동한다.)
 *
 * BPF_PROG의 마지막 인자 `ret`는 이 훅 체인에서 앞서 실행된 다른 LSM이
 * 이미 내린 판정값이다. 0이 아니면(이미 다른 모듈이 거부했으면) 그대로
 * 반환하여 존중한다 — BPF LSM 프로그램의 표준 관례.
 */
SEC("lsm/bprm_check_security")
int BPF_PROG(kshield_lsm_bprm_check, struct linux_binprm *bprm, int ret)
{
    if (ret != 0)
        return ret;

    char parent_comm[MAX_COMM_LEN] = {};
    if (!current_is_watched(&parent_comm))
        return 0;

    char filename[MAX_PATH_LEN] = {};
    const char *fname_ptr = BPF_CORE_READ(bprm, filename);
    bpf_probe_read_kernel_str(&filename, sizeof(filename), fname_ptr);

    int is_suspicious = 0;
    for (int i = 0; i < MAX_SUSPICIOUS_BIN; i++) {
        if (str_eq(filename, suspicious_bins[i], MAX_PATH_LEN)) {
            is_suspicious = 1;
            break;
        }
    }
    if (!is_suspicious)
        return 0;

    struct shadow_event evt = {};
    evt.type = EVT_LSM_EXEC_BLOCK;
    evt.pid  = bpf_get_current_pid_tgid() >> 32;
    bpf_get_current_comm(&evt.comm, sizeof(evt.comm));
    __builtin_memcpy(evt.parent_comm, parent_comm, MAX_COMM_LEN);
    __builtin_memcpy(evt.filename, filename, MAX_PATH_LEN);
    evt.enforced = enforce_mode;
    bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &evt, sizeof(evt));

    /* 동기적 차단: execve() 자체가 여기서 -EPERM으로 즉시 실패한다.
     * SIGKILL과 달리 "이미 실행된 뒤 죽이는" 것이 아니라 애초에 실행이
     * 시작되지 않는다. audit-only 모드(enforce_mode=0)에서는 0을
     * 반환하여 원래 execve()가 그대로 진행되게 둔다. */
    return enforce_mode ? -EPERM : 0;
}

/*
 * security_socket_connect 훅: connect()가 실제 프로토콜 계층(예:
 * tcp_v4_connect)까지 내려가기 *전에* 호출된다. 여기서 -EPERM을
 * 반환하면 connect() 시스템 콜 자체가 실패하며, 3-way 핸드셰이크가
 * 시작조차 되지 않는다. bash `/dev/tcp/`든, python3 소켓이든, 어떤
 * 바이너리/언어로 구현되었든 결국 이 훅을 통과해야 하므로 메인 구현의
 * SHADOW_CONNECT(v3)와 동일한 우회-불가 성질을 가지면서, 비동기
 * SIGKILL 대신 동기적으로 차단한다는 점이 다르다.
 */
SEC("lsm/socket_connect")
int BPF_PROG(kshield_lsm_socket_connect, struct socket *sock, struct sockaddr *address, int addrlen, int ret)
{
    if (ret != 0)
        return ret;

    char parent_comm[MAX_COMM_LEN] = {};
    if (!current_is_watched(&parent_comm))
        return 0;

    /* TCP만 대상으로 한다(메인 구현의 tcp_v4_connect/tcp_v6_connect
     * 훅과 범위를 맞춤). UDP(예: DNS 조회)까지 막으면 정상 동작이
     * 깨질 수 있어 제외한다. */
    unsigned short sock_type = BPF_CORE_READ(sock, type);
    if (sock_type != 1 /* SOCK_STREAM */)
        return 0;

    unsigned short family = BPF_CORE_READ(address, sa_family);

    if (family == 2 /* AF_INET */) {
        struct sockaddr_in *addr_in = (struct sockaddr_in *)address;
        __be32 dst_addr_be = 0;
        __be16 dst_port_be = 0;
        bpf_probe_read_kernel(&dst_addr_be, sizeof(dst_addr_be), &addr_in->sin_addr.s_addr);
        bpf_probe_read_kernel(&dst_port_be, sizeof(dst_port_be), &addr_in->sin_port);
        __u32 dst_addr = bpf_ntohl(dst_addr_be);

        if (is_loopback_or_trusted(dst_addr))
            return 0;

        struct shadow_event evt = {};
        evt.type     = EVT_LSM_CONNECT_BLOCK;
        evt.pid      = bpf_get_current_pid_tgid() >> 32;
        evt.dst_addr = dst_addr;
        evt.dst_port = bpf_ntohs(dst_port_be);
        bpf_get_current_comm(&evt.comm, sizeof(evt.comm));
        __builtin_memcpy(evt.parent_comm, parent_comm, MAX_COMM_LEN);
        evt.enforced = enforce_mode;
        bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &evt, sizeof(evt));

        /* 동기적 차단: connect()가 즉시 실패, 핸드셰이크 시작 안 함.
         * audit-only 모드에서는 0을 반환해 연결을 그대로 허용한다. */
        return enforce_mode ? -EPERM : 0;
    }

    if (family == 10 /* AF_INET6 */) {
        struct sockaddr_in6 *addr_in6 = (struct sockaddr_in6 *)address;
        struct in6_addr addr6 = {};
        __be16 dst_port_be = 0;
        bpf_probe_read_kernel(&addr6, sizeof(addr6), &addr_in6->sin6_addr);
        bpf_probe_read_kernel(&dst_port_be, sizeof(dst_port_be), &addr_in6->sin6_port);

        int is_v6_loopback = 1;
        for (int i = 0; i < 15; i++) {
            if (addr6.in6_u.u6_addr8[i] != 0) { is_v6_loopback = 0; break; }
        }
        if (is_v6_loopback && addr6.in6_u.u6_addr8[15] != 1)
            is_v6_loopback = 0;

        if (is_v6_loopback)
            return 0;

        /* TODO(향후 연구): 메인 구현과 동일하게 IPv6 trusted 목록은
         * 아직 없다. loopback 외 모든 v6 목적지를 의심으로 간주한다. */

        struct shadow_event evt = {};
        evt.type     = EVT_LSM_CONNECT_BLOCK;
        evt.pid      = bpf_get_current_pid_tgid() >> 32;
        evt.dst_port = bpf_ntohs(dst_port_be);
        bpf_get_current_comm(&evt.comm, sizeof(evt.comm));
        __builtin_memcpy(evt.parent_comm, parent_comm, MAX_COMM_LEN);
        evt.enforced = enforce_mode;
        bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &evt, sizeof(evt));

        return enforce_mode ? -EPERM : 0;
    }

    return 0;
}
