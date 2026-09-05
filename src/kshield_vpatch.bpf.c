// SPDX-License-Identifier: GPL-2.0
/*
 * kshield_vpatch.bpf.c
 *
 * eBPF 기반 AI 서빙 프레임워크 취약점 가상 패치(Virtual Patching)
 *
 * 배경: Ray의 Jobs Submission API(CVE-2023-48022, "ShadowRay")처럼 인증이
 * 없는 원격 코드 실행 취약점이 악용되면, 정상적으로는 네트워크 도구를
 * 실행하지 않는 AI 워커 프로세스의 자손(descendant) 프로세스가 curl, wget
 * 같은 페이로드 다운로드용 바이너리를 실행하거나, 직접 소켓을 열어 외부와
 * 통신하게 된다.
 *
 * v2 설계 (v1의 문제를 실측으로 발견하여 수정):
 *   - v1은 "바로 위 부모"만 확인했다. 그런데 실제 실행 체인은
 *     python3(워커) → sh → curl 처럼 여러 단계를 거치므로, curl의 직속
 *     부모는 sh이지 워커가 아니라서 탐지가 안 되는 문제가 있었다.
 *   - 또한 job 실행기가 정상/악성 관계없이 항상 /bin/sh를 경유하는 구조라서,
 *     /bin/sh 자체를 의심 목록에 넣으면 정상 job까지 전부 오탐되는 문제가
 *     실제 VM 테스트에서 확인되었다.
 *   - v2는 sched_process_fork를 추가로 후킹하여 "AI 워커의 자손 프로세스"
 *     계보(lineage)를 BPF map으로 추적한다.
 *
 * v3 설계 (v2의 한계를 실측 이후 재검토하여 보강):
 *   - v2의 SHADOW_EXEC 탐지는 suspicious_bins[]라는 "실행 파일 이름
 *     블록리스트"에 의존한다. 이는 다음과 같이 쉽게 우회 가능하다는
 *     한계가 있다:
 *       (a) bash의 내장 기능(`exec 3<>/dev/tcp/host/port`)은 curl/nc 같은
 *           외부 바이너리를 실행하지 않고 자체적으로 소켓을 연다.
 *       (b) python3는 watched_parents[]에는 있지만 suspicious_bins[]에는
 *           없어, python3 자체가 urllib 등으로 직접 통신하면 탐지되지 않는다.
 *       (c) 공격자가 별도 프로세스를 실행(exec)하지 않고 원래 프로세스
 *           안에서 직접 소켓 통신만 하면, 애초에 감시할 실행 이벤트가
 *           없다.
 *   - 이 세 가지 우회의 공통점은 결국 커널의 `tcp_v4_connect`/
 *     `tcp_v6_connect`를 통해 아웃바운드 TCP 연결을 시도한다는 점이다.
 *     이는 "어떤 바이너리를 실행했는가"가 아니라 "AI 워커 계보에서 신뢰
 *     되지 않은 목적지로 나가는 연결을 시도했는가"를 감시하면, 어떤
 *     바이너리·언어로 구현되었든 상관없이 포착할 수 있다는 뜻이다.
 *   - v3는 SHADOW_CONNECT 탐지를 추가한다: AI 워커 계보에 속한 프로세스가
 *     loopback(127.0.0.0/8) 또는 trusted_dst_ipv4[]에 없는 목적지로
 *     연결을 시도하면 즉시 SIGKILL을 전송한다. 기존 SHADOW_EXEC(v2)는
 *     그대로 유지하여 두 계층이 함께 방어한다(defense-in-depth) — 알려진
 *     바이너리는 exec 시점에 더 일찍 잡고, 그 외 모든 경로는 connect
 *     시점에 잡는다.
 *   - 아울러 v2에는 프로세스 종료 시 ai_worker_lineage map을 정리하는
 *     로직이 없어, PID 재사용 시 무관한 새 프로세스가 죽은 프로세스의
 *     계보 정보를 잘못 물려받을 수 있는 버그가 있었다. v3는
 *     sched_process_exit 훅으로 이를 정리한다.
 *
 * 한계: SHADOW_CONNECT도 완전한 차단은 아니다. (1) 이미 열려 있는 정상
 * 연결에 얹혀 데이터를 빼가는 경우, (2) DNS 등 허용된 포트/프로토콜
 * 위로 데이터를 숨기는 터널링, (3) 네트워크가 아예 필요 없는 로컬
 * 전용 공격은 이 메커니즘으로 포착되지 않는다. 또한 bpf_send_signal은
 * 비동기적이므로 connect() 진입 시점에 신호를 보내도 완전한 사전 차단을
 * 보장하지는 않는다(향후 연구: security_socket_connect LSM 훅 기반의
 * 동기적 차단으로 전환 가능하나, CONFIG_BPF_LSM 및 활성 LSM 스택에 "bpf"
 * 포함이 필요해 배포 환경 의존성이 있다).
 *
 * 검증 완료(v2): VM 실측(Ubuntu, 실제 curl 사용)에서 정상 job(echo,
 * python3 -c ...)은 오탐 없이 통과하고, python3 -> sh -> curl 2단계
 * 공격 체인은 curl exec 시점에 정확히 SIGKILL로 차단됨을 확인하였다.
 * TODO(검증 필요, v3): SHADOW_CONNECT 및 lineage 정리 로직은 아직 VM
 * 실측 전이다.
 */
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_endian.h>

char LICENSE[] SEC("license") = "GPL";

#define MAX_COMM_LEN        16
#define MAX_WATCHED_PARENT   8
#define MAX_SUSPICIOUS_BIN   8
#define MAX_PATH_LEN         64
#define MAX_TRUSTED_IPS      8

#define EVT_SHADOW_EXEC    1
#define EVT_SHADOW_CONNECT 2

/* 감시 대상 AI 워커 프로세스 이름.
 * 실 배포 시 대상 프레임워크(Ray/vLLM/Triton 등)의 실제 워커 프로세스명으로
 * 교체한다. "python3"는 본 PoC의 mock 서버(python3 mock_ray_server.py)를
 * 감시하기 위해 포함되어 있으며, 실제 Ray 배포에서는 "raylet" 등으로
 * 좁혀야 오탐을 줄일 수 있다. */
const volatile char watched_parents[MAX_WATCHED_PARENT][MAX_COMM_LEN] = {
    "raylet",
    "ray::IDLE",
    "python3",
};

/* AI 워커 계보(자손 프로세스)가 실행했을 때만 의심스러운 바이너리.
 * /bin/sh, /bin/bash는 정상 job 실행에도 쓰이는 경로이므로 제외하고,
 * 실제 페이로드 다운로드/외부 연결에 쓰이는 도구만 포함한다.
 * SHADOW_CONNECT(아래)가 이 목록에 없는 경로도 커버하므로, 이 목록은
 * "알려진 바이너리를 더 일찍 잡기 위한" 보조 계층이다. */
const volatile char suspicious_bins[MAX_SUSPICIOUS_BIN][MAX_PATH_LEN] = {
    "/usr/bin/curl",
    "/usr/bin/wget",
    "/bin/nc",
    "/usr/bin/nc",
    "/usr/bin/ncat",
};

/* loopback(127.0.0.0/8) 외에 AI 워커 계보가 연결해도 되는 목적지 IPv4
 * 주소(호스트 바이트 순서). 실 배포 시 클러스터 내부 노드, 신뢰된 내부
 * 스토리지 등의 IP를 추가한다. 기본값은 비어 있음(loopback만 허용) —
 * 본 PoC의 mock 서버는 정상 job 처리 중 외부 연결이 전혀 필요 없기
 * 때문이다. */
const volatile __u32 trusted_dst_ipv4[MAX_TRUSTED_IPS] = {};

struct shadow_event {
    __u32 type;       /* EVT_SHADOW_EXEC 또는 EVT_SHADOW_CONNECT */
    __u32 pid;
    __u32 ppid;
    char  comm[MAX_COMM_LEN];
    char  parent_comm[MAX_COMM_LEN];
    char  filename[MAX_PATH_LEN]; /* EVT_SHADOW_EXEC에서만 사용 */
    __u32 dst_addr;   /* EVT_SHADOW_CONNECT에서만 사용, 호스트 바이트 순서 */
    __u16 dst_port;   /* EVT_SHADOW_CONNECT에서만 사용, 호스트 바이트 순서 */
};

struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(key_size, sizeof(int));
    __uint(value_size, sizeof(int));
} events SEC(".maps");

/* AI 워커의 자손 프로세스 계보를 추적하는 맵: pid -> 1 (계보에 속함) */
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

/* 현재 프로세스가 AI 워커 계보에 속하는지 확인.
 * lineage map에 없더라도 직속 부모가 watched_parents[]와 일치하면
 * (예: BPF 프로그램이 fork 이후·exec 이전에 로드된 경우 대비) 계보로
 * 간주한다. parent_comm_out에 직속 부모 comm을 채워 반환한다. */
static __always_inline int current_is_watched(char (*parent_comm_out)[MAX_COMM_LEN])
{
    __u32 pid = bpf_get_current_pid_tgid() >> 32;
    __u8 *in_lineage = bpf_map_lookup_elem(&ai_worker_lineage, &pid);

    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    struct task_struct *parent = BPF_CORE_READ(task, real_parent);
    /* 주의: BPF_CORE_READ_STR_INTO는 목적지 버퍼 크기를 sizeof(*dst)로
     * 추론하므로, 반드시 배열 포인터(char (*)[N]) 타입으로 넘겨야 한다.
     * 과거 char*로 넘겼다가 sizeof(*dst)==1이 되어 문자열이 사실상
     * 빈 채로 읽히는 버그가 실측으로 발견된 바 있다. */
    BPF_CORE_READ_STR_INTO(parent_comm_out, parent, comm);

    return (in_lineage != NULL) || is_watched_comm(*parent_comm_out);
}

/*
 * 프로세스가 fork될 때마다, 부모가 "AI 워커 계보"에 속하거나(이미
 * lineage map에 있음) 감시 대상 프로세스명과 일치하면, 자식도 계보에
 * 편입시킨다. 이렇게 하면 python3 → sh → curl처럼 몇 단계를 거치든
 * 계보 추적이 끊기지 않는다.
 */
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

/* 프로세스 종료 시 계보 map에서 제거하여, PID 재사용 시 무관한 새
 * 프로세스가 죽은 프로세스의 계보 정보를 잘못 물려받는 것을 방지한다. */
SEC("tp/sched/sched_process_exit")
int trace_lineage_exit(void *ctx)
{
    __u32 pid = bpf_get_current_pid_tgid() >> 32;
    bpf_map_delete_elem(&ai_worker_lineage, &pid);
    return 0;
}

SEC("tp/sched/sched_process_exec")
int trace_shadow_exec(struct trace_event_raw_sched_process_exec *ctx)
{
    char parent_comm[MAX_COMM_LEN] = {};
    if (!current_is_watched(&parent_comm))
        return 0;

    /* 실행된 바이너리 경로 읽기 (tracepoint의 __data_loc 필드) */
    char filename[MAX_PATH_LEN] = {};
    unsigned fname_off = ctx->__data_loc_filename & 0xFFFF;
    bpf_probe_read_kernel_str(&filename, sizeof(filename), (void *)ctx + fname_off);

    /* 실행된 바이너리가 의심 목록(curl/wget/nc 등)에 있는지 확인 */
    int is_suspicious = 0;
    for (int i = 0; i < MAX_SUSPICIOUS_BIN; i++) {
        if (str_eq(filename, suspicious_bins[i], MAX_PATH_LEN)) {
            is_suspicious = 1;
            break;
        }
    }
    if (!is_suspicious)
        return 0;

    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    struct task_struct *parent = BPF_CORE_READ(task, real_parent);

    /* 이상 행위 확정: AI 워커 계보에서 의심 바이너리 실행 → 이벤트 기록 후 즉시 종료 */
    struct shadow_event evt = {};
    evt.type = EVT_SHADOW_EXEC;
    evt.pid  = bpf_get_current_pid_tgid() >> 32;
    evt.ppid = BPF_CORE_READ(parent, pid);
    bpf_get_current_comm(&evt.comm, sizeof(evt.comm));
    __builtin_memcpy(evt.parent_comm, parent_comm, MAX_COMM_LEN);
    __builtin_memcpy(evt.filename, filename, MAX_PATH_LEN);

    bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &evt, sizeof(evt));

    /* sched_process_exec은 새 프로세스 컨텍스트에서 발동하므로,
     * bpf_send_signal(SIGKILL)은 방금 exec된 의심 프로세스 자신을 종료시킨다. */
    bpf_send_signal(9);

    return 0;
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

/*
 * AI 워커 계보에 속한 프로세스가 아웃바운드 TCP 연결을 시도하는 순간을
 * 감시한다. curl/wget/nc 같은 별도 바이너리를 실행하든, bash의
 * /dev/tcp/든, python3의 소켓 API든 상관없이 커널 내부에서는 결국
 * tcp_v4_connect를 거치므로, "어떤 바이너리인가"에 의존하지 않는다.
 */
SEC("kprobe/tcp_v4_connect")
int BPF_KPROBE(trace_shadow_connect_v4, struct sock *sk, struct sockaddr *uaddr, int addr_len)
{
    char parent_comm[MAX_COMM_LEN] = {};
    if (!current_is_watched(&parent_comm))
        return 0;

    struct sockaddr_in *addr_in = (struct sockaddr_in *)uaddr;
    __be32 dst_addr_be = 0;
    __be16 dst_port_be = 0;
    bpf_probe_read_kernel(&dst_addr_be, sizeof(dst_addr_be), &addr_in->sin_addr.s_addr);
    bpf_probe_read_kernel(&dst_port_be, sizeof(dst_port_be), &addr_in->sin_port);

    __u32 dst_addr = bpf_ntohl(dst_addr_be);

    if (is_loopback_or_trusted(dst_addr))
        return 0;

    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    struct task_struct *parent = BPF_CORE_READ(task, real_parent);

    struct shadow_event evt = {};
    evt.type     = EVT_SHADOW_CONNECT;
    evt.pid      = bpf_get_current_pid_tgid() >> 32;
    evt.ppid     = BPF_CORE_READ(parent, pid);
    evt.dst_addr = dst_addr;
    evt.dst_port = bpf_ntohs(dst_port_be);
    bpf_get_current_comm(&evt.comm, sizeof(evt.comm));
    __builtin_memcpy(evt.parent_comm, parent_comm, MAX_COMM_LEN);

    bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &evt, sizeof(evt));

    /* 주의: bpf_send_signal은 비동기적이라 tcp_v4_connect 자신의 완료를
     * 즉시 막지는 못한다. 완전한 사전 차단이 필요하면 향후 연구에서
     * security_socket_connect LSM 훅으로 전환하여 non-zero 반환으로
     * 연결 자체를 거부하는 방식을 검토한다. */
    bpf_send_signal(9);

    return 0;
}

SEC("kprobe/tcp_v6_connect")
int BPF_KPROBE(trace_shadow_connect_v6, struct sock *sk, struct sockaddr *uaddr, int addr_len)
{
    char parent_comm[MAX_COMM_LEN] = {};
    if (!current_is_watched(&parent_comm))
        return 0;

    struct sockaddr_in6 *addr_in6 = (struct sockaddr_in6 *)uaddr;
    struct in6_addr addr6 = {};
    __be16 dst_port_be = 0;
    bpf_probe_read_kernel(&addr6, sizeof(addr6), &addr_in6->sin6_addr);
    bpf_probe_read_kernel(&dst_port_be, sizeof(dst_port_be), &addr_in6->sin6_port);

    /* ::1 (IPv6 loopback) 확인: 앞 15바이트 0, 마지막 바이트 1 */
    int is_v6_loopback = 1;
    for (int i = 0; i < 15; i++) {
        if (addr6.in6_u.u6_addr8[i] != 0) { is_v6_loopback = 0; break; }
    }
    if (is_v6_loopback && addr6.in6_u.u6_addr8[15] != 1)
        is_v6_loopback = 0;

    if (is_v6_loopback)
        return 0;

    /* TODO(향후 연구): IPv6 목적지용 trusted 목록은 아직 없다.
     * 현재는 IPv4와 달리 loopback 외 모든 v6 목적지를 의심으로 간주한다. */

    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    struct task_struct *parent = BPF_CORE_READ(task, real_parent);

    struct shadow_event evt = {};
    evt.type     = EVT_SHADOW_CONNECT;
    evt.pid      = bpf_get_current_pid_tgid() >> 32;
    evt.ppid     = BPF_CORE_READ(parent, pid);
    evt.dst_port = bpf_ntohs(dst_port_be);
    bpf_get_current_comm(&evt.comm, sizeof(evt.comm));
    __builtin_memcpy(evt.parent_comm, parent_comm, MAX_COMM_LEN);

    bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &evt, sizeof(evt));
    bpf_send_signal(9);

    return 0;
}
