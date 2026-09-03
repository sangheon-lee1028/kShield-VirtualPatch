// SPDX-License-Identifier: GPL-2.0
/*
 * kshield_vpatch.bpf.c
 *
 * eBPF 기반 AI 서빙 프레임워크 취약점 가상 패치(Virtual Patching)
 *
 * 배경: Ray의 Jobs Submission API(CVE-2023-48022, "ShadowRay")처럼 인증이
 * 없는 원격 코드 실행 취약점이 악용되면, 정상적으로는 네트워크 도구를
 * 실행하지 않는 AI 워커 프로세스의 자손(descendant) 프로세스가 curl, wget
 * 같은 페이로드 다운로드용 바이너리를 실행하게 된다.
 *
 * v2 설계 (v1의 문제를 실측으로 발견하여 수정):
 *   - v1은 "바로 위 부모"만 확인했다. 그런데 실제 실행 체인은
 *     python3(워커) → sh → curl 처럼 여러 단계를 거치므로, curl의 직속
 *     부모는 sh이지 워커가 아니라서 탐지가 안 되는 문제가 있었다.
 *   - 또한 job 실행기가 정상/악성 관계없이 항상 /bin/sh를 경유하는 구조라서,
 *     /bin/sh 자체를 의심 목록에 넣으면 정상 job까지 전부 오탐되는 문제가
 *     실제 VM 테스트에서 확인되었다.
 *   - v2는 sched_process_fork를 추가로 후킹하여 "AI 워커의 자손 프로세스"
 *     계보(lineage)를 BPF map으로 추적한다. /bin/sh, /bin/bash는 정상적인
 *     job 실행 경로이므로 의심 목록에서 제외하고, 계보에 속한 프로세스가
 *     curl/wget/nc처럼 실제 페이로드 다운로드·외부 연결에 쓰이는 바이너리를
 *     실행하는 순간만 탐지한다. 이렇게 하면 몇 단계를 거치든 탐지되면서도,
 *     정상 job(echo, python3 -c ...)은 오탐되지 않는다.
 *
 * TODO(검증 필요): v2도 아직 VM에서 전체 시나리오(정상 job 통과 + 다단계
 * 공격 탐지) 재검증이 필요하다.
 */
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

char LICENSE[] SEC("license") = "GPL";

#define MAX_COMM_LEN        16
#define MAX_WATCHED_PARENT   8
#define MAX_SUSPICIOUS_BIN   8
#define MAX_PATH_LEN         64

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
 * 실제 페이로드 다운로드/외부 연결에 쓰이는 도구만 포함한다. */
const volatile char suspicious_bins[MAX_SUSPICIOUS_BIN][MAX_PATH_LEN] = {
    "/usr/bin/curl",
    "/usr/bin/wget",
    "/bin/nc",
    "/usr/bin/nc",
    "/usr/bin/ncat",
};

struct shadow_exec_event {
    __u32 pid;
    __u32 ppid;
    char  comm[MAX_COMM_LEN];
    char  parent_comm[MAX_COMM_LEN];
    char  filename[MAX_PATH_LEN];
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
        bpf_printk("[DEBUG-FORK] lineage 편입: parent=%s(pid=%d) -> child_pid=%d",
                   parent_comm, parent_pid, child_pid);
    }

    return 0;
}

SEC("tp/sched/sched_process_exec")
int trace_shadow_exec(struct trace_event_raw_sched_process_exec *ctx)
{
    __u32 pid = bpf_get_current_pid_tgid() >> 32;

    /* 1) 현재 프로세스가 AI 워커 계보에 속하는지 확인.
     *    fork 시점에 lineage map에 등록되지 못한 경우(예: BPF 프로그램이
     *    fork 이후·exec 이전에 로드된 경우)를 대비해, 직속 부모 comm도
     *    보조적으로 함께 확인한다. */
    __u8 *in_lineage = bpf_map_lookup_elem(&ai_worker_lineage, &pid);

    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    struct task_struct *parent = BPF_CORE_READ(task, real_parent);
    char parent_comm[MAX_COMM_LEN] = {};
    BPF_CORE_READ_STR_INTO(&parent_comm, parent, comm);

    int is_watched = (in_lineage != NULL) || is_watched_comm(parent_comm);
    if (!is_watched)
        return 0;

    /* 2) 실행된 바이너리 경로 읽기 (tracepoint의 __data_loc 필드) */
    char filename[MAX_PATH_LEN] = {};
    unsigned fname_off = ctx->__data_loc_filename & 0xFFFF;
    bpf_probe_read_kernel_str(&filename, sizeof(filename), (void *)ctx + fname_off);

    bpf_printk("[DEBUG-EXEC] watched=1 pid=%d parent_comm=%s in_lineage=%d filename=%s",
               pid, parent_comm, in_lineage != NULL, filename);

    /* 3) 실행된 바이너리가 의심 목록(curl/wget/nc 등)에 있는지 확인 */
    int is_suspicious = 0;
    for (int i = 0; i < MAX_SUSPICIOUS_BIN; i++) {
        if (str_eq(filename, suspicious_bins[i], MAX_PATH_LEN)) {
            is_suspicious = 1;
            break;
        }
    }
    if (!is_suspicious)
        return 0;

    /* 이상 행위 확정: AI 워커 계보에서 의심 바이너리 실행 → 이벤트 기록 후 즉시 종료 */
    struct shadow_exec_event evt = {};
    evt.pid  = pid;
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
