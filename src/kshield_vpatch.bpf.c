// SPDX-License-Identifier: GPL-2.0
/*
 * kshield_vpatch.bpf.c
 *
 * eBPF 기반 AI 서빙 프레임워크 취약점 가상 패치(Virtual Patching)
 *
 * 배경: Ray의 Jobs Submission API(CVE-2023-48022, "ShadowRay")처럼 인증이
 * 없는 원격 코드 실행 취약점이 악용되면, 정상적으로는 쉘/네트워크 도구를
 * 실행하지 않는 AI 워커 프로세스가 갑자기 /bin/sh, curl, wget 등을 실행하게
 * 된다. 이 프로그램은 sched_process_exec 트레이스포인트를 후킹하여, 감시
 * 대상으로 지정한 부모 프로세스(comm)가 의심스러운 자식 프로세스를 실행하는
 * 순간을 탐지하고 즉시 SIGKILL을 전송한다.
 *
 * 기존 kShield의 EVIL_OPEN(파일 반복 접근 횟수 기반 탐지)과 달리, 이 탐지는
 * "정상적으로는 절대 발생하지 않는 행동이 한 번이라도 발생했는가"를 기준으로
 * 하므로 반복 임계값에 의존하지 않는다.
 *
 * TODO(검증 필요): 이 코드는 초안이며, 실제 VM 환경에서 컴파일·로드
 * 테스트를 거치지 않았다. sched_process_exec 트레이스포인트의 필드 오프셋
 * (__data_loc_filename) 등은 커널 버전에 따라 확인이 필요하다.
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

/* 감시 대상 부모 프로세스 이름 (AI 서빙 워커 프로세스).
 * 실 배포 시 대상 프레임워크(Ray/vLLM/Triton 등)의 워커 프로세스명으로
 * 교체한다. */
const volatile char watched_parents[MAX_WATCHED_PARENT][MAX_COMM_LEN] = {
    "raylet",
    "ray::IDLE",
    "python3",
};

/* 정상적인 AI 워커가 실행할 이유가 없는 의심 바이너리 목록.
 * ShadowRay 등 RCE 악용 시 공통적으로 관측되는 후속 행위(쉘 실행,
 * 페이로드 다운로드)를 기준으로 선정하였다. */
const volatile char suspicious_bins[MAX_SUSPICIOUS_BIN][MAX_PATH_LEN] = {
    "/bin/sh",
    "/bin/bash",
    "/usr/bin/curl",
    "/usr/bin/wget",
    "/bin/nc",
    "/usr/bin/nc",
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

SEC("tp/sched/sched_process_exec")
int trace_shadow_exec(struct trace_event_raw_sched_process_exec *ctx)
{
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    struct task_struct *parent = BPF_CORE_READ(task, real_parent);

    char parent_comm[MAX_COMM_LEN] = {};
    bpf_probe_read_kernel_str(&parent_comm, sizeof(parent_comm), &parent->comm);

    /* 1) 부모 프로세스가 감시 대상(AI 워커)인지 확인 */
    int is_watched = 0;
    for (int i = 0; i < MAX_WATCHED_PARENT; i++) {
        if (str_eq(parent_comm, watched_parents[i], MAX_COMM_LEN)) {
            is_watched = 1;
            break;
        }
    }
    if (!is_watched)
        return 0;

    /* 2) 실행된 바이너리 경로 읽기 (tracepoint의 __data_loc 필드) */
    char filename[MAX_PATH_LEN] = {};
    unsigned fname_off = ctx->__data_loc_filename & 0xFFFF;
    bpf_probe_read_kernel_str(&filename, sizeof(filename), (void *)ctx + fname_off);

    /* 3) 실행된 바이너리가 의심 목록에 있는지 확인 */
    int is_suspicious = 0;
    for (int i = 0; i < MAX_SUSPICIOUS_BIN; i++) {
        if (str_eq(filename, suspicious_bins[i], MAX_PATH_LEN)) {
            is_suspicious = 1;
            break;
        }
    }
    if (!is_suspicious)
        return 0;

    /* 이상 행위 확정: AI 워커가 의심 바이너리를 실행함 → 이벤트 기록 후 즉시 종료 */
    struct shadow_exec_event evt = {};
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
