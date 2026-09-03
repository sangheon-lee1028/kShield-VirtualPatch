// SPDX-License-Identifier: GPL-2.0
/*
 * kshield_vpatch.c — 사용자 공간 로더
 *
 * kshield_vpatch.bpf.c가 탐지한 SHADOW_EXEC 이벤트(AI 워커 프로세스의
 * 비정상 자식 프로세스 실행)를 perf buffer로부터 수신하여 콘솔에 출력한다.
 * 실제 프로세스 종료(SIGKILL)는 커널 측 BPF 프로그램에서 즉시 수행되며,
 * 이 사용자 공간 프로그램은 로깅/모니터링 역할만 담당한다.
 *
 * TODO(검증 필요): 실제 VM에서 kshield_vpatch.bpf.c와 함께 빌드·실행
 * 테스트가 필요하다.
 */
#include <stdio.h>
#include <signal.h>
#include <unistd.h>
#include <time.h>
#include <string.h>
#include <errno.h>
#include <bpf/libbpf.h>
#include "kshield_vpatch.skel.h"

#define MAX_COMM_LEN 16
#define MAX_PATH_LEN 64

struct shadow_exec_event {
    unsigned int pid;
    unsigned int ppid;
    char comm[MAX_COMM_LEN];
    char parent_comm[MAX_COMM_LEN];
    char filename[MAX_PATH_LEN];
};

static volatile sig_atomic_t exiting = 0;

static void sig_handler(int signo)
{
    exiting = 1;
}

static void handle_event(void *ctx, int cpu, void *data, __u32 data_sz)
{
    struct shadow_exec_event *e = data;
    time_t now = time(NULL);
    char ts[32];
    strftime(ts, sizeof(ts), "%H:%M:%S", localtime(&now));

    printf("[%s] SHADOW_EXEC 탐지! parent=%s(pid=%u) -> child=%s(pid=%u) exec=%s => SIGKILL 전송\n",
           ts, e->parent_comm, e->ppid, e->comm, e->pid, e->filename);
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
    struct kshield_vpatch_bpf *skel;
    struct perf_buffer *pb = NULL;
    int err;

    libbpf_set_print(libbpf_print_fn);

    skel = kshield_vpatch_bpf__open_and_load();
    if (!skel) {
        fprintf(stderr, "BPF 스켈레톤 로드 실패\n");
        return 1;
    }

    err = kshield_vpatch_bpf__attach(skel);
    if (err) {
        fprintf(stderr, "BPF 프로그램 attach 실패: %d\n", err);
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

    printf("kShield-VirtualPatch 실행 중... (Ctrl+C로 종료)\n");
    printf("감시 대상: watched_parents[] 프로세스가 suspicious_bins[]를 실행하는지 감시\n\n");

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
    return -err;
}
