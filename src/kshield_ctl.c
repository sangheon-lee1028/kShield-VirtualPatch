// SPDX-License-Identifier: GPL-2.0
/*
 * kshield_ctl.c — 신뢰 목적지 IP 런타임 제어 도구 (v8)
 *
 * kshield_vpatch/kshield_vpatch_lsm은 trusted_dst_ipv4_map을
 * /sys/fs/bpf/kshield_trusted_ips_v3, /sys/fs/bpf/kshield_trusted_ips_lsm에
 * 각각 핀(pin)해 둔다. 이 도구는 그 핀된 맵을 add/del/list하여, 데몬을
 * 재시작하거나 재컴파일하지 않고도 신뢰 목적지(클라우드 스토리지 IP 등)를
 * 운영 중에 갱신할 수 있게 한다.
 *
 * 사용법:
 *   kshield_ctl add <ipv4> [--target v3|lsm|both]   (기본값: both)
 *   kshield_ctl del <ipv4> [--target v3|lsm|both]
 *   kshield_ctl list [--target v3|lsm|both]
 *
 * 두 데몬은 서로 다른 BPF 오브젝트라 맵을 공유하지 않으므로(설계상 의도),
 * 기본 동작은 두 맵 모두에 동일하게 적용한다 — 신뢰 목적지는 어느 방어
 * 계층이 켜져 있든 동일하게 취급되어야 하기 때문이다. 대상 데몬이 실행
 * 중이 아니면(핀된 맵이 없으면) 그 쪽은 경고만 남기고 건너뛴다.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <bpf/bpf.h>

#define PIN_PATH_V3  "/sys/fs/bpf/kshield_trusted_ips_v3"
#define PIN_PATH_LSM "/sys/fs/bpf/kshield_trusted_ips_lsm"

static void print_usage(const char *prog)
{
    fprintf(stderr,
        "사용법:\n"
        "  %s add <ipv4> [--target v3|lsm|both]\n"
        "  %s del <ipv4> [--target v3|lsm|both]\n"
        "  %s list [--target v3|lsm|both]\n"
        "(--target 생략 시 기본값은 both)\n",
        prog, prog, prog);
}

static void do_list(int fd, const char *label)
{
    __u32 key = 0, next_key;
    __u8 val;
    int found = 0;

    printf("[%s] 신뢰 목적지 IP 목록:\n", label);
    while (bpf_map_get_next_key(fd, found ? &key : NULL, &next_key) == 0) {
        if (bpf_map_lookup_elem(fd, &next_key, &val) == 0) {
            struct in_addr addr = { .s_addr = htonl(next_key) };
            printf("  %s\n", inet_ntoa(addr));
        }
        key = next_key;
        found = 1;
    }
    if (!found)
        printf("  (없음 — loopback만 신뢰됨)\n");
}

static int apply_to_target(const char *target, const char *action, __u32 ip_host)
{
    struct { const char *name; const char *path; } daemons[2] = {
        { "v3",  PIN_PATH_V3 },
        { "lsm", PIN_PATH_LSM },
    };
    int touched = 0;

    for (int i = 0; i < 2; i++) {
        if (strcmp(target, "both") != 0 && strcmp(target, daemons[i].name) != 0)
            continue;

        int fd = bpf_obj_get(daemons[i].path);
        if (fd < 0) {
            fprintf(stderr, "[경고] %s 맵(%s) 열기 실패(데몬 미실행?): %s\n",
                    daemons[i].name, daemons[i].path, strerror(errno));
            continue;
        }

        if (strcmp(action, "add") == 0) {
            __u8 flag = 1;
            if (bpf_map_update_elem(fd, &ip_host, &flag, BPF_ANY) != 0)
                fprintf(stderr, "[오류] %s 맵에 추가 실패: %s\n", daemons[i].name, strerror(errno));
        } else if (strcmp(action, "del") == 0) {
            if (bpf_map_delete_elem(fd, &ip_host) != 0)
                fprintf(stderr, "[오류] %s 맵에서 삭제 실패(원래 없었을 수 있음): %s\n",
                        daemons[i].name, strerror(errno));
        } else {
            do_list(fd, daemons[i].name);
        }

        close(fd);
        touched++;
    }
    return touched;
}

int main(int argc, char **argv)
{
    if (argc < 2) {
        print_usage(argv[0]);
        return 1;
    }

    const char *action = argv[1];
    if (strcmp(action, "add") != 0 && strcmp(action, "del") != 0 && strcmp(action, "list") != 0) {
        print_usage(argv[0]);
        return 1;
    }

    const char *ip_str = NULL;
    const char *target = "both";
    int arg_i = 2;

    if (strcmp(action, "list") != 0) {
        if (argc < 3) {
            fprintf(stderr, "IPv4 주소가 필요합니다.\n");
            print_usage(argv[0]);
            return 1;
        }
        ip_str = argv[2];
        arg_i = 3;
    }

    for (int i = arg_i; i < argc; i++) {
        if (strcmp(argv[i], "--target") == 0 && i + 1 < argc) {
            target = argv[i + 1];
            i++;
        }
    }
    if (strcmp(target, "v3") != 0 && strcmp(target, "lsm") != 0 && strcmp(target, "both") != 0) {
        fprintf(stderr, "잘못된 --target 값: %s (v3|lsm|both 중 하나)\n", target);
        return 1;
    }

    __u32 ip_host = 0;
    if (ip_str) {
        struct in_addr addr;
        if (inet_aton(ip_str, &addr) == 0) {
            fprintf(stderr, "잘못된 IPv4 주소: %s\n", ip_str);
            return 1;
        }
        ip_host = ntohl(addr.s_addr);
    }

    int touched = apply_to_target(target, action, ip_host);
    if (touched == 0) {
        fprintf(stderr, "대상 데몬이 하나도 실행 중이 아닙니다(핀된 맵을 찾을 수 없음).\n");
        return 1;
    }

    if (strcmp(action, "add") == 0)
        printf("%s 추가 완료 (target=%s)\n", ip_str, target);
    else if (strcmp(action, "del") == 0)
        printf("%s 삭제 완료 (target=%s)\n", ip_str, target);

    return 0;
}
