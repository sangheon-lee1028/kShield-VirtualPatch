// SPDX-License-Identifier: GPL-2.0
/*
 * kshield_ctl.c — 런타임 제어 도구
 *
 * kshield_vpatch/kshield_vpatch_lsm이 핀(pin)해 둔 두 종류의 BPF map을
 * 데몬 재시작·재컴파일 없이 조회/수정한다.
 *
 *   - trusted_dst_ipv4_map (v8): 신뢰 목적지 IP. 클라우드 스토리지(S3,
 *     HuggingFace 등) IP처럼 운영 중 자주 바뀌는 목적지를 컴파일 타임
 *     rodata 배열로 두면 IP 하나 추가할 때마다 재컴파일이 필요해지는
 *     문제를 해소한다.
 *   - exempt_uids_map (v9): 감시 예외 UID. GPU를 오래 점유하는 job을
 *     오탐으로 SIGKILL했을 때의 비용이 크다는 점을 반영해, 검증된
 *     사용자 단위로 감시 자체를 예외 처리할 수 있게 한다.
 *
 * 사용법:
 *   kshield_ctl trust-add <ipv4> [--target v3|lsm|both]    (기본값: both)
 *   kshield_ctl trust-del <ipv4> [--target v3|lsm|both]
 *   kshield_ctl trust-list [--target v3|lsm|both]
 *   kshield_ctl exempt-add <uid> [--target v3|lsm|both]
 *   kshield_ctl exempt-del <uid> [--target v3|lsm|both]
 *   kshield_ctl exempt-list [--target v3|lsm|both]
 *
 * 두 데몬은 서로 다른 BPF 오브젝트라 맵을 공유하지 않으므로(설계상 의도),
 * 기본 동작은 두 맵 모두에 동일하게 적용한다 — 신뢰 목적지·예외 UID는
 * 어느 방어 계층이 켜져 있든 동일하게 취급되어야 하기 때문이다. 대상
 * 데몬이 실행 중이 아니면(핀된 맵이 없으면) 그 쪽은 경고만 남기고
 * 건너뛴다.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <bpf/bpf.h>

#define PIN_TRUST_V3   "/sys/fs/bpf/kshield_trusted_ips_v3"
#define PIN_TRUST_LSM  "/sys/fs/bpf/kshield_trusted_ips_lsm"
#define PIN_EXEMPT_V3  "/sys/fs/bpf/kshield_exempt_uids_v3"
#define PIN_EXEMPT_LSM "/sys/fs/bpf/kshield_exempt_uids_lsm"

struct daemon_target {
    const char *name;
    const char *path;
};

static void print_usage(const char *prog)
{
    fprintf(stderr,
        "사용법:\n"
        "  %s trust-add <ipv4> [--target v3|lsm|both]   신뢰 목적지 IP 추가\n"
        "  %s trust-del <ipv4> [--target v3|lsm|both]   신뢰 목적지 IP 삭제\n"
        "  %s trust-list [--target v3|lsm|both]         신뢰 목적지 IP 목록\n"
        "  %s exempt-add <uid> [--target v3|lsm|both]   UID 감시 예외 추가\n"
        "  %s exempt-del <uid> [--target v3|lsm|both]   UID 감시 예외 삭제\n"
        "  %s exempt-list [--target v3|lsm|both]        UID 감시 예외 목록\n"
        "(--target 생략 시 기본값은 both)\n",
        prog, prog, prog, prog, prog, prog);
}

static void list_ip_entries(int fd, const char *label)
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

static void list_uid_entries(int fd, const char *label)
{
    __u32 key = 0, next_key;
    __u8 val;
    int found = 0;

    printf("[%s] 감시 예외 UID 목록:\n", label);
    while (bpf_map_get_next_key(fd, found ? &key : NULL, &next_key) == 0) {
        if (bpf_map_lookup_elem(fd, &next_key, &val) == 0)
            printf("  uid=%u\n", next_key);
        key = next_key;
        found = 1;
    }
    if (!found)
        printf("  (없음)\n");
}

static int apply(const struct daemon_target *targets, const char *target_sel,
                  const char *action, __u32 key, void (*list_fn)(int, const char *))
{
    int touched = 0;

    for (int i = 0; i < 2; i++) {
        if (strcmp(target_sel, "both") != 0 && strcmp(target_sel, targets[i].name) != 0)
            continue;

        int fd = bpf_obj_get(targets[i].path);
        if (fd < 0) {
            fprintf(stderr, "[경고] %s 맵(%s) 열기 실패(데몬 미실행?): %s\n",
                    targets[i].name, targets[i].path, strerror(errno));
            continue;
        }

        if (strcmp(action, "add") == 0) {
            __u8 flag = 1;
            if (bpf_map_update_elem(fd, &key, &flag, BPF_ANY) != 0)
                fprintf(stderr, "[오류] %s 맵에 추가 실패: %s\n", targets[i].name, strerror(errno));
        } else if (strcmp(action, "del") == 0) {
            if (bpf_map_delete_elem(fd, &key) != 0)
                fprintf(stderr, "[오류] %s 맵에서 삭제 실패(원래 없었을 수 있음): %s\n",
                        targets[i].name, strerror(errno));
        } else {
            list_fn(fd, targets[i].name);
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

    const char *cmd = argv[1];
    int is_trust  = (strncmp(cmd, "trust-", 6) == 0);
    int is_exempt = (strncmp(cmd, "exempt-", 7) == 0);
    if (!is_trust && !is_exempt) {
        print_usage(argv[0]);
        return 1;
    }

    const char *action = is_trust ? cmd + 6 : cmd + 7; /* "add" / "del" / "list" */
    if (strcmp(action, "add") != 0 && strcmp(action, "del") != 0 && strcmp(action, "list") != 0) {
        print_usage(argv[0]);
        return 1;
    }

    const char *val_str = NULL;
    const char *target_sel = "both";
    int arg_i = 2;

    if (strcmp(action, "list") != 0) {
        if (argc < 3) {
            fprintf(stderr, "%s가 필요합니다.\n", is_trust ? "IPv4 주소" : "UID");
            print_usage(argv[0]);
            return 1;
        }
        val_str = argv[2];
        arg_i = 3;
    }

    for (int i = arg_i; i < argc; i++) {
        if (strcmp(argv[i], "--target") == 0 && i + 1 < argc) {
            target_sel = argv[i + 1];
            i++;
        }
    }
    if (strcmp(target_sel, "v3") != 0 && strcmp(target_sel, "lsm") != 0 && strcmp(target_sel, "both") != 0) {
        fprintf(stderr, "잘못된 --target 값: %s (v3|lsm|both 중 하나)\n", target_sel);
        return 1;
    }

    __u32 key = 0;
    if (val_str) {
        if (is_trust) {
            struct in_addr addr;
            if (inet_aton(val_str, &addr) == 0) {
                fprintf(stderr, "잘못된 IPv4 주소: %s\n", val_str);
                return 1;
            }
            key = ntohl(addr.s_addr);
        } else {
            char *end = NULL;
            unsigned long uid = strtoul(val_str, &end, 10);
            if (end == val_str || *end != '\0') {
                fprintf(stderr, "잘못된 UID: %s\n", val_str);
                return 1;
            }
            key = (__u32)uid;
        }
    }

    struct daemon_target targets[2];
    if (is_trust) {
        targets[0] = (struct daemon_target){ "v3",  PIN_TRUST_V3 };
        targets[1] = (struct daemon_target){ "lsm", PIN_TRUST_LSM };
    } else {
        targets[0] = (struct daemon_target){ "v3",  PIN_EXEMPT_V3 };
        targets[1] = (struct daemon_target){ "lsm", PIN_EXEMPT_LSM };
    }

    int touched = apply(targets, target_sel, action, key, is_trust ? list_ip_entries : list_uid_entries);
    if (touched == 0) {
        fprintf(stderr, "대상 데몬이 하나도 실행 중이 아닙니다(핀된 맵을 찾을 수 없음).\n");
        return 1;
    }

    if (strcmp(action, "add") == 0)
        printf("%s 추가 완료 (target=%s)\n", val_str, target_sel);
    else if (strcmp(action, "del") == 0)
        printf("%s 삭제 완료 (target=%s)\n", val_str, target_sel);

    return 0;
}
