// SPDX-License-Identifier: GPL-2.0
/*
 * kshield_ctl.c — 런타임 제어 도구
 *
 * kshield_vpatch/kshield_vpatch_lsm이 핀(pin)해 둔 BPF map들을 데몬
 * 재시작·재컴파일 없이 조회/수정한다.
 *
 *   - trusted_dst_ipv4_map (v8): 신뢰 목적지 IP.
 *   - exempt_uids_map (v9): 감시 예외 UID. GPU를 오래 점유하는 job을
 *     오탐으로 SIGKILL했을 때의 비용이 크다는 점을 반영해, 검증된
 *     사용자 단위로 감시 자체를 예외 처리할 수 있게 한다.
 *   - exempt_cgroups_map (v10): 감시 예외 cgroup ID. UID보다 더 세밀한
 *     컨테이너/파드 단위 예외. 쿠버네티스 "네임스페이스" 자체는 커널이
 *     아는 개념이 아니라 K8s API 서버가 관리하는 논리적 그룹이라
 *     eBPF에서 직접 관측할 수 없으므로, 컨테이너/파드 하나하나가 보통
 *     자신만의 cgroup을 갖는다는 점을 이용한 근사치다.
 *   - watched_parents_map/watched_self_map/suspicious_bins_map (v10):
 *     감시 대상 프로세스명·의심 바이너리 목록. 새 CVE 대응이나 감시
 *     대상 프레임워크 변경 때마다 재컴파일해야 했던 문제를 해소한다.
 *
 * 사용법:
 *   kshield_ctl trust-add <ipv4> [--target v3|lsm|both]          (기본값: both)
 *   kshield_ctl trust-del <ipv4> [--target v3|lsm|both]
 *   kshield_ctl trust-list [--target v3|lsm|both]
 *   kshield_ctl exempt-add <uid> [--target v3|lsm|both]
 *   kshield_ctl exempt-del <uid> [--target v3|lsm|both]
 *   kshield_ctl exempt-list [--target v3|lsm|both]
 *   kshield_ctl cgroup-exempt-add <cgroup_id> [--target v3|lsm|both]
 *   kshield_ctl cgroup-exempt-del <cgroup_id> [--target v3|lsm|both]
 *   kshield_ctl cgroup-exempt-list [--target v3|lsm|both]
 *   kshield_ctl parent-add <comm> [--target v3|lsm|both]         감시 대상 프로세스명(자손 계보용)
 *   kshield_ctl parent-del <comm> [--target v3|lsm|both]
 *   kshield_ctl parent-list [--target v3|lsm|both]
 *   kshield_ctl self-add <comm> [--target v3|lsm|both]           감시 대상 프로세스명(자기 자신용, v6)
 *   kshield_ctl self-del <comm> [--target v3|lsm|both]
 *   kshield_ctl self-list [--target v3|lsm|both]
 *   kshield_ctl bin-add <path> [--target v3|lsm|both]            의심 바이너리 경로
 *   kshield_ctl bin-del <path> [--target v3|lsm|both]
 *   kshield_ctl bin-list [--target v3|lsm|both]
 *
 * 두 데몬은 서로 다른 BPF 오브젝트라 맵을 공유하지 않으므로(설계상 의도),
 * 기본 동작은 두 맵 모두에 동일하게 적용한다. 대상 데몬이 실행 중이
 * 아니면(핀된 맵이 없으면) 그 쪽은 경고만 남기고 건너뛴다.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <bpf/bpf.h>

#define KEY_COMM_LEN 16
#define KEY_PATH_LEN 64

struct daemon_target {
    const char *name;
    const char *path;
};

static const struct daemon_target trust_targets[2] = {
    { "v3",  "/sys/fs/bpf/kshield_trusted_ips_v3" },
    { "lsm", "/sys/fs/bpf/kshield_trusted_ips_lsm" },
};
static const struct daemon_target exempt_targets[2] = {
    { "v3",  "/sys/fs/bpf/kshield_exempt_uids_v3" },
    { "lsm", "/sys/fs/bpf/kshield_exempt_uids_lsm" },
};
static const struct daemon_target cgroup_targets[2] = {
    { "v3",  "/sys/fs/bpf/kshield_exempt_cgroups_v3" },
    { "lsm", "/sys/fs/bpf/kshield_exempt_cgroups_lsm" },
};
static const struct daemon_target parent_targets[2] = {
    { "v3",  "/sys/fs/bpf/kshield_watched_parents_v3" },
    { "lsm", "/sys/fs/bpf/kshield_watched_parents_lsm" },
};
static const struct daemon_target self_targets[2] = {
    { "v3",  "/sys/fs/bpf/kshield_watched_self_v3" },
    { "lsm", "/sys/fs/bpf/kshield_watched_self_lsm" },
};
static const struct daemon_target bin_targets[2] = {
    { "v3",  "/sys/fs/bpf/kshield_suspicious_bins_v3" },
    { "lsm", "/sys/fs/bpf/kshield_suspicious_bins_lsm" },
};

static void print_usage(const char *prog)
{
    fprintf(stderr,
        "사용법: %s <명령> <값> [--target v3|lsm|both]  (--target 생략 시 both)\n\n"
        "  trust-add/trust-del/trust-list <ipv4>          신뢰 목적지 IP\n"
        "  exempt-add/exempt-del/exempt-list <uid>        감시 예외 UID\n"
        "  cgroup-exempt-add/-del/-list <cgroup_id>       감시 예외 cgroup ID\n"
        "  parent-add/parent-del/parent-list <comm>       감시 대상 프로세스명(자손 계보용)\n"
        "  self-add/self-del/self-list <comm>             감시 대상 프로세스명(자기 자신용)\n"
        "  bin-add/bin-del/bin-list <path>                의심 바이너리 경로\n"
        "(<값>은 *-list 명령에는 필요 없음)\n",
        prog);
}

/* ---- 고정폭 정수 키(IP 4B / UID 4B / cgroup ID 8B) 리소스 ---- */

static int apply_num(const struct daemon_target *targets, const char *target_sel,
                      const char *action, const void *key,
                      void (*list_fn)(int fd, const char *label))
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
            if (bpf_map_update_elem(fd, key, &flag, BPF_ANY) != 0)
                fprintf(stderr, "[오류] %s 맵에 추가 실패: %s\n", targets[i].name, strerror(errno));
        } else if (strcmp(action, "del") == 0) {
            if (bpf_map_delete_elem(fd, key) != 0)
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

static void list_ip(int fd, const char *label)
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

static void list_uid(int fd, const char *label)
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

static void list_cgroup(int fd, const char *label)
{
    __u64 key = 0, next_key;
    __u8 val;
    int found = 0;
    printf("[%s] 감시 예외 cgroup ID 목록:\n", label);
    while (bpf_map_get_next_key(fd, found ? &key : NULL, &next_key) == 0) {
        if (bpf_map_lookup_elem(fd, &next_key, &val) == 0)
            printf("  cgroup_id=%llu\n", (unsigned long long)next_key);
        key = next_key;
        found = 1;
    }
    if (!found)
        printf("  (없음)\n");
}

/* ---- 문자열 키(comm 16B / path 64B) 리소스 ---- */

static void list_str(int fd, const char *label, int key_len, const char *what)
{
    char key[KEY_PATH_LEN] = {}, next_key[KEY_PATH_LEN] = {};
    __u8 val;
    int found = 0;
    printf("[%s] %s 목록:\n", label, what);
    while (bpf_map_get_next_key(fd, found ? key : NULL, next_key) == 0) {
        if (bpf_map_lookup_elem(fd, next_key, &val) == 0)
            printf("  %.*s\n", key_len, next_key);
        memcpy(key, next_key, key_len);
        found = 1;
    }
    if (!found)
        printf("  (없음)\n");
}

static int apply_str(const struct daemon_target *targets, const char *target_sel,
                      const char *action, const char *value, int key_len, const char *what)
{
    char key[KEY_PATH_LEN] = {};
    strncpy(key, value, key_len - 1);

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
            if (bpf_map_update_elem(fd, key, &flag, BPF_ANY) != 0)
                fprintf(stderr, "[오류] %s 맵에 추가 실패: %s\n", targets[i].name, strerror(errno));
        } else if (strcmp(action, "del") == 0) {
            if (bpf_map_delete_elem(fd, key) != 0)
                fprintf(stderr, "[오류] %s 맵에서 삭제 실패(원래 없었을 수 있음): %s\n",
                        targets[i].name, strerror(errno));
        } else {
            list_str(fd, targets[i].name, key_len, what);
        }
        close(fd);
        touched++;
    }
    return touched;
}

/* prefix로 시작하면 나머지(action)를 반환하고, 아니면 NULL */
static const char *strip_prefix(const char *s, const char *prefix)
{
    size_t n = strlen(prefix);
    return strncmp(s, prefix, n) == 0 ? s + n : NULL;
}

int main(int argc, char **argv)
{
    if (argc < 2) {
        print_usage(argv[0]);
        return 1;
    }

    const char *cmd = argv[1];
    const char *action;
    const char *target_sel = "both";
    const char *value = NULL;

    enum { R_TRUST, R_EXEMPT, R_CGROUP, R_PARENT, R_SELF, R_BIN } resource;

    if ((action = strip_prefix(cmd, "cgroup-exempt-")) != NULL)
        resource = R_CGROUP;
    else if ((action = strip_prefix(cmd, "trust-")) != NULL)
        resource = R_TRUST;
    else if ((action = strip_prefix(cmd, "exempt-")) != NULL)
        resource = R_EXEMPT;
    else if ((action = strip_prefix(cmd, "parent-")) != NULL)
        resource = R_PARENT;
    else if ((action = strip_prefix(cmd, "self-")) != NULL)
        resource = R_SELF;
    else if ((action = strip_prefix(cmd, "bin-")) != NULL)
        resource = R_BIN;
    else {
        print_usage(argv[0]);
        return 1;
    }

    if (strcmp(action, "add") != 0 && strcmp(action, "del") != 0 && strcmp(action, "list") != 0) {
        print_usage(argv[0]);
        return 1;
    }

    int arg_i = 2;
    if (strcmp(action, "list") != 0) {
        if (argc < 3) {
            fprintf(stderr, "값이 필요합니다.\n");
            print_usage(argv[0]);
            return 1;
        }
        value = argv[2];
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

    int touched = 0;

    switch (resource) {
    case R_TRUST: {
        __u32 ip_host = 0;
        if (value) {
            struct in_addr addr;
            if (inet_aton(value, &addr) == 0) {
                fprintf(stderr, "잘못된 IPv4 주소: %s\n", value);
                return 1;
            }
            ip_host = ntohl(addr.s_addr);
        }
        touched = apply_num(trust_targets, target_sel, action, &ip_host, list_ip);
        break;
    }
    case R_EXEMPT: {
        __u32 uid = 0;
        if (value) {
            char *end = NULL;
            unsigned long v = strtoul(value, &end, 10);
            if (end == value || *end != '\0') {
                fprintf(stderr, "잘못된 UID: %s\n", value);
                return 1;
            }
            uid = (__u32)v;
        }
        touched = apply_num(exempt_targets, target_sel, action, &uid, list_uid);
        break;
    }
    case R_CGROUP: {
        __u64 cgid = 0;
        if (value) {
            char *end = NULL;
            unsigned long long v = strtoull(value, &end, 10);
            if (end == value || *end != '\0') {
                fprintf(stderr, "잘못된 cgroup ID: %s\n", value);
                return 1;
            }
            cgid = (__u64)v;
        }
        touched = apply_num(cgroup_targets, target_sel, action, &cgid, list_cgroup);
        break;
    }
    case R_PARENT:
        touched = apply_str(parent_targets, target_sel, action, value ? value : "",
                             KEY_COMM_LEN, "감시 대상 프로세스명(자손 계보용)");
        break;
    case R_SELF:
        touched = apply_str(self_targets, target_sel, action, value ? value : "",
                             KEY_COMM_LEN, "감시 대상 프로세스명(자기 자신용)");
        break;
    case R_BIN:
        touched = apply_str(bin_targets, target_sel, action, value ? value : "",
                             KEY_PATH_LEN, "의심 바이너리 경로");
        break;
    }

    if (touched == 0) {
        fprintf(stderr, "대상 데몬이 하나도 실행 중이 아닙니다(핀된 맵을 찾을 수 없음).\n");
        return 1;
    }

    if (strcmp(action, "add") == 0)
        printf("%s 추가 완료 (target=%s)\n", value, target_sel);
    else if (strcmp(action, "del") == 0)
        printf("%s 삭제 완료 (target=%s)\n", value, target_sel);

    return 0;
}
