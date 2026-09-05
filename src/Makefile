# kShield-VirtualPatch Makefile
#
# 사전 준비 (VM에서):
#   sudo apt install -y clang llvm libbpf-dev linux-tools-$(uname -r) libelf-dev
#
# vmlinux.h 생성 (커널 BTF 기반, 최초 1회):
#   bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h
#
# 빌드 대상 두 가지:
#   kshield_vpatch      메인 구현(v3). kprobe+tracepoint, 비동기 SIGKILL.
#                        어디서나(추가 커널 설정 없이) attach 가능. 검증 완료.
#   kshield_vpatch_lsm   LSM 훅 기반 사전 차단 구현. security_bprm_check_security /
#                        security_socket_connect에서 동기적으로 -EPERM 반환.
#                        CONFIG_BPF_LSM=y 및 활성 LSM 목록에 "bpf" 필요.
#                        기능·성능 검증 완료(paper_draft.md 3.5절, 4.4절).

CLANG ?= clang
BPFTOOL ?= bpftool
ARCH := $(shell uname -m | sed 's/x86_64/x86/')

CFLAGS := -g -O2 -Wall
BPF_CFLAGS := -g -O2 -target bpf -D__TARGET_ARCH_$(ARCH) -I.

all: kshield_vpatch kshield_vpatch_lsm

kshield_vpatch.bpf.o: kshield_vpatch.bpf.c vmlinux.h
	$(CLANG) $(BPF_CFLAGS) -c $< -o $@

kshield_vpatch.skel.h: kshield_vpatch.bpf.o
	$(BPFTOOL) gen skeleton $< > $@

kshield_vpatch: kshield_vpatch.c kshield_vpatch.skel.h
	$(CLANG) $(CFLAGS) -I. $< -lbpf -lelf -lz -o $@

kshield_vpatch_lsm.bpf.o: kshield_vpatch_lsm.bpf.c vmlinux.h
	$(CLANG) $(BPF_CFLAGS) -c $< -o $@

kshield_vpatch_lsm.skel.h: kshield_vpatch_lsm.bpf.o
	$(BPFTOOL) gen skeleton $< > $@

kshield_vpatch_lsm: kshield_vpatch_lsm.c kshield_vpatch_lsm.skel.h
	$(CLANG) $(CFLAGS) -I. $< -lbpf -lelf -lz -o $@

clean:
	rm -f *.o *.skel.h kshield_vpatch kshield_vpatch_lsm

.PHONY: all clean
