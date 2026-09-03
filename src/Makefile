# kShield-VirtualPatch Makefile
#
# 사전 준비 (VM에서):
#   sudo apt install -y clang llvm libbpf-dev linux-tools-$(uname -r) libelf-dev
#
# vmlinux.h 생성 (커널 BTF 기반, 최초 1회):
#   bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h
#
# TODO(검증 필요): 이 Makefile은 초안이며 실제 빌드 테스트가 필요하다.
# libbpf 헤더 경로, bpftool 경로는 환경에 따라 조정해야 할 수 있다.

CLANG ?= clang
BPFTOOL ?= bpftool
ARCH := $(shell uname -m | sed 's/x86_64/x86/')

CFLAGS := -g -O2 -Wall
BPF_CFLAGS := -g -O2 -target bpf -D__TARGET_ARCH_$(ARCH) -I.

all: kshield_vpatch

kshield_vpatch.bpf.o: kshield_vpatch.bpf.c vmlinux.h
	$(CLANG) $(BPF_CFLAGS) -c $< -o $@

kshield_vpatch.skel.h: kshield_vpatch.bpf.o
	$(BPFTOOL) gen skeleton $< > $@

kshield_vpatch: kshield_vpatch.c kshield_vpatch.skel.h
	$(CLANG) $(CFLAGS) -I. $< -lbpf -lelf -lz -o $@

clean:
	rm -f *.o *.skel.h kshield_vpatch

.PHONY: all clean
