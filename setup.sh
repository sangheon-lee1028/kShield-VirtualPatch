#!/usr/bin/env bash
# setup.sh — kShield-VirtualPatch VM 환경 설정
#
# Ubuntu/Debian 계열 VM에서 eBPF 빌드에 필요한 패키지를 설치하고
# vmlinux.h(커널 BTF 기반 헤더)를 생성한다.
#
# 사용법: bash setup.sh

set -euo pipefail

echo "=== 1) 빌드 의존성 설치 ==="
sudo apt update
sudo apt install -y clang llvm libelf-dev libbpf-dev linux-tools-common \
    linux-tools-generic linux-tools-"$(uname -r)" python3 make

echo "=== 2) BTF 지원 확인 ==="
if [ ! -f /sys/kernel/btf/vmlinux ]; then
    echo "[오류] /sys/kernel/btf/vmlinux 가 없습니다. 커널이 BTF를 지원하지 않습니다." >&2
    exit 1
fi
echo "BTF 지원 확인됨."

echo "=== 3) vmlinux.h 생성 ==="
bpftool btf dump file /sys/kernel/btf/vmlinux format c > src/vmlinux.h
echo "src/vmlinux.h 생성 완료."

echo "=== 4) 빌드 ==="
(cd src && make)

echo "=== 완료 ==="
echo "실행: sudo ./src/kshield_vpatch"
