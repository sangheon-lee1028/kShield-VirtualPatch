# eBPF 기반 AI 서빙 프레임워크 취약점 가상 패치(Virtual Patching) 프레임워크 kShield-VirtualPatch

**이상헌**
(소속 기관)
lsh66404865@gmail.com

> **작성 상태 안내**: 1~4장(서론, 관련 연구, 설계, 실험)이 VM 실측을 거쳐
> 완성되었고, 참고문헌은 웹 검색으로 실제 URL·발행일자를 확인하여 정리하였다.
> 이후 실험적으로 LSM 훅 기반 동기적 사전 차단 컴포넌트(3.5절)를 추가하였으며,
> 이는 코드 구현만 완료되었고 VM 실측은 아직 수행하지 않았다.

---

## 요약

AI 서빙 프레임워크(Ray, vLLM, Triton 등)에서 발견되는 원격 코드 실행(RCE) 취약점은 벤더의 패치 대응이 지연되거나, 조직 내부적으로 프레임워크 업그레이드가 늦어지는 경우가 많다. 대표적으로 Ray의 Jobs Submission API에 존재하는 인증 부재 취약점(CVE-2023-48022, "ShadowRay")은 벤더가 공식 패치를 제공하지 않은 채 오랜 기간 방치되었고, 실제로 수천 대의 클러스터가 침해되어 암호화폐 채굴 등에 악용되었다. 본 논문은 eBPF를 활용하여 애플리케이션 코드를 수정하거나 재배포하지 않고도, 이러한 취약점이 실제로 악용될 때 나타나는 비정상 행위를 커널 수준에서 탐지·차단하는 가상 패치(virtual patching) 메커니즘 kShield-VirtualPatch를 제안한다. 초기 설계(SHADOW_EXEC)는 `sched_process_exec` 트레이스포인트를 후킹하여, 감시 대상 AI 워커 프로세스의 계보(lineage)가 의심스러운 자식 프로세스(curl, wget 등)를 실행하는 순간을 탐지한다. 그러나 이 방식은 실행 파일 이름 블록리스트에 의존하므로, bash의 내장 TCP 리다이렉션 기능(`/dev/tcp/`)처럼 별도 바이너리를 실행하지 않는 우회에 취약함이 VM 실측으로 확인되었다. 이를 보완하기 위해 `tcp_v4_connect`/`tcp_v6_connect`를 직접 후킹하는 SHADOW_CONNECT를 추가하였다 — "어떤 바이너리를 실행했는가"가 아니라 "AI 워커 계보에서 신뢰되지 않은 목적지로 연결을 시도했는가"를 감시하므로, 바이너리 종류와 무관하게 포착한다. 이 방식은 파일 접근 반복 횟수에 의존하는 기존 빈도 기반 탐지와 달리, 정상적으로는 발생하지 않는 단일 이상 행위를 즉시 포착한다는 점에서 구조적 이점을 가진다.

mock Ray Jobs API 환경에서 python3→sh→curl로 이어지는 2단계 공격 체인은 curl 실행 시점에(SHADOW_EXEC), bash `/dev/tcp/` 기반 우회 시도는 연결 시도 시점에(SHADOW_CONNECT) 각각 즉시 SIGKILL로 차단되었으며, 두 경우 모두 정상 job(echo, python3 -c 등)은 오탐 없이 통과하였다. 10회 반복 성능 측정 결과 kShield-VirtualPatch 활성화로 인한 통계적으로 유의미한 처리량·지연시간 저하는 관측되지 않았다(처리량 p=0.7322, 지연시간 p=0.6956, Welch's t-test). 다만 SHADOW_EXEC/SHADOW_CONNECT는 모두 행위 발생 "이후" `bpf_send_signal`로 비동기 종료시키는 방식이라는 잔여 한계가 있어, 이를 해소하기 위해 `security_bprm_check_security`/`security_socket_connect` LSM 훅으로 시스템 콜 자체를 동기적으로 실패시키는 사전 차단 컴포넌트를 추가로 구현하였다(3.5절). 이 LSM 컴포넌트는 코드 작성만 완료되었으며 VM 실측은 아직 수행하지 않았다.

**핵심어:** eBPF, 가상 패치, virtual patching, AI 서빙 프레임워크 보안, Ray, ShadowRay, CVE-2023-48022

---

## 1. 서론

AI 서빙 프레임워크(Ray, vLLM, Triton Inference Server, MLflow 등)는 대규모 LLM 추론 파이프라인의 핵심 인프라로 자리잡았다. 그러나 이러한 프레임워크들은 빠른 기능 개발 속도에 비해 보안 검토가 상대적으로 미흡한 경우가 많으며, 실제로 원격 코드 실행급 심각한 취약점이 지속적으로 보고되고 있다.

가장 널리 알려진 사례는 Ray의 Jobs Submission API에 존재하는 CVE-2023-48022("ShadowRay")이다. Ray 대시보드의 기본 포트(8265)로 노출되는 이 API는 기본 설정에서 별도의 인증을 요구하지 않아, 네트워크로 접근 가능한 누구나 임의의 코드를 클러스터의 워커 프로세스 권한으로 실행시킬 수 있다. 보안 업체 Oligo Security의 조사에 따르면 [1], 이 취약점을 통해 실제로 수천 대의 Ray 클러스터가 침해되어 암호화폐 채굴, 역방향 셸 연결, 클러스터 내 크레덴셜 탈취 등에 악용된 사례가 확인되었다. 더 심각한 문제는 벤더(Anyscale)가 이를 "설계상 의도된 동작(Ray는 신뢰된 네트워크 내에서만 배포되어야 한다는 문서상의 전제)"이라는 입장을 오래 유지하며 즉각적인 공식 패치를 제공하지 않았다는 점이다 [2]. 이는 전통적인 "벤더 패치를 기다린다"는 대응 전략이 통하지 않는 상황을 만든다.

이러한 상황에서 방어자가 취할 수 있는 현실적인 선택지는 제한적이다. 프레임워크 자체를 수정하는 것은 벤더의 협조 없이는 어렵고, 프레임워크 업그레이드는 프로덕션 환경의 호환성 리스크 때문에 신중하게 이루어져야 한다. 웹 애플리케이션 보안 분야에서는 이런 상황에 대응하기 위해 WAF(Web Application Firewall) 수준에서 "가상 패치(virtual patching)"라는 개념이 오래전부터 활용되어 왔다 [7] — 취약점 자체를 고치지 못하는 동안, 그 취약점이 악용될 때 나타나는 특정 패턴만 탐지하여 임시로 차단하는 기법이다.

본 논문은 이 개념을 AI 서빙 프레임워크의 커널 수준으로 확장한다. eBPF를 이용하면 애플리케이션 코드를 한 줄도 수정하지 않고, 재시작도 없이, 실행 중인 프로세스에 탐지 로직을 "붙였다 뗄 수 있다." 이는 정식 패치가 배포되기 전까지의 공백을 메우는 임시 방어선이자, 정식 패치가 나온 뒤에는 훅을 제거하기만 하면 되는 저비용 대응 수단이 된다.

본 연구의 주요 기여는 다음과 같다.
- AI 서빙 프레임워크의 알려진 RCE 취약점(ShadowRay)을 대상으로 한 eBPF 기반 가상 패치 메커니즘 설계 및 구현
- 파일 접근 "빈도"가 아닌 "비정상 행위 발생 여부"를 탐지 기준으로 삼아, 단일 악용 시도로도 즉시 탐지 가능한 구조 제시
- 취약점 악용 재현(mock Ray Jobs API + exploit 스크립트)과 eBPF 방어 효과의 실증적 검증

---

## 2. 관련 연구

### 2.1 AI 서빙 프레임워크의 보안 취약점

Ray의 ShadowRay(CVE-2023-48022 [3][4]) 외에도, TorchServe, Triton Inference Server, MLflow 등 주요 AI 서빙 프레임워크에서 경로 탐색(path traversal), 역직렬화(deserialization) 기반 원격 코드 실행 등의 취약점이 다수 보고되었다. 이들 프레임워크는 공통적으로 (1) 빠른 기능 릴리스 주기로 인해 보안 검토가 상대적으로 후순위로 밀리고, (2) 조직 내부적으로 버전 업그레이드가 프로덕션 안정성 문제로 지연되는 경향을 보인다.

### 2.2 가상 패치(Virtual Patching)

가상 패치는 웹 애플리케이션 보안 분야에서 오래전부터 확립된 개념으로, ModSecurity, Cloudflare WAF, AWS WAF 등이 신규 CVE 발표 시 해당 취약점의 악용 패턴을 차단하는 임시 규칙을 신속히 배포하는 방식으로 널리 활용한다. 그러나 이러한 도구들은 대부분 HTTP 요청 계층에서 동작하며, 애플리케이션이 실제로 수행하는 시스템 수준 행위(프로세스 실행, 파일 접근 등)까지는 관측하지 못한다.

### 2.3 eBPF 기반 런타임 보안 및 가상 패치 메커니즘

Falco [5], Tetragon [6] 등 eBPF 기반 런타임 보안 도구는 커스텀 룰을 통해 특정 시스템 콜 패턴을 탐지·차단하는 기능을 이미 범용적으로 제공한다. 즉, "eBPF로 특정 행위 패턴을 감시해서 막는다"는 메커니즘 자체는 새로운 것이 아니다. 그러나 이들 도구의 기본 룰셋은 범용 워크로드를 대상으로 하며, AI 서빙 프레임워크에 특화된 취약점(예: ShadowRay의 구체적인 악용 시 발생하는 프로세스 트리 패턴)에 대한 룰은 아직 정립되어 있지 않다. 본 논문의 기여는 새로운 탐지 메커니즘의 발명이 아니라, 기존 eBPF 런타임 보안 기법을 AI 서빙 프레임워크라는 특정 도메인에 적용하고 실제 CVE로 그 효과를 검증하는 데 있다.

### 2.4 kShield(모델 파일 보안)와의 관계

본 연구는 저자의 선행 연구인 kShield(모델 파일 보안 프레임워크) [8]와 같은 eBPF kprobe/tracepoint 기반 아키텍처(커널 공간 BPF 프로그램 + perf buffer + 사용자 공간 데몬 + `bpf_send_signal`을 통한 즉시 프로세스 종료)를 공유한다. 다만 탐지 대상과 원리가 다르다. kShield는 보안 파일에 대한 접근 **빈도**(임계값 초과)를 탐지 기준으로 삼는 반면, 본 연구는 정상적으로는 절대 발생하지 않을 **단일 행위**(비정상 프로세스 실행)의 발생 여부를 탐지 기준으로 삼는다. 이는 공격자가 파일을 여러 번 나누어 여는 대신 한 번의 `open()`+`read()`로 데이터를 통째로 탈취하는 경우에도 탐지가 가능하다는 구조적 이점을 가진다.

---

## 3. 설계 및 구현

### 3.1 위협 모델

본 논문이 상정하는 위협 모델은 다음과 같다. 공격자는 AI 서빙 프레임워크의 관리 API(예: Ray Jobs Submission API, 기본 포트 8265)에 네트워크로 접근 가능하며, 해당 API에 인증 메커니즘이 부재하거나 미흡하게 설정된 취약점(CVE-2023-48022 [3][4])을 악용하여 임의의 코드를 원격에서 실행시킬 수 있다.

이 취약점은 벤더가 "의도된 설계"라는 입장을 고수하며 즉각적인 공식 패치를 제공하지 않거나 [2], 조직 내부적으로 프레임워크 업그레이드에 따른 프로덕션 호환성 리스크 때문에 패치 적용이 장기간 지연되는 상황을 전제로 한다. 실제로 Oligo Security의 조사에 따르면 [1] 수천 대의 Ray 클러스터가 이 취약점을 통해 실제로 침해되어 암호화폐 채굴, 역방향 셸 연결, 클러스터 내 자격 증명 탈취 등에 악용된 사례가 확인되었다.

공격자의 궁극적 목표는 원격 코드 실행을 통해 정상적인 AI 워커 프로세스의 권한으로 비정상적인 하위 프로세스를 실행하거나(예: `/bin/sh`, `curl`), 공격자가 제어하는 외부 서버로 아웃바운드 연결을 수립하여 2차 피해(암호화폐 채굴, 데이터 유출, 크레덴셜 탈취)를 유발하는 것이다.

단, 본 논문은 ShadowRay 취약점의 원격 코드 실행 이후 악성 행위 탐지에 집중하며, 취약점 자체의 존재 여부 진단이나 초기 침투 벡터 차단은 다루지 않는다. 또한 프레임워크 소스 코드 자체를 사전에 변조하거나 커널 루트킷을 삽입하는 공격, 그리고 ShadowRay 외 다른 CVE에 대한 일반화된 방어는 본 논문의 범위 밖으로 한다.

### 3.2 시스템 아키텍처

kShield-VirtualPatch는 저자의 선행 연구 kShield [8]와 동일한 아키텍처 패턴(커널 공간 BPF 프로그램 + perf buffer + 사용자 공간 로거)을 따른다.

```
┌─────────────────────────────────────────────┐
│              사용자 공간                      │
│  ┌──────────────┐  perf buffer  ┌──────────┐ │
│  │ kshield_vpatch│◄──────────────│  이벤트  │ │
│  │  로거/데몬     │               │  핸들러  │ │
│  └──────────────┘               └──────────┘ │
├─────────────────────────────────────────────┤
│              커널 공간                        │
│  ┌─────────────────────────────────────────┐│
│  │  tp/sched/sched_process_fork            ││
│  │   → ai_worker_lineage 맵에 계보 등록    ││
│  │  tp/sched/sched_process_exit            ││
│  │   → 계보 맵에서 종료 프로세스 제거      ││
│  ├─────────────────────────────────────────┤│
│  │  tp/sched/sched_process_exec  (SHADOW_EXEC)││
│  │  ┌─────────────────────────────────┐   ││
│  │  │ 계보(lineage)에 속하고,           │   ││
│  │  │ 실행 파일이 suspicious_bins[]에    │   ││
│  │  │ 있으면 → SIGKILL 즉시 전송        │   ││
│  │  └─────────────────────────────────┘   ││
│  ├─────────────────────────────────────────┤│
│  │  kprobe/tcp_v4_connect,v6_connect (SHADOW_CONNECT)││
│  │  ┌─────────────────────────────────┐   ││
│  │  │ 계보(lineage)에 속하고,           │   ││
│  │  │ 목적지가 loopback/trusted_dst_ipv4[]│  ││
│  │  │ 밖이면 → SIGKILL 즉시 전송        │   ││
│  │  └─────────────────────────────────┘   ││
│  └─────────────────────────────────────────┘│
└─────────────────────────────────────────────┘
```

이 다이어그램은 어디서나(추가 커널 설정 없이) attach 가능한 기본 방어선(kprobe/tracepoint + 비동기 SIGKILL)만을 나타낸다. 3.5절에서 별도로 다루는 실험적 LSM 컴포넌트(`kshield_vpatch_lsm`)는 동일한 판정 로직을 `security_bprm_check_security`/`security_socket_connect` 훅에서 동기적으로 수행하는 독립된 BPF 오브젝트이며, 위 다이어그램에는 포함되지 않는다.

### 3.3 핵심 탐지 메커니즘 (SHADOW_EXEC, SHADOW_CONNECT)

초기 설계(v1)는 `sched_process_exec` 트레이스포인트에서 새로 실행된 프로세스의 **직속 부모**만 확인하여, 부모 comm이 `watched_parents[]`(감시 대상 AI 워커 프로세스 목록, 예: `raylet`)와 일치하고 실행 파일이 `suspicious_bins[]`와 일치하면 즉시 SIGKILL을 전송하는 방식이었다.

그러나 VM 실측 과정에서 두 가지 문제가 발견되었다.

1. **정상 job도 오탐**: mock Ray Jobs API는 정상/악성 job을 구분하지 않고 항상 `/bin/sh -c <entrypoint>` 형태로 실행한다. 이는 실제 Ray의 job 실행 방식과도 동일하다. 따라서 `suspicious_bins[]`에 `/bin/sh`가 포함되어 있으면 정상 job(`echo`, `python3 -c ...`)조차 실행 즉시 차단되는 문제가 실측으로 확인되었다.
2. **다단계 실행 체인 탐지 실패**: 실제 공격은 `python3(워커) → sh → curl`처럼 최소 2단계를 거친다. curl의 직속 부모는 `sh`이지 워커 프로세스가 아니므로, "직속 부모만 확인"하는 v1 로직으로는 curl 실행을 탐지할 수 없었다.

이를 해결하기 위해 v2는 `sched_process_fork` 트레이스포인트를 추가로 후킹하여 **AI 워커의 자손 프로세스 계보(lineage)**를 BPF 해시맵(`ai_worker_lineage`, pid → flag)으로 추적한다. 프로세스가 fork될 때, 부모가 이미 계보에 속하거나 `watched_parents[]`와 일치하면 자식도 계보에 편입시킨다. 이렇게 하면 몇 단계를 거치든 계보 추적이 끊기지 않는다. 아울러 `/bin/sh`, `/bin/bash`는 정상 job 실행에도 쓰이는 경로이므로 `suspicious_bins[]`에서 제외하고, `curl`, `wget`, `nc` 등 실제 페이로드 다운로드·외부 연결에 쓰이는 바이너리만 남겼다.

최종 탐지 로직(`src/kshield_vpatch.bpf.c` 참조)은 다음과 같다.

1. `sched_process_fork` 시 부모가 계보에 속하거나 `watched_parents[]`와 일치하면 자식 PID를 계보에 등록
2. `sched_process_exec` 시 현재 프로세스가 계보에 속하는지(또는 직속 부모가 `watched_parents[]`와 일치하는지) 확인
3. 계보에 속하는 경우, 실행된 바이너리가 `suspicious_bins[]`(`/usr/bin/curl`, `/usr/bin/wget`, `/bin/nc`, `/usr/bin/nc`, `/usr/bin/ncat`)와 일치하는지 확인
4. 일치하면 이벤트를 perf buffer로 제출하고 `bpf_send_signal(SIGKILL)` 호출

이 메커니즘은 kShield의 EVIL_OPEN(반복 횟수 기반)과 근본적으로 다른 원리로 동작한다. AI 워커 계보에서 curl/wget 등이 실행되는 행위는 정상 운영 중에는 **단 한 번도 발생해서는 안 되는** 행위이므로, 반복 횟수와 무관하게 첫 발생 시점에 즉시 탐지·차단할 수 있다.

`watched_parents[]`와 `suspicious_bins[]`는 BPF rodata 섹션에 컴파일 타임에 삽입되며, 이는 kShield [8]와 동일하게 대상 경로 변경 시 재컴파일이 필요하다는 한계를 가진다(향후 연구 참고). 전체 구현 코드는 공개 저장소 [9]에서 확인할 수 있다.

**v3 재설계: SHADOW_CONNECT — 실행 파일 블록리스트의 근본적 우회 문제 해결**

v2의 SHADOW_EXEC는 `suspicious_bins[]`라는 실행 파일 이름 블록리스트에 의존하는데, 이는 다음과 같이 쉽게 우회 가능하다는 한계가 있었다.

1. **bash 내장 기능 우회**: `bash -c 'exec 3<>/dev/tcp/host/port; ...'` 같은 방식은 bash 자체의 내장 TCP 리다이렉션 기능을 사용하므로, curl/nc 같은 별도 바이너리를 `exec()`하지 않는다. `suspicious_bins[]`에 없는 방식이라 v2로는 탐지 불가능했다.
2. **watched_parents의 python3가 suspicious_bins에는 없음**: python3는 감시 대상 부모 목록에는 있지만, python3 자신이 소켓 API로 직접 통신하면 실행 파일 이름 기반 검사를 통과한다.
3. **별도 프로세스 실행 없이 직접 통신**: 공격자가 원래 프로세스 안에서 소켓만 열면, 애초에 감시할 `exec()` 이벤트 자체가 없다.

이 세 우회의 공통점은 결국 커널의 `tcp_v4_connect`/`tcp_v6_connect`를 거쳐 아웃바운드 TCP 연결을 시도한다는 점이다. v3는 이 지점을 직접 후킹하여, "어떤 바이너리를 실행했는가"가 아니라 **"AI 워커 계보에서 신뢰되지 않은 목적지로 연결을 시도했는가"** 를 감시한다. AI 워커 계보에 속한 프로세스가 loopback(127.0.0.0/8) 또는 `trusted_dst_ipv4[]`(운영자가 사전에 신뢰 목적지로 등록한 IP 목록)에 없는 주소로 연결을 시도하면, 바이너리 종류와 무관하게 즉시 SIGKILL을 전송한다. 기존 SHADOW_EXEC은 그대로 유지하여 두 계층이 함께 방어한다(defense-in-depth) — 알려진 바이너리는 실행 시점에 더 일찍 잡고, 그 외 모든 경로는 연결 시도 시점에 잡는다.

아울러 v2에는 프로세스 종료 시 `ai_worker_lineage` 맵을 정리하는 로직이 없어, PID가 재사용될 경우 무관한 새 프로세스가 죽은 프로세스의 계보 정보를 잘못 물려받을 수 있는 버그가 있었다. v3는 `sched_process_exit` 훅으로 프로세스 종료 시 계보 정보를 제거하여 이를 해결하였다.

**v3의 한계**: SHADOW_CONNECT도 완전한 차단은 아니다. (1) 이미 열려 있는 정상 연결에 얹혀 데이터를 빼가는 경우, (2) 허용된 포트/프로토콜(예: DNS) 위로 데이터를 숨기는 터널링, (3) 네트워크가 아예 필요 없는 로컬 전용 공격은 이 메커니즘으로 포착되지 않는다. 또한 `bpf_send_signal`은 비동기적이므로 `connect()` 진입 시점에 신호를 보내도 완전한 사전 차단을 수학적으로 보장하지는 않는다 — 이 한계를 해소하기 위해 `security_socket_connect`/`security_bprm_check_security` LSM 훅 기반의 동기적 사전 차단을 별도 컴포넌트로 구현하였다(3.5절). 다만 `CONFIG_BPF_LSM` 및 활성 LSM 스택에 "bpf" 포함이 필요해 배포 환경 의존성이 있으므로, 본 절의 SHADOW_EXEC/SHADOW_CONNECT는 그러한 의존성 없이 어디서나 동작하는 기본 방어선으로 계속 유지한다.

### 3.5 (실험적) LSM 훅 기반 동기적 사전 차단

SHADOW_EXEC/SHADOW_CONNECT는 모두 "행위가 발생한 뒤 `bpf_send_signal(9)`로 프로세스를 죽이는" 방식이다. `bpf_send_signal`은 비동기 전달이므로, 신호가 실제로 전달되기 전에 `connect()`가 이미 진행되었거나 `execve()`가 이미 완료되었을 여지를 이론적으로 완전히 배제하지 못한다. 이를 근본적으로 해소하려면 시스템 콜의 반환값 자체를 커널이 원래 진행을 이어가기 전에 대체해야 한다.

`BPF_PROG_TYPE_LSM` 프로그램은 커널의 LSM 훅 지점(`security_bprm_check_security`, `security_socket_connect` 등)에 fmod_ret 트램폴린 방식으로 부착되어, 원래 함수가 반환하기 전에 그 반환값 자체를 대체할 수 있다. 이를 이용해 별도 컴포넌트(`src/kshield_vpatch_lsm.bpf.c`, `src/kshield_vpatch_lsm.c`)를 구현하였다.

- `security_bprm_check_security` 훅에서 AI 워커 계보가 `suspicious_bins[]`를 실행하려 하면 `-EPERM`을 반환하여 `execve()` 자체를 실패시킨다 — 의심 바이너리는 단 한 명령어도 실행되지 않는다.
- `security_socket_connect` 훅에서 AI 워커 계보가 신뢰되지 않은 목적지로 `connect()`를 시도하면 `-EPERM`을 반환하여 연결 자체를 실패시킨다 — 3-way handshake조차 시작되지 않는다.

두 훅 모두 커널 호출 경로상 SHADOW_EXEC/SHADOW_CONNECT가 관측하는 지점(`sched_process_exec` tracepoint, `tcp_v4_connect`/`tcp_v6_connect`)보다 앞서 실행되므로, 이 LSM 컴포넌트가 성공적으로 attach된 환경에서는 대부분의 시도가 SHADOW_EXEC/SHADOW_CONNECT까지 도달하기 전에 이미 차단된다. 두 컴포넌트를 동시에 로드해도 서로 간섭하지 않으며, LSM attach가 불가능한 환경(아래 참고)에서는 SHADOW_EXEC/SHADOW_CONNECT가 계속 방어선 역할을 한다.

`BPF_PROG_TYPE_LSM`은 `CONFIG_BPF_LSM=y` 커널과, 활성 LSM 목록(`/sys/kernel/security/lsm`)에 `"bpf"` 포함을 요구한다. 이는 배포판·배포 설정에 따라 기본값이 다르며, 포함되어 있지 않다면 부팅 파라미터에 `lsm=...,bpf`를 추가하고 재부팅해야 한다 — 이는 보안 설정 변경이므로 운영자가 직접 판단·수행해야 할 사항이다. 이 요구사항이 SHADOW_EXEC/SHADOW_CONNECT(3.3절)에는 없다는 점이, 본 논문이 두 계층을 모두 유지하는 이유다.

> **검증 상태**: 이 컴포넌트는 코드 작성만 완료되었으며, 4장의 실험 결과에는 포함되어 있지 않다. VM에서의 빌드·attach 성공 여부, 실제 `execve()`/`connect()` 사전 차단 동작, SIGKILL 방식(3.3절) 대비 오탐·성능 특성 비교는 아직 실측하지 못하였다(5장 향후 연구 참고).

### 3.4 공격 재현 환경

실제 Ray 클러스터를 설치하지 않고도 ShadowRay의 핵심 취약점(인증 없는 원격 코드 실행)을 재현하기 위해 목업 Jobs API 서버(`attack/mock_ray_server.py`)를 구현하였다. 이 서버는 `/api/jobs/` 엔드포인트로 제출된 `entrypoint` 명령어를 인증 검사 없이 그대로 서브프로세스로 실행하여, 실제 Ray Jobs API의 핵심 취약 동작을 그대로 재현한다. `attack/exploit_shadowray.py`는 이 엔드포인트에 악성 명령어를 제출하는 공격 스크립트다.

---

## 4. 실험

### 4.1 실험 환경

| 항목 | 사양 |
|------|------|
| OS | Ubuntu 22.04 LTS |
| 커널 | Linux 6.8.0-138-generic |
| eBPF 프레임워크 | libbpf + libbpf-bootstrap |
| Mock Ray Jobs API | Python 3 `http.server` 기반 |
| 벤치마크 도구 | 자체 제작 Python 스크립트(`benchmark_vpatch.py`), 요청 500회/런 |

### 4.2 실험 설계

**공격 탐지 실험:**
1. kShield-VirtualPatch 비활성 상태에서 `exploit_shadowray.py`로 악성 entrypoint(`curl ... | sh`) 제출 → mock 서버가 이를 실행하는지 확인 (기준선)
2. kShield-VirtualPatch 활성 상태에서 동일 공격 재현 → SIGKILL 발동까지의 시간, 로그 출력 확인
3. 오탐(false positive) 측정: mock 서버가 정상적인 job(예: 단순 Python 스크립트 실행)을 처리하는 동안 kShield-VirtualPatch가 오작동하지 않는지 확인

**성능 오버헤드 실험 (kShield 선행 연구와 동일한 방법론 적용 예정):**
- kShield-VirtualPatch 비활성/활성 상태에서 mock 서버의 정상 job 처리 처리량·지연시간을 N회 반복 측정
- Welch's t-test로 통계적 유의성 검증

### 4.3 공격 탐지 결과

| 구분 | kShield-VirtualPatch 비활성 | kShield-VirtualPatch 활성 |
|------|---------------------------|---------------------------|
| 악성 entrypoint(`curl \| sh`) 실행 여부 | 실행됨 (mock 서버가 인증 없이 그대로 실행하므로 차단 수단 없음) | **curl exec 시점에 즉시 SIGKILL로 차단** |
| 다단계 체인(python3→sh→curl) 탐지 | 해당 없음 | 탐지됨 — curl의 직속 부모는 sh이지만, fork 기반 계보 추적으로 정확히 포착 |
| 정상 job(`echo`, `python3 -c ...`) 처리 | 정상 처리 | **오탐 없이 정상 처리** (SHADOW_EXEC 미발생) |

실제 kShield-VirtualPatch 로그:
```
[00:03:55] SHADOW_EXEC 탐지! parent=sh(pid=55945) -> child=curl(pid=55946) exec=/usr/bin/curl => SIGKILL 전송
```

trace 버퍼 분석 결과, 실행 체인은 다음과 같이 진행되었다: `python3(워커) → fork → sh` (계보 편입) → `sh` exec (감시 대상이지만 `suspicious_bins[]`에 없어 통과) → `sh → fork → curl` (계보 편입, 2단계 추적 성공) → `curl` exec (계보 소속 + `suspicious_bins[]` 일치 → SIGKILL). 파이프의 두 번째 `sh`(`curl ... | sh`)도 동일하게 계보에 편입되었으나 `suspicious_bins[]`에 없어 오탐 없이 통과하였다.

**SHADOW_CONNECT(v3) 우회 시나리오 재현 결과**: SHADOW_EXEC(v2)이 실행 파일 이름 블록리스트에 의존한다는 한계를 검증하기 위해, `suspicious_bins[]`에 없는 방식으로 공격을 재현하였다. bash의 내장 TCP 리다이렉션 기능(`bash -c 'exec 3<>/dev/tcp/1.1.1.1/80; echo leaked >&3'`)은 curl/nc 같은 별도 바이너리를 실행하지 않으므로 SHADOW_EXEC로는 탐지되지 않는다. SHADOW_CONNECT는 이 시도를 `tcp_v4_connect` 진입 시점에 정확히 포착하였다.

```
[13:36:02] SHADOW_CONNECT 탐지! parent=sh -> proc=bash(pid=118590) dst=1.1.1.1:80 => SIGKILL 전송
```

동일 조건에서 정상 job(`echo benign-job`)은 SHADOW_EXEC·SHADOW_CONNECT 어느 쪽도 발생시키지 않고 정상 처리되어, 새 탐지 계층 추가가 기존 정상 경로에 오탐을 유발하지 않음을 확인하였다. 개발 과정에서 `parent_comm` 필드가 로그에 빈 값으로 찍히는 버그(공통 헬퍼 함수에 배열 대신 포인터를 넘겨 `BPF_CORE_READ_STR_INTO`의 목적지 크기 추론이 1바이트로 축소된 문제)를 실측으로 발견하여 수정하였다.

**한계**: 위 결과들은 단일 실행 기반 정성적 확인이며, 반복 실행에 따른 탐지율 통계(예: N회 중 탐지 성공 횟수)는 측정하지 않았다. 또한 SIGKILL까지의 정밀 지연시간(마이크로초 단위)은 별도 계측(`bpf_ktime_get_ns()` 기반 타임스탬프)이 필요하며 본 실험에서는 초 단위 로그로만 확인하였다. SHADOW_CONNECT의 나머지 한계(기존 연결 재사용, 허용 포트 위 터널링, 네트워크 불필요 공격)는 3.3절에 기술하였다.

### 4.4 성능 오버헤드 결과

kShield-VirtualPatch 비활성(`vpatch_off`)/활성(`vpatch_on`) 상태에서 mock 서버에 정상 job을 500회/런 × 10회 반복 제출하여 처리량·지연시간을 측정하였다.

**[표 4] 비교군별 성능 측정 결과 (N=10, 평균±표준편차)**

| 구분 | 처리량 (req/s) | 지연시간 (ms) |
|------|--------------|-------------|
| vpatch_off (비활성) | 586.89 ± 9.04 | 1.638 ± 0.025 |
| vpatch_on (활성) | 585.17 ± 12.74 | 1.644 ± 0.037 |

**[표 5] Welch's t-test 결과**

| 지표 | t-통계 | p-값 | 유의성 |
|------|--------|------|--------|
| 처리량 | +0.348 | 0.7322 | ns |
| 지연시간 | -0.399 | 0.6956 | ns |

*기준: ns = 유의하지 않음 (p≥0.05)*

kShield-VirtualPatch 활성화로 인한 처리량·지연시간 변화는 Welch's t-test 결과 통계적으로 유의미하지 않았다(처리량 p=0.7322, 지연시간 p=0.6956). 단, p>0.05는 "차이가 없음"을 증명하는 것이 아니라 "차이를 기각하지 못한 것"임을 유의해야 한다. 완전한 동등성 주장을 위해서는 TOST(Two One-Sided Tests) 기반 동등성 검정과 더 큰 표본(N≥30)이 필요하며, 이는 향후 연구 과제로 남긴다. 그럼에도 현재 N=10 조건에서 fork/exec 트레이스포인트 후킹과 BPF 해시맵 조회(계보 추적)로 인한 유의미한 오버헤드가 관측되지 않았다는 점은, kShield-VirtualPatch가 실 운용 환경에 부담 없이 적용 가능함을 보여주는 실용적 근거가 된다.

**한계**: 위 성능 측정은 SHADOW_EXEC(v2)만 적용된 상태에서 수행되었다. SHADOW_CONNECT(v3)가 추가한 `tcp_v4_connect`/`tcp_v6_connect` 커널 함수 후킹은 시스템 전역의 모든 아웃바운드 TCP 연결 시도마다 실행되므로(AI 워커 계보 여부 판별을 위한 map 조회가 매 연결마다 발생), 네트워크 연결이 빈번한 워크로드에서는 SHADOW_EXEC 단독과 다른 오버헤드 특성을 보일 수 있다. SHADOW_CONNECT를 포함한 재측정은 아직 수행하지 않았으며 향후 연구 과제로 남긴다.

---

## 5. 결론 및 향후 연구

본 논문은 AI 서빙 프레임워크의 알려진 RCE 취약점(ShadowRay)에 대해, 코드 수정이나 재배포 없이 eBPF로 가상 패치를 적용하는 방법을 제시하였다. SHADOW_EXEC과 SHADOW_CONNECT 두 계층은 반복 횟수가 아닌 단일 이상 행위 발생을 기준으로 하므로, 기존 kShield [8]의 빈도 기반 탐지가 가진 구조적 한계(공격자가 한 번의 접근으로 데이터를 탈취하는 경우 탐지 불가)를 보완한다.

VM 실측 결과, python3(워커)→sh→curl로 이어지는 2단계 공격 체인은 curl 실행 시점에(SHADOW_EXEC), bash `/dev/tcp/` 내장 기능을 이용한 우회 시도는 연결 시도 시점에(SHADOW_CONNECT) 각각 정확히 차단하였으며, 두 경우 모두 정상 job은 오탐 없이 통과함을 확인하였다. 10회 반복 성능 측정(SHADOW_EXEC 단독 기준) 결과 kShield-VirtualPatch 활성화로 인한 통계적으로 유의미한 처리량·지연시간 저하는 관측되지 않았다(처리량 p=0.7322, 지연시간 p=0.6956, Welch's t-test).

개발 과정에서 두 차례의 설계 반복이 있었다. 첫째, "직속 부모만 확인"하는 초기 설계(v1)가 다단계 공격 체인을 놓치고 정상 job도 오탐하는 문제를 실측으로 발견하여 프로세스 계보(lineage) 추적 방식(v2)으로 재설계하였다. 둘째, v2의 실행 파일 이름 블록리스트(`suspicious_bins[]`)가 bash 내장 기능 같은 우회에 취약함을 확인하여, 연결 시도 자체를 감시하는 SHADOW_CONNECT(v3)를 추가하였다. 이 경험은 행위 기반 탐지 메커니즘을 설계할 때 (1) 실행 체인의 깊이, (2) 감시 신호가 "특정 도구의 사용"이 아니라 "행위의 본질적 불변량"에 기반해야 함을 반드시 고려해야 함을 보여준다. 다만 SHADOW_CONNECT조차도 완전한 차단은 아니며, 이미 열려 있는 연결의 재사용, 허용된 프로토콜 위의 터널링, 네트워크가 불필요한 로컬 전용 공격에는 대응하지 못한다 — 이는 특정 구현의 결함이라기보다 행위 기반 탐지 일반의 본질적 한계에 가깝다.

향후 연구 과제는 다음과 같다.
- **다른 CVE로의 일반화**: 현재는 ShadowRay 한 사례에 특화되어 있다. Triton, TorchServe, MLflow 등 다른 프레임워크의 알려진 CVE에 대해서도 유사한 방식의 룰을 구축하고 공통 프레임워크로 일반화할 필요가 있다.
- **런타임 룰 설정 지원**: `watched_parents[]`, `suspicious_bins[]`, `trusted_dst_ipv4[]`가 컴파일 타임에 고정되어 있어, 새로운 CVE 대응이나 신뢰 목적지 추가 시마다 재컴파일이 필요하다. BPF map 기반 런타임 룰 갱신 메커니즘 도입이 필요하다.
- **LSM 기반 사전 차단의 VM 실측 검증**: `security_bprm_check_security`/`security_socket_connect` LSM 훅을 이용한 동기적 사전 차단을 별도 컴포넌트(`kshield_vpatch_lsm.*`, 3.5절)로 구현하였으나, 아직 VM에서 빌드·attach·기능 검증을 거치지 않았다. `CONFIG_BPF_LSM` 및 `lsm=...,bpf` 부팅 설정 여부에 따른 attach 성공률, 실제 사전 차단 동작 여부, SIGKILL 방식(3.3절) 대비 오탐·성능 특성 비교가 필요하다.
- **SHADOW_CONNECT의 성능 오버헤드 정량화**: 현재 성능 측정은 SHADOW_EXEC 단독 기준이다. 시스템 전역 아웃바운드 연결마다 실행되는 SHADOW_CONNECT의 오버헤드를 네트워크 집약적 워크로드에서 별도로 측정해야 한다.
- **IPv6 신뢰 목적지 목록 지원**: 현재 IPv6는 loopback(`::1`) 외 모든 목적지를 의심으로 간주하며, IPv4의 `trusted_dst_ipv4[]`에 대응하는 신뢰 목록이 없다.
- **DNS 터널링 등 잔여 우회 대응**: 허용된 프로토콜(DNS 등) 위로 데이터를 은닉하는 터널링, 기존 정상 연결에 얹혀가는 방식 등 SHADOW_CONNECT로도 막지 못하는 우회에 대한 추가 탐지 계층 연구가 필요하다.
- **실제 Ray 클러스터 환경 검증**: 현재는 mock 서버 기반 재현이며, 실제 Ray 설치 환경에서의 검증이 필요하다.
- **오탐 시나리오 확장 검증**: 본 실험은 `echo`, `python3 -c` 등 단순 job으로만 오탐 여부를 확인하였다. AI 워커가 정상적으로 서브프로세스를 실행하거나 외부와 통신하는 더 복잡한 합법적 워크로드(예: 데이터 전처리 파이프라인, 정상적인 API 호출)와의 충돌 가능성을 다양한 시나리오에서 검증해야 한다.
- **탐지 반복성 및 정밀 지연시간 측정**: 공격 탐지는 단일 실행 기반 정성적 확인에 그쳤다. N회 반복 탐지율과 `bpf_ktime_get_ns()` 기반 정밀 SIGKILL 지연시간 측정이 필요하다.
- **동등성 검정(TOST) 수행**: 성능 무영향을 통계적으로 엄밀히 증명하기 위해 TOST 기반 동등성 검정과 표본 크기 확대(N≥30)가 필요하다.
- **Falco/Tetragon과의 정량적 비교**: 기존 범용 런타임 보안 도구 [5][6]에 동일한 룰을 이식했을 때와의 성능·정확도 비교가 필요하다.

---

## 참고문헌

[1] Oligo Security, "ShadowRay: First Known Attack Campaign Targeting AI Workloads Exploited In The Wild," Mar. 2024. [Online]. Available: https://www.oligo.security/blog/shadowray-attack-ai-workloads-actively-exploited-in-the-wild
[2] Anyscale, "Update on Ray CVEs CVE-2023-6019, CVE-2023-6020, CVE-2023-6021, CVE-2023-48022, CVE-2023-48023," Anyscale Blog, 2024. [Online]. Available: https://www.anyscale.com/blog/update-on-ray-cves-cve-2023-6019-cve-2023-6020-cve-2023-6021-cve-2023-48022-cve-2023-48023
[3] MITRE/NVD, "CVE-2023-48022," National Vulnerability Database, 2023. [Online]. Available: https://nvd.nist.gov/vuln/detail/CVE-2023-48022
[4] GitHub Advisory Database, "Ray has arbitrary code execution via jobs submission API (GHSA-6wgj-66m2-xxp2)," 2023. [Online]. Available: https://github.com/advisories/GHSA-6wgj-66m2-xxp2
[5] Falco, "Container Runtime Security," The Falco Authors, CNCF, 2024. [Online]. Available: https://falco.org
[6] Isovalent, "Tetragon: eBPF-based Security Observability and Runtime Enforcement," GitHub, 2023. [Online]. Available: https://github.com/cilium/tetragon
[7] OWASP Foundation, "Virtual Patching Best Practices," 2024. [Online]. Available: https://owasp.org/www-community/Virtual_Patching_Best_Practices
[8] 이상헌, "kShield: eBPF 기반 AI 모델 보안 프레임워크 구현 코드," GitHub, 2026. [Online]. Available: https://github.com/sangheon-lee1028/Ai-ebpf
[9] 이상헌, "kShield-VirtualPatch: eBPF 기반 AI 서빙 프레임워크 취약점 가상 패치 구현 코드," GitHub, 2026. [Online]. Available: https://github.com/sangheon-lee1028/kShield-VirtualPatch
