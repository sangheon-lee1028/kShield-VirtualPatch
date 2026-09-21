# Falco / Tetragon 비교 실험

kShield-VirtualPatch와 같은 판정(AI 워커 계보의 신뢰되지 않은 connect / nc 실행)을 Falco 룰과
Tetragon 정책으로 옮겨, 같은 VM·같은 워크로드에서 성능과 탐지·차단을 비교한다. 논문 2.3절의
"정량 비교를 수행하지 못했다"를 실측으로 대체하는 것이 목적이다.

## 구성

| 파일 | 역할 |
|---|---|
| `falco_vpatch_rules.yaml` | SHADOW_CONNECT/SHADOW_EXEC 동등 Falco 룰 (탐지 전용) |
| `tetragon_vpatch_policy.yaml` | SHADOW_CONNECT 동등 Tetragon 정책 (Sigkill) |
| `run_comparison.py` | `check` / `detect` / `perf` 실행기 |
| `compare_stats.py` | Welch t-test, Bonferroni, 평균 차이 95% CI, TOST 동등성 검정 |

## 준비 (VM)

1. **Falco 0.42 이상**(modern eBPF, 커널 5.8+/BTF 필요). 공식 apt 저장소 기준
   (https://falco.org/docs/setup/packages/):
   ```bash
   curl -fsSL https://falco.org/repo/falcosecurity-packages.asc | \
     sudo gpg --dearmor -o /usr/share/keyrings/falco-archive-keyring.gpg
   echo "deb [signed-by=/usr/share/keyrings/falco-archive-keyring.gpg] https://download.falco.org/packages/deb stable main" | \
     sudo tee /etc/apt/sources.list.d/falcosecurity.list
   sudo apt-get update -y
   sudo env FALCO_FRONTEND=noninteractive FALCO_DRIVER_CHOICE=modern_ebpf apt-get install -y falco
   ```
2. **Tetragon standalone**(릴리스 tarball, systemd 서비스 `tetragon`).
   최신 버전은 https://github.com/cilium/tetragon/releases 에서 확인한다
   (https://tetragon.io/docs/installation/package/):
   ```bash
   TETRA_VER=v1.7.0   # 릴리스 페이지의 최신 태그로 바꾼다
   curl -LO https://github.com/cilium/tetragon/releases/download/${TETRA_VER}/tetragon-${TETRA_VER}-amd64.tar.gz
   tar -xvf tetragon-${TETRA_VER}-amd64.tar.gz
   cd tetragon-${TETRA_VER}-amd64 && sudo ./install.sh && cd ..
   ```
   tarball 설치본의 gRPC 주소는 unix 소켓(`unix:///var/run/tetragon/tetragon.sock`)이며,
   실행기의 `--tetra-extra` 기본값이 이미 이 주소다.
3. 설치 직후 자동 기동된 서비스는 멈춘다(베이스라인 오염 방지).
   ```bash
   sudo systemctl stop tetragon
   sudo systemctl stop falco-modern-bpf falco-kmod falcoctl-artifact-follow 2>/dev/null
   sudo systemctl disable falco-modern-bpf falco-kmod falcoctl-artifact-follow 2>/dev/null
   ```
4. `python3`의 실제 경로가 `tetragon_vpatch_policy.yaml`의 `matchBinaries.values`에 있는지 확인한다.
   ```bash
   which python3; readlink -f "$(which python3)"
   ```
5. 버전(`falco --version`, `tetra version`)은 메타데이터 JSON에 자동 기록된다. 논문에 명시한다.

## 실행 순서

```bash
sudo python3 attack/compare/run_comparison.py check
```
```bash
sudo python3 attack/compare/run_comparison.py detect
```
```bash
sudo python3 attack/compare/run_comparison.py perf
```

tetra의 gRPC 주소 기본값은 tarball 설치본의 unix 소켓이다. 다른 방식으로 설치했다면
`--tetra-extra`(서브커맨드 앞)로 바꾼다.
```bash
python3 attack/compare/compare_stats.py attack/results/cmp_raw_<타임스탬프>.csv
```

`check`가 실패하면 메시지대로 고친 뒤 다시 실행한다. Tetragon 정책이 로드되지 않으면
`tetra tracingpolicy add attack/compare/tetragon_vpatch_policy.yaml`의 오류 메시지를 보고
필드명을 버전에 맞게 고친다.

## 측정 설계

- **같은 세션 ABBA 교차**: 그룹 순서를 라운드마다 뒤집는다(기본 2라운드 x 5회 = 10회).
  시간에 따른 드리프트(지난번 "세션 의존성" 한계)를 상쇄한다.
- **도구를 먼저 띄운 뒤 mock 서버 기동**: 모든 도구가 자기 방식으로 계보를 처음부터 관찰한다.
- **워크로드 2종**: 일반 job, fork 집약적 job(지난 실험에서 오버헤드가 처음 관측된 조건).
- **측정값**: 처리량, 평균/p99 지연, 도구 에이전트의 CPU 시간·RSS.

## 결과 해석 원칙

- **결과를 정해 놓고 설계하지 않는다.** 차이가 없을 수도, 있을 수도 있다. 나온 대로 보고한다.
- "큰 차이 없음"을 주장하려면 **동등성 마진을 데이터를 보기 전에 고정**하고(기본 ±2%) TOST로
  입증한다. `compare_stats.py`의 판정이 "판정 불가"이면 "차이가 관측되지 않았다"까지만 쓸 수 있다.
- **Falco는 탐지만 한다.** 오버헤드·탐지 여부만 비교하고, 차단 비교는 Tetragon과 한다.
- Falco는 이벤트를 사용자 공간에서 필터링하고 Tetragon·kShield는 커널 안에서 판정한다. 기능 범위도
  다르므로 "더 빠르다"가 아니라 **범용성의 비용 대 특화의 이점**으로 서술한다.
- `tool_cpu_s`는 사용자 공간 에이전트 비용이다. BPF 프로그램 실행 시간은 트리거한 프로세스에
  계상되어 처리량·지연에 이미 포함된다.
- `falco_default` 그룹(`--groups off,kshield,falco,falco_default,tetragon`)은 Falco 기본 룰셋을
  그대로 켠 참고용이다. 일반적 배포 상태의 비용을 보여 준다.

## 범위와 한계 (논문에 함께 적을 것)

- 감시 루트는 python3(기존 kShield 실험과 동일). IPv4 한정, 벤치마크는 127.0.0.1로 접속한다.
- Tetragon 정책에는 exec 계층(nc 즉시 차단)이 없다. nc도 connect에서 차단된다.
- kShield의 런타임 신뢰 IP/예외/syslog 같은 운영 기능은 이 실험이 비교하지 않는다(정성 비교 대상).
- 탐지 실험의 `killed`는 SIGKILL(rc=137) 여부이며, 비동기 SIGKILL이므로 데이터가 한 바이트도 안
  나갔다는 뜻은 아니다.

## 결과가 나오면 논문에서 고칠 곳

- `paper_draft.md` 2.3절: "아직 수행하지 못한 과제" 문장을 결과 인용으로 교체
- 4장: 새 절(탐지 표, 성능 표, 해석 + 위 한계)
- 5장 향후 연구: "Falco/Tetragon과의 정량적 비교" 항목 삭제
