#!/usr/bin/env python3
"""
stat_analysis.py — kShield-VirtualPatch 반복 측정 + Welch's t-test 통계 분석 도구

논문 4장 실험: benchmark_vpatch.py를 N회 반복 실행하여 평균±표준편차를
산출하고, kShield-VirtualPatch 비활성(off) vs 활성(on) 두 그룹 간
Welch's t-test로 통계적 유의성을 검증한다.

사용법:
    # 1단계: 각 그룹별 반복 측정 (그룹마다 별도 실행 — 아래 실험 절차 참고)
    python3 stat_analysis.py measure --group vpatch_off --runs 10
    python3 stat_analysis.py measure --group vpatch_on  --runs 10

    # 2단계: 두 그룹 비교 (t-test)
    python3 stat_analysis.py compare --compare results/stats_vpatch_off.csv results/stats_vpatch_on.csv

실험 절차:
    1) mock_ray_server.py 실행 (터미널 A)
    2) [vpatch_off 측정] kShield-VirtualPatch를 실행하지 않은 상태로
       `measure --group vpatch_off --runs 10` 수행
    3) kShield-VirtualPatch 실행 (터미널 B: sudo ./src/kshield_vpatch)
    4) [vpatch_on 측정] `measure --group vpatch_on --runs 10` 수행
    5) `compare`로 두 결과 비교

시스템 전역(무관한 프로세스) 오버헤드 측정: mock_ray_server.py 없이도
--bench-script로 benchmark_unrelated_connect.py를 지정하면, AI 워커
계보와 무관한 connect() 성능에 kShield-VirtualPatch가 미치는 영향을
측정할 수 있다.
    python3 stat_analysis.py measure --group off_unrelated --runs 10 \\
        --bench-script attack/benchmark_unrelated_connect.py --port 19999

fork 집약적 워크로드 측정: --fork-heavy를 추가하면 benchmark_vpatch.py가
job당 fork를 훨씬 많이 발생시키는 entrypoint를 사용한다(실제 Ray의
빈번한 워커 프로세스 생성 패턴 재현, 4.4절 한계 3 대응).
    python3 stat_analysis.py measure --group off_fork --runs 10 --fork-heavy
"""

import argparse
import csv
import math
import os
import statistics
import subprocess
import sys
from datetime import datetime

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
RESULTS_DIR = os.path.join(SCRIPT_DIR, "results")
BENCH_SCRIPT = os.path.join(SCRIPT_DIR, "benchmark_vpatch.py")


# ── Welch's t-test (stdlib only, scipy optional) ───────────────────────────
def _regularized_incomplete_beta(a, b, x, iterations=200):
    """수치 적분으로 정규화 불완전 베타함수 근사 (p-value 계산용)"""
    if x <= 0:
        return 0.0
    if x >= 1:
        return 1.0
    lbeta = math.lgamma(a) + math.lgamma(b) - math.lgamma(a + b)
    front = math.exp(math.log(x) * a + math.log(1 - x) * b - lbeta) / a

    def cf():
        TINY = 1e-30
        f = TINY
        C, D = f, 0.0
        for m in range(iterations):
            for sign in (1, -1):
                if m == 0 and sign == 1:
                    d = 1.0
                elif sign == 1:
                    d = m * (b - m) * x / ((a + 2 * m - 1) * (a + 2 * m))
                else:
                    d = -(a + m) * (a + b + m) * x / ((a + 2 * m) * (a + 2 * m + 1))
                D = 1.0 + d * D
                if abs(D) < TINY:
                    D = TINY
                D = 1.0 / D
                C = 1.0 + d / C
                if abs(C) < TINY:
                    C = TINY
                f *= C * D
                if abs(C * D - 1.0) < 1e-10:
                    break
        return f

    return front * cf()


def t_dist_cdf(t, df):
    """t 분포 누적분포함수 (양측 p-value 계산용)"""
    x = df / (df + t * t)
    p_one_tail = 0.5 * _regularized_incomplete_beta(df / 2, 0.5, x)
    return 2 * p_one_tail


def welch_ttest(a, b):
    """Welch's t-test: (t, df, p) 반환"""
    try:
        from scipy import stats as sp
        t, p = sp.ttest_ind(a, b, equal_var=False)
        return float(t), None, float(p)
    except ImportError:
        pass

    n1, n2 = len(a), len(b)
    m1, m2 = statistics.mean(a), statistics.mean(b)
    v1 = statistics.variance(a) / n1
    v2 = statistics.variance(b) / n2
    se = math.sqrt(v1 + v2)
    if se == 0:
        return 0.0, float("inf"), 1.0
    t = (m1 - m2) / se
    df = (v1 + v2) ** 2 / (v1 ** 2 / (n1 - 1) + v2 ** 2 / (n2 - 1))
    p = t_dist_cdf(abs(t), df)
    return t, df, p


# ── 벤치마크 1회 실행 ───────────────────────────────────────────────────────
def run_once(host, port, count, out_path, bench_script=None, fork_heavy=False):
    cmd = [
        sys.executable, bench_script or BENCH_SCRIPT,
        "--host", host, "--port", str(port),
        "--count", str(count), "--output", out_path,
    ]
    if fork_heavy:
        cmd.append("--fork-heavy")
    subprocess.run(cmd, check=True, stdout=subprocess.DEVNULL)

    stats = {}
    with open(out_path, newline="", encoding="utf-8") as f:
        for row in csv.reader(f):
            if len(row) == 2:
                try:
                    stats[row[0]] = float(row[1])
                except ValueError:
                    pass
    return stats


# ── 반복 측정 모드 ──────────────────────────────────────────────────────────
def run_repeated(args):
    os.makedirs(RESULTS_DIR, exist_ok=True)
    print(f"{'='*58}")
    print(f"  [{args.group}]  {args.runs}회 반복 측정")
    print(f"{'='*58}")

    throughputs, latencies = [], []

    for i in range(args.runs):
        ts = datetime.now().strftime("%Y%m%d_%H%M%S_%f")[:19]
        out = os.path.join(RESULTS_DIR, f"stat_{args.group}_r{i+1}_{ts}.csv")
        print(f"  Run {i+1}/{args.runs} ...", end="  ", flush=True)
        s = run_once(args.host, args.port, args.count, out,
                      bench_script=args.bench_script, fork_heavy=args.fork_heavy)
        thr = s.get("throughput_rps", float("nan"))
        lat = s.get("latency_mean_ms", float("nan"))
        throughputs.append(thr)
        latencies.append(lat)
        print(f"throughput={thr:.2f} req/s   latency={lat:.3f} ms")

    mean_t = statistics.mean(throughputs)
    std_t = statistics.stdev(throughputs)
    mean_l = statistics.mean(latencies)
    std_l = statistics.stdev(latencies)

    print(f"\n  처리량  : {mean_t:.2f} ± {std_t:.2f} req/s")
    print(f"  지연시간: {mean_l:.3f} ± {std_l:.3f} ms")

    stats_path = os.path.join(RESULTS_DIR, f"stats_{args.group}.csv")
    with open(stats_path, "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["group", "runs", "throughput_mean", "throughput_std", "latency_mean", "latency_std"])
        w.writerow([args.group, args.runs, mean_t, std_t, mean_l, std_l])
        w.writerow([])
        w.writerow(["run", "throughput_rps", "latency_mean_ms"])
        for i, (t, l) in enumerate(zip(throughputs, latencies), 1):
            w.writerow([i, t, l])

    print(f"  저장: {stats_path}")
    print(f"{'='*58}\n")


# ── 비교(t-test) 모드 ──────────────────────────────────────────────────────
def load_stats_csv(path):
    per_run_t, per_run_l = [], []
    with open(path, newline="", encoding="utf-8") as f:
        reader = csv.reader(f)
        header = next(reader)
        summary_row = next(reader)
        d = dict(zip(header, summary_row))
        group = d["group"]
        runs = int(float(d["runs"]))
        mean_t = float(d["throughput_mean"])
        std_t = float(d["throughput_std"])
        mean_l = float(d["latency_mean"])
        std_l = float(d["latency_std"])
        next(reader)
        next(reader)
        for row in reader:
            if len(row) >= 3 and row[0]:
                per_run_t.append(float(row[1]))
                per_run_l.append(float(row[2]))
    return group, runs, mean_t, std_t, mean_l, std_l, per_run_t, per_run_l


def run_compare(args):
    path_a, path_b = args.compare
    ga, na, mt_a, st_a, ml_a, sl_a, rt_a, rl_a = load_stats_csv(path_a)
    gb, nb, mt_b, st_b, ml_b, sl_b, rt_b, rl_b = load_stats_csv(path_b)

    t_thr, df_thr, p_thr = welch_ttest(rt_a, rt_b)
    t_lat, df_lat, p_lat = welch_ttest(rl_a, rl_b)

    def sig(p):
        return " *** (p<0.001)" if p < 0.001 else (" ** (p<0.01)" if p < 0.01 else (" * (p<0.05)" if p < 0.05 else " ns"))

    print(f"\n{'='*62}")
    print(f"  Welch's t-test:  [{ga}] (N={na})  vs  [{gb}] (N={nb})")
    print(f"{'='*62}")
    print(f"  {'지표':<14}  {ga:>12}  {gb:>12}   t-stat    p-value")
    print(f"  {'-'*58}")
    print(f"  {'처리량(req/s)':<14}  {mt_a:>8.2f}±{st_a:<5.2f}  {mt_b:>8.2f}±{st_b:<5.2f}   {t_thr:+.3f}   {p_thr:.4f}{sig(p_thr)}")
    print(f"  {'지연(ms)':<14}  {ml_a:>8.3f}±{sl_a:<5.3f}  {ml_b:>8.3f}±{sl_b:<5.3f}   {t_lat:+.3f}   {p_lat:.4f}{sig(p_lat)}")
    print(f"{'='*62}\n")


def main():
    parser = argparse.ArgumentParser(description="kShield-VirtualPatch 반복 측정 + Welch's t-test")
    sub = parser.add_subparsers(dest="cmd")

    m = sub.add_parser("measure", help="그룹 반복 측정")
    m.add_argument("--group", required=True, help="그룹 이름 (예: vpatch_off, vpatch_on)")
    m.add_argument("--runs", type=int, default=10, help="반복 횟수 (기본: 10)")
    m.add_argument("--count", type=int, default=500, help="요청 수 (기본: 500)")
    m.add_argument("--host", default="localhost")
    m.add_argument("--port", type=int, default=8265)
    m.add_argument("--bench-script", default=None,
                    help="사용할 벤치마크 스크립트 경로 (기본: benchmark_vpatch.py). "
                         "예: attack/benchmark_unrelated_connect.py (시스템 전역 오버헤드 측정용)")
    m.add_argument("--fork-heavy", action="store_true",
                    help="benchmark_vpatch.py에 --fork-heavy를 전달 (fork 집약적 entrypoint 사용)")

    c = sub.add_parser("compare", help="두 그룹 t-test 비교")
    c.add_argument("--compare", nargs=2, metavar=("A.csv", "B.csv"), required=True)

    args = parser.parse_args()
    if args.cmd == "measure":
        run_repeated(args)
    elif args.cmd == "compare":
        run_compare(args)
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
