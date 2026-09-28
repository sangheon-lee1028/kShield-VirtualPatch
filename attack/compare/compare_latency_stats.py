#!/usr/bin/env python3
"""
compare_latency_stats.py — run_comparison.py latency 결과(latency_raw_*.csv) 분석

phase(exec/connect) x event(sync_block/post_exit) x sig 조합별로 그룹당
delta_ns의 평균 ± SD·중앙값·최소/최대를 마이크로초(µs) 단위로 요약하고,
--compare로 그룹 두 개를 지정하면 Welch's t-test로 차이를 검정한다
(compare_stats.py와 같은 t 분포 CDF 계산을 재사용 — scipy 의존 없음).

post_exit 행은 반드시 sig로 나눠 읽는다: sig=9는 SIGKILL로 실제로 죽은
것(비동기 차단이 걸린 것)이고, sig=0은 그냥 정상 종료(안 막힌 것)이다.
Falco처럼 탐지만 하는 도구를 이 스크립트로 재면 post_exit 행이 전부
sig=0으로 나오는 게 정상이며, 그건 "느린 차단"이 아니라 "차단이 없다"는
뜻이다 — sig=0 행을 sig=9 행과 같은 표로 묶어 "지연시간"이라고 부르면
안 된다.

사용법:
    python3 attack/compare/compare_latency_stats.py attack/results/latency_raw_<ts>.csv
    python3 attack/compare/compare_latency_stats.py <raw.csv> --compare kshield,kshield_lsm
"""
import argparse
import csv
import os
import statistics
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import stat_analysis  # noqa: E402  (scipy 없이 검증된 t 분포 CDF 재사용)


def two_sided_p(t, df):
    return stat_analysis.t_dist_cdf(abs(t), df)


def welch(a, b):
    n1, n2 = len(a), len(b)
    if n1 < 2 or n2 < 2:
        return None
    m1, m2 = statistics.mean(a), statistics.mean(b)
    v1, v2 = statistics.variance(a) / n1, statistics.variance(b) / n2
    se = (v1 + v2) ** 0.5
    if se == 0:
        return {"diff": m1 - m2, "p": 1.0 if m1 == m2 else 0.0}
    df = (v1 + v2) ** 2 / (v1 ** 2 / (n1 - 1) + v2 ** 2 / (n2 - 1))
    t = (m1 - m2) / se
    return {"diff": m1 - m2, "p": two_sided_p(t, df)}


def block_latencies(data, group, phase):
    """group·phase에서 '실제로 막힌' 시도의 delta_ns만 모은다 — sync_block은
    전부, post_exit은 sig=9(SIGKILL로 실제로 죽음)만 포함한다. post_exit/
    sig=0(안 막힘)은 절대 섞지 않는다. 동기 차단(sync_block)과 비동기 킬
    (post_exit/sig=9)은 event 이름이 다르므로, 이벤트 이름이 아니라 '막혔는가'
    기준으로 묶어야 kshield(전부 post_exit)와 kshield_lsm(전부 sync_block)처럼
    차단 방식 자체가 다른 두 그룹을 비교할 수 있다."""
    out = []
    for (g, p, e, s), vals in data.items():
        if g != group or p != phase:
            continue
        if e == "sync_block" or (e == "post_exit" and s == "9"):
            out.extend(vals)
    return out


def load(path):
    data = {}
    with open(path, newline="", encoding="utf-8") as f:
        for r in csv.DictReader(f):
            key = (r["group"], r["phase"], r["event"], r.get("sig") or "")
            data.setdefault(key, []).append(int(r["delta_ns"]))
    return data


def main():
    ap = argparse.ArgumentParser(description="latency_raw_*.csv 분석")
    ap.add_argument("raw")
    ap.add_argument("--compare", help="쉼표로 그룹 두 개 지정 시 Welch t-test 수행 (예: kshield,kshield_lsm)")
    args = ap.parse_args()

    data = load(args.raw)
    if not data:
        sys.exit(f"{args.raw} 에 데이터가 없습니다.")
    keys = sorted(data.keys())

    print(f"{'그룹':<14}{'phase':<9}{'event':<13}{'sig':<5}{'N':>4}  "
          f"{'평균 ± SD (µs)':<22}{'중앙값':>10}{'최소':>10}{'최대':>10}")
    for group, phase, event, sig in keys:
        vals_us = [v / 1000 for v in data[(group, phase, event, sig)]]
        n = len(vals_us)
        mean_sd = (f"{statistics.mean(vals_us):.2f} ± {statistics.stdev(vals_us):.2f}"
                   if n > 1 else f"{vals_us[0]:.2f}")
        print(f"{group:<14}{phase:<9}{event:<13}{sig or '-':<5}{n:>4}  {mean_sd:<22}"
              f"{statistics.median(vals_us):>10.2f}{min(vals_us):>10.2f}{max(vals_us):>10.2f}")

    print("\n(post_exit/sig=0은 '안 막힘'이다 — sig=9 post_exit과 절대 같은 것으로 취급하지 말 것)")

    if args.compare:
        g1, g2 = [g.strip() for g in args.compare.split(",")]
        print(f"\n[차단까지 걸린 시간 비교: {g1} vs {g2}]  "
              "(sync_block 전부 + post_exit/sig=9만 '막힘'으로 집계, sig=0은 제외)")
        phases = sorted({p for (g, p, _e, _s) in keys if g in (g1, g2)})
        if not phases:
            print(f"  {g1}, {g2} 중 데이터에 있는 그룹이 없습니다.")
        for phase in phases:
            a = [v / 1000 for v in block_latencies(data, g1, phase)]
            b = [v / 1000 for v in block_latencies(data, g2, phase)]
            if not a or not b:
                print(f"  {phase}: 한쪽 그룹에 '막힌' 데이터 없음 (건너뜀) "
                      f"(N={len(a)} vs N={len(b)})")
                continue
            res = welch(a, b)
            if res is None:
                print(f"  {phase}: 표본 부족(N<2)으로 검정 생략")
                continue
            print(f"  {phase}: {g1} 평균 {statistics.mean(a):.2f}µs "
                  f"(N={len(a)}) vs {g2} 평균 {statistics.mean(b):.2f}µs (N={len(b)}), "
                  f"차이 {res['diff']:+.2f}µs, Welch p={res['p']:.4g}")


if __name__ == "__main__":
    main()
