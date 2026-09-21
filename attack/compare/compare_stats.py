#!/usr/bin/env python3
"""
compare_stats.py — run_comparison.py perf 결과(cmp_raw_*.csv) 통계 분석

기준(off) 대비 각 그룹에 대해 워크로드별로 다음을 계산한다.
  - 평균 차이(%)와 95% 신뢰구간 (Welch)
  - Welch's t-test p-값 (Bonferroni 보정 α 기준으로 유의성 판정)
  - TOST 동등성 검정 p-값 (사전에 고정한 마진 ±margin% 안에 들어오는가)
  - 판정: 차이 있음 / 동등 / 유의하나 마진 이내 / 판정 불가

"p > 0.05"는 "차이가 없음"의 증명이 아니다. 차이가 작다고 주장하려면 마진을 데이터를
보기 전에 정해 두고 TOST로 입증해야 한다. 판정 불가는 결과를 그대로 보고하면 된다.

사용법:
    python3 attack/compare/compare_stats.py attack/results/cmp_raw_<ts>.csv
    python3 attack/compare/compare_stats.py <raw.csv> --margin-pct 2 --baseline off
"""
import argparse
import csv
import math
import os
import statistics
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import stat_analysis  # noqa: E402  (scipy 대조 검증을 마친 t 분포 CDF 재사용)

METRICS = [("throughput", "thr", "처리량 (req/s)"), ("latency", "lat", "평균 지연 (ms)")]


def two_sided_p(t, df):
    return stat_analysis.t_dist_cdf(abs(t), df)


def upper_tail(t, df):
    """P(T > t)."""
    p2 = two_sided_p(t, df)
    return p2 / 2 if t >= 0 else 1 - p2 / 2


def t_crit(df, alpha):
    lo, hi = 0.0, 200.0
    for _ in range(100):
        mid = (lo + hi) / 2
        if two_sided_p(mid, df) > alpha:
            lo = mid
        else:
            hi = mid
    return (lo + hi) / 2


def load_raw(path):
    data = {}
    with open(path, newline="", encoding="utf-8") as f:
        for r in csv.DictReader(f):
            d = data.setdefault((r["workload"], r["group"]),
                                {"thr": [], "lat": [], "p99": [], "cpu": [], "rss": [], "fail": 0})
            d["thr"].append(float(r["throughput_rps"]))
            d["lat"].append(float(r["latency_mean_ms"]))
            d["p99"].append(float(r["latency_p99_ms"]))
            if r.get("tool_cpu_s"):
                d["cpu"].append(float(r["tool_cpu_s"]))
            if r.get("tool_rss_kb"):
                d["rss"].append(float(r["tool_rss_kb"]))
            d["fail"] += int(float(r.get("failures") or 0))
    return data


def compare(g, b, margin_pct, alpha, alpha_tost):
    n1, n2 = len(g), len(b)
    m1, m2 = statistics.mean(g), statistics.mean(b)
    v1, v2 = statistics.variance(g) / n1, statistics.variance(b) / n2
    se = math.sqrt(v1 + v2)
    diff = m1 - m2
    if se == 0:
        return {"diff_pct": diff / m2 * 100, "ci": (diff / m2 * 100,) * 2, "p": 1.0 if diff == 0 else 0.0,
                "p_tost": 0.0 if abs(diff) < abs(margin_pct) / 100 * m2 else 1.0}
    df = (v1 + v2) ** 2 / (v1 ** 2 / (n1 - 1) + v2 ** 2 / (n2 - 1))
    tc = t_crit(df, 0.05)
    delta = abs(margin_pct) / 100 * m2
    p_lower = upper_tail((diff + delta) / se, df)
    p_upper = upper_tail((delta - diff) / se, df)
    return {
        "diff_pct": diff / m2 * 100,
        "ci": ((diff - tc * se) / m2 * 100, (diff + tc * se) / m2 * 100),
        "p": two_sided_p(diff / se, df),
        "p_tost": max(p_lower, p_upper),
    }


def verdict(res, alpha_adj, alpha_tost):
    sig = res["p"] < alpha_adj
    equiv = res["p_tost"] < alpha_tost
    if equiv and sig:
        return "유의하나 마진 이내"
    if equiv:
        return "동등"
    if sig:
        return "차이 있음"
    return "판정 불가"


def fmt_ms(vals, nd):
    return f"{statistics.mean(vals):.{nd}f} ± {statistics.stdev(vals):.{nd}f}" if len(vals) > 1 else "-"


def main():
    ap = argparse.ArgumentParser(description="비교 실험 통계 분석")
    ap.add_argument("raw", help="cmp_raw_*.csv")
    ap.add_argument("--baseline", default="off")
    ap.add_argument("--margin-pct", type=float, default=2.0,
                    help="동등성 마진(기준 평균 대비 %%). 데이터를 보기 전에 고정할 것")
    ap.add_argument("--alpha", type=float, default=0.05)
    ap.add_argument("--adjust-tost", action="store_true", help="TOST 임계값에도 Bonferroni 보정 적용")
    args = ap.parse_args()

    data = load_raw(args.raw)
    workloads = sorted({w for w, _ in data}, key=lambda w: (w != "normal", w))
    groups = sorted({g for _, g in data}, key=lambda g: (g != args.baseline, g))
    if args.baseline not in groups:
        sys.exit(f"기준 그룹 '{args.baseline}' 이(가) 데이터에 없습니다: {groups}")
    others = [g for g in groups if g != args.baseline]
    m = len(others) * len(METRICS) * len(workloads)
    alpha_adj = args.alpha / m
    alpha_tost = alpha_adj if args.adjust_tost else args.alpha

    out_path = os.path.splitext(args.raw)[0] + "_summary.csv"
    summary = []

    print(f"기준 그룹={args.baseline} | 그룹={others} | 검정 {m}회 → Bonferroni α={alpha_adj:.4f} | "
          f"동등성 마진 ±{args.margin_pct}% (TOST α={alpha_tost:.4f})")

    for wl in workloads:
        base = data.get((wl, args.baseline))
        if not base:
            continue
        print(f"\n{'=' * 78}\n워크로드: {wl}   (기준 N={len(base['thr'])})\n{'=' * 78}")
        for key, short, label in METRICS:
            nd = 2 if key == "throughput" else 3
            print(f"\n[{label}]")
            print(f"{'그룹':<14}{'평균 ± SD':<20}{'차이 %':>9}  {'95% CI (%)':<18}{'Welch p':>9}{'TOST p':>9}  판정")
            print(f"{args.baseline:<14}{fmt_ms(base[short], nd):<20}{'(기준)':>9}")
            for g in others:
                d = data.get((wl, g))
                if not d:
                    continue
                res = compare(d[short], base[short], args.margin_pct, args.alpha, alpha_tost)
                v = verdict(res, alpha_adj, alpha_tost)
                ci = f"[{res['ci'][0]:+.2f}, {res['ci'][1]:+.2f}]"
                print(f"{g:<14}{fmt_ms(d[short], nd):<20}{res['diff_pct']:>+8.2f}%  {ci:<18}"
                      f"{res['p']:>9.4f}{res['p_tost']:>9.4f}  {v}")
                summary.append({"workload": wl, "group": g, "metric": key,
                                "mean": statistics.mean(d[short]), "sd": statistics.stdev(d[short]),
                                "diff_pct": res["diff_pct"], "ci_lo": res["ci"][0], "ci_hi": res["ci"][1],
                                "welch_p": res["p"], "tost_p": res["p_tost"], "verdict": v})

        print("\n[참고: p99 지연 · 도구 사용자 공간 자원]")
        print(f"{'그룹':<14}{'p99 지연 (ms)':<20}{'CPU s/런':<14}{'RSS (MB)':<12}{'실패 요청'}")
        for g in [args.baseline] + others:
            d = data.get((wl, g))
            if not d:
                continue
            cpu = f"{statistics.mean(d['cpu']):.3f}" if d["cpu"] else "-"
            rss = f"{statistics.mean(d['rss']) / 1024:.0f}" if d["rss"] else "-"
            print(f"{g:<14}{fmt_ms(d['p99'], 3):<20}{cpu:<14}{rss:<12}{d['fail']}")

    with open(out_path, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=list(summary[0].keys()))
        w.writeheader()
        w.writerows(summary)
    print(f"\n요약 CSV: {out_path}")
    print("해석 주의: CPU s/런은 사용자 공간 에이전트 비용만이며, BPF 프로그램 실행 시간은 "
          "트리거한 프로세스에 계상되어 처리량/지연에 반영된다.")


if __name__ == "__main__":
    main()
