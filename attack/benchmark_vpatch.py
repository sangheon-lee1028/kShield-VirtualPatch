#!/usr/bin/env python3
"""
benchmark_vpatch.py — kShield-VirtualPatch 성능 오버헤드 측정 도구

mock_ray_server.py의 /api/jobs/ 엔드포인트에 "정상(benign)" job을 N회
반복 제출하여 지연시간(ms)·처리량(req/s)을 측정하고 CSV로 저장한다.
kShield-VirtualPatch 비활성/활성 상태에서 각각 실행하여 오버헤드를
비교하는 데 사용한다.

주의: 이 스크립트는 아직 실행/검증되지 않았다. 실험은 4장에서
실제 VM 측정 후 수행할 예정이며, 본 파일은 그 실험에 쓸 코드만
미리 작성해 둔 것이다.

사용법:
    python3 benchmark_vpatch.py                       # 기본값: 500회, localhost:8265
    python3 benchmark_vpatch.py --count 1000 --port 8265
    python3 benchmark_vpatch.py --output metrics_vpatch_off.csv
"""
import argparse
import csv
import json
import statistics
import sys
import time
import urllib.error
import urllib.request
from datetime import datetime

DEFAULT_HOST   = "localhost"
DEFAULT_PORT   = 8265
DEFAULT_COUNT  = 500
DEFAULT_OUTPUT = "metrics_vpatch.csv"

# mock_ray_server는 entrypoint를 그대로 실행하므로, 정상 워크로드를
# 흉내내는 무해한 명령어만 사용한다 (kShield-VirtualPatch의
# suspicious_bins[]에 해당하지 않는 명령어).
BENIGN_ENTRYPOINTS = [
    "python3 -c \"print(1+1)\"",
    "echo benign-job",
    "python3 -c \"import time; time.sleep(0.01)\"",
]


def submit_job(url: str, entrypoint: str):
    payload = json.dumps({"entrypoint": entrypoint}).encode("utf-8")
    req = urllib.request.Request(
        url, data=payload, headers={"Content-Type": "application/json"}, method="POST"
    )
    t0 = time.perf_counter()
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            resp.read()
            latency_ms = (time.perf_counter() - t0) * 1000
            return latency_ms, resp.status
    except urllib.error.HTTPError as e:
        latency_ms = (time.perf_counter() - t0) * 1000
        return latency_ms, e.code
    except urllib.error.URLError as e:
        latency_ms = (time.perf_counter() - t0) * 1000
        return latency_ms, 0


def percentile(sorted_list, p):
    idx = max(0, int(len(sorted_list) * p / 100) - 1)
    return sorted_list[idx]


def run_benchmark(url: str, count: int, output_path: str) -> dict:
    print("=" * 65)
    print("  kShield-VirtualPatch 성능 벤치마크")
    print("=" * 65)
    print(f"  대상 URL : {url}")
    print(f"  반복 횟수: {count} 회")
    print(f"  출력 파일: {output_path}")
    print("-" * 65)

    latencies = []
    status_ok = 0
    status_fail = 0
    rows = []

    wall_start = time.perf_counter()

    for i in range(count):
        entrypoint = BENIGN_ENTRYPOINTS[i % len(BENIGN_ENTRYPOINTS)]
        lat, code = submit_job(url, entrypoint)

        latencies.append(lat)
        rows.append({"seq": i + 1, "latency_ms": round(lat, 3), "status": code})

        if code == 200:
            status_ok += 1
        else:
            status_fail += 1

        if (i + 1) % 100 == 0 or i == 0:
            avg_so_far = statistics.mean(latencies)
            print(f"  [{i+1:>5}/{count}]  avg={avg_so_far:.2f} ms  ok={status_ok}  fail={status_fail}")

    wall_elapsed = time.perf_counter() - wall_start
    sorted_lat = sorted(latencies)
    n = len(latencies)

    stats = {
        "timestamp": datetime.now().isoformat(timespec="seconds"),
        "url": url,
        "total_requests": count,
        "success": status_ok,
        "failure": status_fail,
        "success_rate_%": round(status_ok / count * 100, 2),
        "total_time_s": round(wall_elapsed, 3),
        "throughput_rps": round(count / wall_elapsed, 2),
        "latency_mean_ms": round(statistics.mean(latencies), 3),
        "latency_median_ms": round(statistics.median(latencies), 3),
        "latency_stdev_ms": round(statistics.stdev(latencies) if n > 1 else 0, 3),
        "latency_p95_ms": round(percentile(sorted_lat, 95), 3),
        "latency_p99_ms": round(percentile(sorted_lat, 99), 3),
    }

    with open(output_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(["## Summary Statistics"])
        for k, v in stats.items():
            writer.writerow([k, v])
        writer.writerow([])
        writer.writerow(["## Per-Request Data"])
        dict_writer = csv.DictWriter(f, fieldnames=["seq", "latency_ms", "status"])
        dict_writer.writeheader()
        dict_writer.writerows(rows)

    print()
    print("=" * 65)
    print(f"  처리량         : {stats['throughput_rps']} req/s")
    print(f"  평균 지연 시간 : {stats['latency_mean_ms']} ms")
    print(f"  P95 / P99      : {stats['latency_p95_ms']} / {stats['latency_p99_ms']} ms")
    print(f"  저장 파일      : {output_path}")
    print("=" * 65)

    return stats


def main():
    parser = argparse.ArgumentParser(description="kShield-VirtualPatch 성능 벤치마크")
    parser.add_argument("--host", default=DEFAULT_HOST)
    parser.add_argument("--port", type=int, default=DEFAULT_PORT)
    parser.add_argument("--count", type=int, default=DEFAULT_COUNT)
    parser.add_argument("--output", default=DEFAULT_OUTPUT)
    args = parser.parse_args()

    url = f"http://{args.host}:{args.port}/api/jobs/"
    run_benchmark(url, args.count, args.output)


if __name__ == "__main__":
    main()
