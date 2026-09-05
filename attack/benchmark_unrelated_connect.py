#!/usr/bin/env python3
"""
benchmark_unrelated_connect.py — 시스템 전역 오버헤드 측정용 벤치마크

배경: kShield-VirtualPatch의 SHADOW_CONNECT(kprobe/tcp_v4_connect·
tcp_v6_connect)와 LSM 사전 차단(security_socket_connect) 훅은 AI 워커
계보 여부와 무관하게 시스템의 "모든" connect() 호출에서 실행된다 —
계보 판별을 위한 BPF map 조회(ai_worker_lineage)가 매 호출마다 먼저
발생하기 때문이다. 그런데 benchmark_vpatch.py는 mock Ray 서버(AI 워커
계보 자체) 의 job 처리 성능만 측정하므로, kShield-VirtualPatch와
"무관한" 다른 프로세스들이 받는 영향은 측정하지 못한다는 한계가
4.4절에 명시되어 있었다. 이 스크립트는 그 공백을 메운다.

이 스크립트가 실제로 "무관한 프로세스"를 대표하는 이유: 계보 판별
로직(current_is_watched, src/kshield_vpatch.bpf.c 및
kshield_vpatch_lsm.bpf.c)은 "직속 부모"의 comm이 watched_parents[]
(raylet, ray::IDLE, python3)와 일치하는지, 또는 이미 lineage map에
등록되어 있는지만 확인한다. 이 스크립트를 터미널에서 직접
`python3 benchmark_unrelated_connect.py`로 실행하면, 이 프로세스
자신의 comm은 "python3"이지만 그 직속 부모는 bash/sh(터미널 셸)이지
watched_parents[]의 어떤 것과도 일치하지 않으므로, lineage에 편입되지
않는다. 즉 이 스크립트가 만드는 connect() 호출들은 정확히 "AI 워커
계보 밖의 무관한 connect()"를 대표한다.

측정 대상: mock Ray 서버나 실제 네트워크 목적지가 아니라, 이 스크립트
자신이 백그라운드 스레드로 띄우는 로컬 더미 TCP 리스너다(accept 후
즉시 닫기만 함 — 어떤 애플리케이션 로직도 없어, 순수하게 connect()
자체의 지연시간만 측정하기 위함). kShield-VirtualPatch 활성화 여부에
따라 이 "아무 관련 없는" connect() 성능이 달라지는지를 stat_analysis.py
로 비교 측정한다.

주의: current_is_watched() 검사(계보 map 조회 + 부모 comm 비교)는
목적지 주소를 읽기 "전"에 먼저 실행되고, 계보에 속하지 않으면 그
자리에서 바로 return 0으로 빠진다(src/kshield_vpatch.bpf.c의
trace_shadow_connect_v4/v6, kshield_vpatch_lsm.bpf.c의
kshield_lsm_socket_connect 참고). 즉 "무관한 프로세스"에게는 목적지가
loopback이든 외부 IP든 상관없이 항상 이 진입부 오버헤드만 적용된다.
그래서 목적지를 굳이 외부로 두지 않고 로컬 더미 리스너로 고정해도,
이 스크립트가 측정하는 "무관한 프로세스가 매 connect()마다 치르는
비용"은 정확하다.

사용법:
    python3 attack/benchmark_unrelated_connect.py --count 500 --output out.csv
    python3 attack/stat_analysis.py measure --group off_unrelated --runs 10 \\
        --bench-script attack/benchmark_unrelated_connect.py --port 19999
"""
import argparse
import csv
import socket
import statistics
import sys
import threading
import time
from datetime import datetime

DEFAULT_HOST   = "127.0.0.1"
DEFAULT_PORT   = 19999
DEFAULT_COUNT  = 500
DEFAULT_OUTPUT = "metrics_unrelated.csv"


def _dummy_listener(host: str, port: int, stop_event: threading.Event):
    """accept 후 아무 처리 없이 즉시 닫기만 하는 더미 TCP 서버.
    connect() 자체의 지연시간만 순수하게 측정하기 위해, 애플리케이션
    로직(요청 파싱, 응답 생성 등)을 의도적으로 배제하였다."""
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind((host, port))
    srv.listen(128)
    srv.settimeout(0.5)
    while not stop_event.is_set():
        try:
            conn, _ = srv.accept()
            conn.close()
        except socket.timeout:
            continue
        except OSError:
            break
    srv.close()


def percentile(sorted_list, p):
    idx = max(0, int(len(sorted_list) * p / 100) - 1)
    return sorted_list[idx]


def run_benchmark(host: str, port: int, count: int, output_path: str) -> dict:
    print("=" * 65)
    print("  kShield-VirtualPatch 시스템 전역 오버헤드 벤치마크")
    print("  (AI 워커 계보와 무관한 connect() 측정)")
    print("=" * 65)
    print(f"  대상       : {host}:{port} (이 스크립트가 띄우는 로컬 더미 리스너)")
    print(f"  반복 횟수  : {count} 회")
    print(f"  출력 파일  : {output_path}")
    print("-" * 65)

    stop_event = threading.Event()
    listener = threading.Thread(target=_dummy_listener, args=(host, port, stop_event), daemon=True)
    listener.start()
    time.sleep(0.2)  # 리스너가 bind/listen을 마칠 시간을 준다

    latencies = []
    rows = []
    fail = 0

    try:
        wall_start = time.perf_counter()
        for i in range(count):
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            t0 = time.perf_counter()
            try:
                sock.connect((host, port))
                lat = (time.perf_counter() - t0) * 1000
                latencies.append(lat)
                rows.append({"seq": i + 1, "latency_ms": round(lat, 3), "status": "ok"})
            except OSError:
                fail += 1
                rows.append({"seq": i + 1, "latency_ms": -1, "status": "fail"})
            finally:
                sock.close()

            if (i + 1) % 100 == 0 or i == 0:
                avg_so_far = statistics.mean(latencies) if latencies else float("nan")
                print(f"  [{i+1:>5}/{count}]  avg={avg_so_far:.4f} ms  fail={fail}")
        wall_elapsed = time.perf_counter() - wall_start
    finally:
        stop_event.set()
        listener.join(timeout=2)

    sorted_lat = sorted(latencies)
    n = len(latencies)

    stats = {
        "timestamp": datetime.now().isoformat(timespec="seconds"),
        "target": f"{host}:{port}",
        "total_requests": count,
        "success": n,
        "failure": fail,
        "total_time_s": round(wall_elapsed, 3),
        "throughput_rps": round(count / wall_elapsed, 2),
        "latency_mean_ms": round(statistics.mean(latencies), 4) if n else 0,
        "latency_median_ms": round(statistics.median(latencies), 4) if n else 0,
        "latency_stdev_ms": round(statistics.stdev(latencies) if n > 1 else 0, 4),
        "latency_p95_ms": round(percentile(sorted_lat, 95), 4) if n else 0,
        "latency_p99_ms": round(percentile(sorted_lat, 99), 4) if n else 0,
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
    parser = argparse.ArgumentParser(description="kShield-VirtualPatch 시스템 전역(무관 프로세스) 오버헤드 벤치마크")
    parser.add_argument("--host", default=DEFAULT_HOST)
    parser.add_argument("--port", type=int, default=DEFAULT_PORT)
    parser.add_argument("--count", type=int, default=DEFAULT_COUNT)
    parser.add_argument("--output", default=DEFAULT_OUTPUT)
    args = parser.parse_args()

    run_benchmark(args.host, args.port, args.count, args.output)


if __name__ == "__main__":
    main()
