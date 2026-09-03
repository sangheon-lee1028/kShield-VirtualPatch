#!/usr/bin/env python3
"""
mock_ray_server.py — CVE-2023-48022(ShadowRay) 취약점 재현용 목업 서버

실제 Ray 클러스터의 Jobs Submission API(기본 포트 8265)는 기본 설정에서
인증 메커니즘이 없어, 네트워크로 접근 가능한 누구나 임의의 코드를
원격에서 실행시킬 수 있다. 실제 Ray 전체를 설치하지 않고도 이 핵심
취약점(인증 없는 원격 코드 실행)만 재현하기 위한 목업 서버다.

/api/jobs/ 엔드포인트로 POST된 "entrypoint" 문자열을 인증 검사 없이
그대로 서브프로세스로 실행한다 — 실제 Ray Jobs API가 job을 제출받아
워커 프로세스에서 실행하는 것과 동일한 핵심 동작이다.

사용법:
    python3 mock_ray_server.py [--port 8265]
"""
import argparse
import json
import subprocess
from http.server import BaseHTTPRequestHandler, HTTPServer


class MockRayJobsHandler(BaseHTTPRequestHandler):
    def do_POST(self):
        if self.path != "/api/jobs/":
            self.send_response(404)
            self.end_headers()
            return

        length = int(self.headers.get("Content-Length", 0))
        body = json.loads(self.rfile.read(length)) if length else {}
        entrypoint = body.get("entrypoint", "")

        print(f"[mock-ray] job 제출됨 (인증 검사 없음): {entrypoint!r}")

        # 실제 Ray 워커가 하는 것처럼, entrypoint 명령어를 그대로 셸에서 실행한다.
        # 프로세스 이름을 kshield_vpatch.bpf.c의 watched_parents[]와
        # 맞추기 위해 raylet이라는 이름으로 wrapper 스크립트를 거쳐 실행한다.
        subprocess.Popen(["/bin/sh", "-c", entrypoint])

        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(json.dumps({"job_id": "raysubmit_mock"}).encode())

    def log_message(self, format, *args):
        pass  # 기본 HTTP 액세스 로그 억제


def main():
    parser = argparse.ArgumentParser(description="ShadowRay 취약점 재현용 목업 Jobs API 서버")
    parser.add_argument("--port", type=int, default=8265)
    args = parser.parse_args()

    server = HTTPServer(("0.0.0.0", args.port), MockRayJobsHandler)
    print(f"Mock Ray Jobs API 서버 시작 (포트 {args.port}, 인증 없음 — 취약 상태 재현)")
    print("종료: Ctrl+C")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
