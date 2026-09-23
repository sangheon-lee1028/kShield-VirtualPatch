#!/usr/bin/env python3
"""
mock_bentoml_server.py — CVE-2024-2912/CVE-2025-27520(BentoML 역직렬화 RCE) 재현용 목업 서버

BentoML은 서비스 API 엔드포인트로 들어오는 요청의 Content-Type이
"application/vnd.bentoml+pickle"이면, 페이로드 메타데이터에
"buffer-lengths" 키가 없는 경우 본문을 검증 없이 그대로 pickle.loads()로
역직렬화한다. MLflow(CVE-2024-37054)와 같은 pickle 기반 취약점이지만,
MLflow처럼 "업로드 후 나중에 로드"하는 2단계가 아니라 **요청 한 번에
즉시** 역직렬화·실행된다는 점이 다르다.

실제 pickle 바이트 인코딩(__reduce__를 이용한 코드 실행)은 구현하지
않고, "이 Content-Type이 붙은 요청 본문이 검증 없이 그대로 실행된다"는
결과만 payload_cmd로 직접 재현한다(mock_ray_server.py와 동일한 단순화
원칙). 실제 역직렬화는 요청을 받은 이 프로세스 안에서 곧바로 일어나므로,
이 프로세스 자신이 직접 fork하는 1단계 계보로 재현한다.

이 스크립트를 이름을 바꾼 인터프리터로 실행해야 comm이 "bentoml"이 된다.
watched_parents 기본값에는 "bentoml"이 없으므로, kshield_ctl parent-add
bentoml로 런타임에 등록해야 탐지된다.

사용법:
    cp "$(which python3)" /tmp/bentoml
    /tmp/bentoml mock_bentoml_server.py [--port 3000]
"""
import argparse
import json
import subprocess
from http.server import BaseHTTPRequestHandler, HTTPServer


class MockBentoMLHandler(BaseHTTPRequestHandler):
    def do_POST(self):
        if self.path != "/predict":
            self.send_response(404)
            self.end_headers()
            return

        content_type = self.headers.get("Content-Type", "")
        length = int(self.headers.get("Content-Length", 0))
        body = json.loads(self.rfile.read(length)) if length else {}

        vulnerable = content_type == "application/vnd.bentoml+pickle"
        print(f"[mock-bentoml] 요청 수신: Content-Type={content_type!r} "
              f"(취약 경로: {'예 — 검증 없이 역직렬화' if vulnerable else '아니오'})")

        if vulnerable:
            payload_cmd = body.get("payload_cmd", "")
            if payload_cmd:
                # 실제로는 pickle.loads()가 이 프로세스 안에서 곧바로
                # 공격자 객체의 __reduce__를 호출한다.
                subprocess.Popen(["/bin/sh", "-c", payload_cmd])

        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(json.dumps({"status": "processed"}).encode())

    def log_message(self, format, *args):
        pass  # 기본 HTTP 액세스 로그 억제


def main():
    parser = argparse.ArgumentParser(description="BentoML 역직렬화 RCE 재현용 목업 서버")
    parser.add_argument("--port", type=int, default=3000)
    args = parser.parse_args()

    server = HTTPServer(("0.0.0.0", args.port), MockBentoMLHandler)
    print(f"Mock BentoML 서버 시작 (포트 {args.port}, pickle Content-Type 검증 없음 — 취약 상태 재현)")
    print("종료: Ctrl+C")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
