#!/usr/bin/env python3
"""
mock_textgenwebui_server.py — CVE-2025-12487/CVE-2025-12488
(oobabooga text-generation-webui trust_remote_code 노출) 재현용 목업 서버

vLLM(CVE-2025-66448)은 운영자가 trust_remote_code=False로 이미 안전
조치를 했다고 믿는 상태에서 그 설정이 간접적으로 **우회**되는
취약점이었다. text-generation-webui는 그보다 더 근본적인 문제다 —
모델 로드 API 자체가 trust_remote_code 값을 **요청 파라미터로 그대로
받아** 써서, 우회할 필요도 없이 공격자가 요청에서 직접 True로 지정하면
그만이다. "안전장치가 뚫렸다"가 아니라 "안전장치를 공격자가 그냥 켤 수
있다"는 점이 다르다.

실제 모델 로드·커스텀 코드 실행 로직은 구현하지 않고, "요청에 실린
trust_remote_code=True가 그대로 받아들여져 모델 코드가 실행된다"는
결과만 payload_cmd로 직접 재현한다(mock_ray_server.py와 동일한 단순화
원칙). 실제 취약점은 이 서버 프로세스 안에서 곧바로 실행되므로, 이
프로세스 자신이 직접 fork하는 1단계 계보로 재현한다.

이 스크립트를 이름을 바꾼 인터프리터로 실행해야 comm이 "textgenwebui"가
된다(리눅스 comm 15자 제한 안에 들어가는 축약형). watched_parents
기본값에는 "textgenwebui"가 없으므로, kshield_ctl parent-add
textgenwebui로 런타임에 등록해야 탐지된다.

사용법:
    cp "$(which python3)" /tmp/textgenwebui
    /tmp/textgenwebui mock_textgenwebui_server.py [--port 7861]
"""
import argparse
import json
import subprocess
from http.server import BaseHTTPRequestHandler, HTTPServer


class MockTextGenWebUIHandler(BaseHTTPRequestHandler):
    def do_POST(self):
        if self.path != "/api/v1/model":
            self.send_response(404)
            self.end_headers()
            return

        length = int(self.headers.get("Content-Length", 0))
        body = json.loads(self.rfile.read(length)) if length else {}
        model_name = body.get("model_name", "attacker/malicious-model")
        # 실제 취약점은 요청에 실린 trust_remote_code 값을 검증 없이 그대로
        # 모델 로드 함수에 넘긴다. 여기서는 그 실행 결과를 payload_cmd로
        # 직접 받는다(재현 단순화).
        trust_remote_code = body.get("trust_remote_code", False)
        payload_cmd = body.get("payload_cmd", "")

        print(f"[mock-textgenwebui] 모델 로드 요청: model_name={model_name!r} "
              f"trust_remote_code={trust_remote_code!r} (요청 파라미터를 검증 없이 그대로 사용)")

        if trust_remote_code and payload_cmd:
            subprocess.Popen(["/bin/sh", "-c", payload_cmd])

        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(json.dumps({"model_name": model_name, "status": "loaded"}).encode())

    def log_message(self, format, *args):
        pass  # 기본 HTTP 액세스 로그 억제


def main():
    parser = argparse.ArgumentParser(
        description="oobabooga text-generation-webui trust_remote_code 노출(CVE-2025-12487/88) 재현용 목업 서버"
    )
    parser.add_argument("--port", type=int, default=7861)
    args = parser.parse_args()

    server = HTTPServer(("0.0.0.0", args.port), MockTextGenWebUIHandler)
    print(f"Mock text-generation-webui 서버 시작 (포트 {args.port}, trust_remote_code 요청 파라미터 검증 없음 — 취약 상태 재현)")
    print("종료: Ctrl+C")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
