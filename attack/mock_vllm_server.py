#!/usr/bin/env python3
"""
mock_vllm_server.py — CVE-2025-66448(vLLM trust_remote_code 우회) 재현용 목업 서버

vLLM은 HuggingFace 모델 저장소의 커스텀 코드(예: 모델 아키텍처 정의)를
실행할지 여부를 trust_remote_code 플래그로 통제한다. 운영자가
trust_remote_code=False로 설정하면 신뢰 안 된 저장소의 코드는 실행되지
않아야 한다 — 즉 이 플래그는 앞선 네 사례와 달리 "운영자가 이미 안전
조치를 취했다고 믿는" 상태를 전제한다.

CVE-2025-66448은 이 안전장치 자체가 뚫리는 경우다. 모델의 config.json에
있는 auto_map 필드가 "프런트엔드" 저장소가 아닌 별도의 "백엔드" 저장소를
가리킬 수 있는데, vLLM이 get_class_from_dynamic_module로 그 매핑을
해석·로드하는 과정이 trust_remote_code=False 설정과 무관하게 그 백엔드
저장소의 Python 코드를 가져와 실행한다. 즉 "안전한 모델처럼 보이는
프런트엔드"를 신뢰하는 순간, 그 프런트엔드가 가리키는 임의의 백엔드
코드가 검증 없이 실행된다.

실제 config.json 파싱·auto_map 해석 로직은 구현하지 않고, "trust_remote_
code=False로 설정했음에도 모델 로드 시 원격 코드가 그대로 실행된다"는
결과만 재현한다(mock_ray_server.py와 동일한 단순화 원칙). 실제 취약점은
vLLM 서버 프로세스 안에서 직접(별도 워커로 넘어가지 않고) 실행되므로,
여기서도 이 프로세스 자신이 직접 fork하는 1단계 계보로 재현한다.

이 스크립트를 이름을 바꾼 인터프리터로 실행해야 comm이 "vllm"이 된다.
watched_parents 기본값에는 "vllm"이 없으므로, kshield_ctl parent-add
vllm으로 런타임에 등록해야 탐지된다.

사용법:
    cp "$(which python3)" /tmp/vllm
    /tmp/vllm mock_vllm_server.py [--port 8001]
"""
import argparse
import json
import subprocess
from http.server import BaseHTTPRequestHandler, HTTPServer


class MockVLLMHandler(BaseHTTPRequestHandler):
    def do_POST(self):
        if self.path != "/v1/load_model":
            self.send_response(404)
            self.end_headers()
            return

        length = int(self.headers.get("Content-Length", 0))
        body = json.loads(self.rfile.read(length)) if length else {}
        model = body.get("model", "attacker/frontend-model")
        auto_map_backend = body.get("auto_map_backend", "attacker/backend-model")
        # 실제로는 auto_map_backend 저장소의 modeling_*.py 안 클래스가
        # get_class_from_dynamic_module을 통해 그대로 실행된다. 여기서는
        # 그 실행될 내용을 payload_cmd로 직접 받는다(재현 단순화).
        payload_cmd = body.get("payload_cmd", "")

        print(f"[mock-vllm] 모델 로드 요청: model={model!r} trust_remote_code=False "
              f"(운영자는 안전하다고 설정함) — 그러나 auto_map이 가리키는 "
              f"백엔드 저장소({auto_map_backend!r})의 코드는 검증 없이 실행됨")

        if payload_cmd:
            # 실제 취약점은 vLLM 서버 프로세스 자신 안에서(별도 워커 없이)
            # 실행되므로, 이 서버 자신이 직접 fork한다.
            subprocess.Popen(["/bin/sh", "-c", payload_cmd])

        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(json.dumps({"model": model, "status": "loaded"}).encode())

    def log_message(self, format, *args):
        pass  # 기본 HTTP 액세스 로그 억제


def main():
    parser = argparse.ArgumentParser(description="vLLM trust_remote_code 우회(CVE-2025-66448) 재현용 목업 서버")
    parser.add_argument("--port", type=int, default=8001)
    args = parser.parse_args()

    server = HTTPServer(("0.0.0.0", args.port), MockVLLMHandler)
    print(f"Mock vLLM 서버 시작 (포트 {args.port}, trust_remote_code=False이지만 auto_map 우회 — 취약 상태 재현)")
    print("종료: Ctrl+C")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
