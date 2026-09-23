#!/usr/bin/env python3
"""
mock_gradio_server.py — CVE-2024-1561(Gradio /component_server 임의 메서드 호출) 재현용 목업 서버

Gradio의 /component_server 엔드포인트는 Component 클래스의 어떤
메서드든 공격자가 지정한 인자로 호출할 수 있게 열려 있다. 공개된 사례는
move_resource_to_block_cache()를 악용한 임의 파일 읽기이지만, 이 취약점의
본질은 "메서드 이름과 인자를 공격자가 마음대로 골라 호출할 수 있다"는
것이다. 지금까지(Ray·TorchServe·MLflow·Triton·vLLM)는 전부 "모델을
등록·로드하면 그 안의 코드가 실행된다"는 형태였던 반면, 이건 **모델
로딩과 무관하게 서버가 스스로 노출한 RPC 스타일 엔드포인트가 임의
메서드 호출을 허용하는** 전혀 다른 유형의 취약점이다.

실제 Component 클래스·메서드 디스패치 로직은 구현하지 않고, "임의
메서드 호출이 검증 없이 이뤄진다"는 결과만 payload_cmd로 직접
재현한다(mock_ray_server.py와 동일한 단순화 원칙 — 여기서는 셸 명령을
실행하는 가상의 메서드를 호출하는 것으로 단순화). 호출은 이 프로세스
안에서 곧바로 일어나므로, 이 프로세스 자신이 직접 fork하는 1단계
계보로 재현한다.

이 스크립트를 이름을 바꾼 인터프리터로 실행해야 comm이 "gradio"가 된다.
watched_parents 기본값에는 "gradio"가 없으므로, kshield_ctl parent-add
gradio로 런타임에 등록해야 탐지된다.

사용법:
    cp "$(which python3)" /tmp/gradio
    /tmp/gradio mock_gradio_server.py [--port 7860]
"""
import argparse
import json
import subprocess
from http.server import BaseHTTPRequestHandler, HTTPServer


class MockGradioHandler(BaseHTTPRequestHandler):
    def do_POST(self):
        if self.path != "/component_server":
            self.send_response(404)
            self.end_headers()
            return

        length = int(self.headers.get("Content-Length", 0))
        body = json.loads(self.rfile.read(length)) if length else {}
        component_id = body.get("component_id", "0")
        method_name = body.get("method_name", "move_resource_to_block_cache")
        # 실제로는 method_name이 가리키는 Component 클래스의 실제 메서드가
        # 인자와 함께 그대로 호출된다. 여기서는 그 호출 결과를
        # payload_cmd로 직접 받는다(재현 단순화).
        payload_cmd = body.get("args", {}).get("payload_cmd", "")

        print(f"[mock-gradio] /component_server 호출됨 (인증·메서드 화이트리스트 없음): "
              f"component_id={component_id!r} method_name={method_name!r} payload_cmd={payload_cmd!r}")

        if payload_cmd:
            subprocess.Popen(["/bin/sh", "-c", payload_cmd])

        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(json.dumps({"status": "ok"}).encode())

    def log_message(self, format, *args):
        pass  # 기본 HTTP 액세스 로그 억제


def main():
    parser = argparse.ArgumentParser(description="Gradio /component_server 임의 메서드 호출(CVE-2024-1561) 재현용 목업 서버")
    parser.add_argument("--port", type=int, default=7860)
    args = parser.parse_args()

    server = HTTPServer(("0.0.0.0", args.port), MockGradioHandler)
    print(f"Mock Gradio 서버 시작 (포트 {args.port}, /component_server 메서드 화이트리스트 없음 — 취약 상태 재현)")
    print("종료: Ctrl+C")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
