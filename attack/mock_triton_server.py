#!/usr/bin/env python3
"""
mock_triton_server.py — CVE-2023-31036(Triton Inference Server 경로 순회) 재현용 목업 서버

실제 Triton은 --model-control explicit 옵션(운영자가 켜야 하는 비기본값,
모델을 재시작 없이 올리고 내리기 위한 기능)으로 기동되면, 모델 저장소
API(POST /v2/repository/models/<name>/load)로 모델을 동적으로 로드할 수
있다. CVE-2023-31036은 이 로드 API의 경로 처리에 상대 경로 순회
취약점이 있어, 공격자가 모델 저장소 디렉터리 밖의 임의 경로를 모델
디렉터리로 지정할 수 있다. Triton의 Python 백엔드는 모델 디렉터리
안의 model.py를 그대로 실행하므로, 저장소 밖의 공격자 제어 경로를
가리키면 그 안의 코드가 실행된다.

경로 순회의 정확한 페이로드 형식은 공개된 PoC가 없어 재현하지 않는다
(mock_ray_server.py/mock_torchserve_server.py와 동일하게, 실제 취약점의
핵심 결과 — "인증 없는 로드 API가 공격자 제어 코드를 실행시킨다" — 만
단순화하여 재현한다).

실제 Triton 아키텍처를 반영해 2단계로 재현한다: Python 백엔드 모델은
격리를 위해 Triton 코어 프로세스(tritonserver)와 별도의 서브프로세스
(백엔드 스텁)에서 실행된다. 여기서는 이 서버 프로세스 자체가
tritonserver 역할을 하고, 모델 로드 시 Python 백엔드 스텁 프로세스를
자식으로 fork해 그 안에서 model.py(= 공격자가 지정한 명령)를 실행한다.

이 스크립트를 이름을 바꾼 인터프리터로 실행해야 comm이 "tritonserver"가
된다. watched_parents 기본값에는 "tritonserver"가 없으므로, kshield_ctl
parent-add tritonserver로 런타임에 등록해야 탐지된다.

사용법:
    cp "$(which python3)" /tmp/tritonserver
    /tmp/tritonserver mock_triton_server.py [--port 8000]
"""
import argparse
import json
import re
import subprocess
from http.server import BaseHTTPRequestHandler, HTTPServer

_LOAD_PATH_RE = re.compile(r"^/v2/repository/models/([^/]+)/load$")


class MockTritonHandler(BaseHTTPRequestHandler):
    def do_POST(self):
        m = _LOAD_PATH_RE.match(self.path)
        if not m:
            self.send_response(404)
            self.end_headers()
            return

        model_name = m.group(1)
        length = int(self.headers.get("Content-Length", 0))
        body = json.loads(self.rfile.read(length)) if length else {}
        # 실제로는 상대 경로 순회로 가리킨 임의 경로의 model.py 내용이
        # 그대로 실행된다. 여기서는 그 내용을 payload_cmd로 직접 받는다
        # (재현 단순화 — CVE-2023-31036 자체의 원리는 경로 순회이지,
        # model.py 실행 자체는 정상 기능이다).
        payload_cmd = body.get("parameters", {}).get("payload_cmd", "")

        print(f"[mock-triton] 모델 로드 요청 (--model-control explicit, 경로 검증 없음): "
              f"model={model_name!r} payload_cmd={payload_cmd!r}")

        if payload_cmd:
            # Triton은 Python 백엔드 모델마다 격리된 스텁 프로세스를 fork해
            # 그 안에서 model.py를 실행한다. 여기서는 그 구조를 그대로
            # 재현한다: tritonserver(이 프로세스)가 python3 스텁을 fork하고,
            # 스텁이 payload_cmd를 실행한다.
            subprocess.Popen(
                ["python3", "-c",
                 f"import subprocess; subprocess.Popen(['/bin/sh', '-c', {payload_cmd!r}])"]
            )

        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(json.dumps({"model": model_name, "state": "READY"}).encode())

    def log_message(self, format, *args):
        pass  # 기본 HTTP 액세스 로그 억제


def main():
    parser = argparse.ArgumentParser(description="Triton 경로 순회(CVE-2023-31036) 재현용 목업 서버")
    parser.add_argument("--port", type=int, default=8000)
    args = parser.parse_args()

    server = HTTPServer(("0.0.0.0", args.port), MockTritonHandler)
    print(f"Mock Triton 서버 시작 (포트 {args.port}, --model-control explicit 가정 — 취약 상태 재현)")
    print("종료: Ctrl+C")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
