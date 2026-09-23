#!/usr/bin/env python3
"""
mock_torchserve_server.py — CVE-2023-43654(ShellTorch) 취약점 재현용 목업 서버

실제 TorchServe의 관리(Management) API(기본 포트 8081)는 기본 설정에서
0.0.0.0에 바인딩되어 외부에 노출되며, 인증 없이 원격 URL의 모델 아카이브
(.mar) 파일을 등록·로드할 수 있다. 이 .mar 파일 안의 커스텀 핸들러 코드가
로드 시점에 실행되어, 네트워크로 접근 가능한 누구나 임의 코드를 원격에서
실행시킬 수 있다.

실제 TorchServe(Java 프런트엔드 + Python 백엔드 워커)를 설치하지 않고도
이 핵심 취약점(인증 없는 원격 코드 실행)만 재현하기 위한 목업 서버다.
mock_ray_server.py와 동일한 원칙 — 실제 .mar 압축 해제·YAML 역직렬화
과정은 구현하지 않고, "인증 없는 모델 등록 요청이 핸들러 코드를 그대로
실행시킨다"는 취약점의 핵심 동작만 재현한다.

실제 TorchServe 아키텍처를 반영해 2단계로 재현한다:
  1) 이 서버 프로세스 자체가 (관리 API를 쥔) torchserve 프런트엔드 역할
  2) 모델 등록 시 Python 백엔드 워커 프로세스를 자식으로 fork하고,
     그 워커가 핸들러 코드(= 공격자가 지정한 명령)를 실행

이 2단계 계보(torchserve → python3 워커 → 공격 행위)는 ShadowRay의
(raylet → sh → curl) 계보와 구조적으로 유사하며, kShield-VirtualPatch의
탐지가 프레임워크·언어 런타임과 무관하게 일반화되는지 검증하기 위한
용도다. 이 스크립트를 python3 대신 이름을 바꾼 인터프리터로 실행해야
comm이 "torchserve"가 된다 — watched_parents 기본값에는 "torchserve"가
없으므로, kshield_ctl parent-add torchserve로 런타임에 등록해야
탐지된다(재컴파일 불필요, v10의 핵심 주장).

사용법:
    cp "$(which python3)" /tmp/torchserve
    /tmp/torchserve mock_torchserve_server.py [--port 8081]
"""
import argparse
import json
import subprocess
import urllib.parse
from http.server import BaseHTTPRequestHandler, HTTPServer


class MockTorchServeManagementHandler(BaseHTTPRequestHandler):
    def do_POST(self):
        if not self.path.startswith("/models"):
            self.send_response(404)
            self.end_headers()
            return

        parsed = urllib.parse.urlparse(self.path)
        params = urllib.parse.parse_qs(parsed.query)
        mar_url = params.get("url", [""])[0]
        model_name = params.get("model_name", ["mock_model"])[0]
        # 실제 취약점은 .mar 안의 핸들러 코드를 실행시키지만, 여기서는
        # mock_ray_server.py의 entrypoint와 동일한 방식으로 "핸들러가
        # 하려는 행위"를 handler_cmd 파라미터로 직접 받는다(재현 단순화).
        handler_cmd = params.get("handler_cmd", [""])[0]

        print(f"[mock-torchserve] 모델 등록됨 (인증 검사 없음): "
              f"name={model_name!r} url={mar_url!r} handler_cmd={handler_cmd!r}")

        if handler_cmd:
            # 실제 TorchServe는 등록된 모델을 초기화할 때 Java 프런트엔드가
            # Python 백엔드 워커 프로세스를 fork하고, 그 워커 안에서 핸들러
            # 코드(.mar에 포함된 커스텀 handler.py)가 실행된다. 여기서는
            # 그 두 단계를 그대로 재현한다: 이 서버(torchserve) 프로세스가
            # python3 워커를 fork하고, 워커가 handler_cmd를 실행한다.
            subprocess.Popen(
                ["python3", "-c",
                 f"import subprocess; subprocess.Popen(['/bin/sh', '-c', {handler_cmd!r}])"]
            )

        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(json.dumps({"status": f"Model {model_name!r} registered"}).encode())

    def log_message(self, format, *args):
        pass  # 기본 HTTP 액세스 로그 억제


def main():
    parser = argparse.ArgumentParser(description="ShellTorch(CVE-2023-43654) 취약점 재현용 목업 관리 API 서버")
    parser.add_argument("--port", type=int, default=8081)
    args = parser.parse_args()

    server = HTTPServer(("0.0.0.0", args.port), MockTorchServeManagementHandler)
    print(f"Mock TorchServe 관리 API 서버 시작 (포트 {args.port}, 인증 없음 — 취약 상태 재현)")
    print("종료: Ctrl+C")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
