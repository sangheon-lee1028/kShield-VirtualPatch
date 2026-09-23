#!/usr/bin/env python3
"""
mock_mlflow_server.py — CVE-2024-37054 등(MLflow pickle 역직렬화 RCE) 재현용 목업 서버

실제 MLflow는 모델 아티팩트(python_model.pkl)를 저장소에서 그대로 읽어
pickle/cloudpickle로 역직렬화한다. 이 아티팩트를 인증 없이(또는 취약한
경로 검증으로) 덮어쓸 수 있는 상태에서, 누군가(서비스 자신 포함) 그
모델을 mlflow.pyfunc.load_model()로 불러오는 순간 역직렬화 중 임의
코드가 실행된다.

ShadowRay/ShellTorch와 달리 **요청 한 번으로 끝나지 않는 2단계 공격**이다.
    1) 아티팩트 업로드: 악성 pickle을 모델 경로에 올려 둔다 (이 시점엔
       아무 일도 안 일어난다 — 그냥 데이터가 저장될 뿐)
    2) 모델 로드: 누군가 그 모델을 불러오는 순간, pickle 역직렬화 중
       공격자가 심어둔 코드가 실행된다

실제 cloudpickle 역직렬화 엔진은 구현하지 않고, "업로드된 모델을 로드할
때 저장해둔 페이로드가 실행된다"는 취약점의 핵심 동작만 재현한다
(mock_ray_server.py/mock_torchserve_server.py와 동일한 단순화 원칙).

이 스크립트를 이름을 바꾼 인터프리터로 실행해야 comm이 "mlflow"가 된다.
watched_parents 기본값에는 "mlflow"가 없으므로, kshield_ctl parent-add
mlflow로 런타임에 등록해야 탐지된다.

사용법:
    cp "$(which python3)" /tmp/mlflow
    /tmp/mlflow mock_mlflow_server.py [--port 5000]
"""
import argparse
import json
import subprocess
from http.server import BaseHTTPRequestHandler, HTTPServer

# 업로드된 모델 이름 -> 페이로드 명령어. 실제로는 pickle 바이트가 저장되지만,
# 여기서는 mock_ray_server.py의 entrypoint와 동일하게 명령어 문자열로 단순화한다.
_UPLOADED_MODELS = {}


class MockMLflowHandler(BaseHTTPRequestHandler):
    def _read_json(self):
        length = int(self.headers.get("Content-Length", 0))
        return json.loads(self.rfile.read(length)) if length else {}

    def do_POST(self):
        if self.path.startswith("/ajax-api/2.0/mlflow-artifacts/artifacts/"):
            self._handle_upload()
        elif self.path == "/invocations":
            self._handle_load()
        else:
            self.send_response(404)
            self.end_headers()

    def _handle_upload(self):
        # 실제로는 python_model.pkl 바이너리가 그대로 저장소에 쓰인다.
        # 이 시점에는 아무 코드도 실행되지 않는다 — 저장만 될 뿐이다.
        body = self._read_json()
        model_name = body.get("model_name", "malicious_model")
        payload_cmd = body.get("payload_cmd", "")
        _UPLOADED_MODELS[model_name] = payload_cmd

        print(f"[mock-mlflow] 아티팩트 업로드됨 (인증/경로 검증 없음): "
              f"model_name={model_name!r} — 아직 실행 안 됨, 로드 시점에 실행")

        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(json.dumps({"status": "uploaded"}).encode())

    def _handle_load(self):
        # mlflow.pyfunc.load_model()이 이 시점에 호출된다고 가정한다.
        # 실제 취약점은 여기서 cloudpickle.load()가 python_model.pkl을
        # 역직렬화하며, 그 안에 심어둔 코드가 이 프로세스 안에서 실행된다.
        body = self._read_json()
        model_name = body.get("model_name", "malicious_model")
        payload_cmd = _UPLOADED_MODELS.get(model_name, "")

        print(f"[mock-mlflow] 모델 로드(load_model) 호출됨: model_name={model_name!r} "
              f"— 역직렬화 중 페이로드 실행: {payload_cmd!r}")

        if payload_cmd:
            # 실제로는 언피클링 중 객체의 __reduce__가 os.system/subprocess를
            # 호출하는 방식으로, 로드를 수행하는 이 프로세스 안에서 바로
            # 실행된다(별도 워커로 넘어가지 않음) — 그래서 mlflow(이 프로세스)
            # 자신이 직접 fork하는 1단계 계보로 재현한다.
            subprocess.Popen(["/bin/sh", "-c", payload_cmd])

        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(json.dumps({"status": "loaded", "model_name": model_name}).encode())

    def log_message(self, format, *args):
        pass  # 기본 HTTP 액세스 로그 억제


def main():
    parser = argparse.ArgumentParser(description="MLflow pickle 역직렬화 RCE 재현용 목업 서버")
    parser.add_argument("--port", type=int, default=5000)
    args = parser.parse_args()

    server = HTTPServer(("0.0.0.0", args.port), MockMLflowHandler)
    print(f"Mock MLflow 서버 시작 (포트 {args.port}, 아티팩트 인증/역직렬화 검증 없음 — 취약 상태 재현)")
    print("종료: Ctrl+C")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
