"""A loopback HTTP control plane for the CLI tests.

The fake serves the four endpoints the client uses, records every request
(method, path, headers, body) and lets a test script the job's status
sequence, its findings, its receipt and HTTP failures. It listens on
127.0.0.1 over plain HTTP, which the client permits for loopback only.
"""

from __future__ import annotations

import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlsplit

TOKEN = "aegis_sk_test_0123456789abcdef_do_not_print"


class FakeControlPlane:
    def __init__(self):
        self.statuses: list[str] = ["QUEUED", "COMPLETED"]
        self.findings: list[dict] = []
        self.receipt: dict | None = None
        self.page_size = 200
        self.reject_status: int | None = None
        self.calls: list[dict] = []
        self.job_id = "job-7f3a"
        fake = self
        self.lock = threading.Lock()

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *_):
                return

            def _reply(self, status: int, body, headers: dict | None = None):
                raw = json.dumps(body).encode() if body is not None else b""
                self.send_response(status)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(raw)))
                for key, value in (headers or {}).items():
                    self.send_header(key, value)
                self.end_headers()
                self.wfile.write(raw)

            def _record(self):
                length = int(self.headers.get("Content-Length") or 0)
                body = self.rfile.read(length) if length else b""
                with fake.lock:
                    fake.calls.append(
                        {
                            "method": self.command,
                            "path": self.path,
                            "headers": dict(self.headers),
                            "body": json.loads(body) if body else None,
                        }
                    )

            def do_POST(self):
                self._record()
                if fake.reject_status:
                    return self._reply(fake.reject_status, {"detail": "refused"})
                if self.path == "/api/v1/pentest/repository-jobs":
                    return self._reply(
                        201, {"job_id": fake.job_id, "result_token": "never-written"}
                    )
                if "/analyses/" in self.path:
                    return self._reply(202, {"id": "delivery-1", "status": "PENDING"})
                return self._reply(404, {"detail": "unknown"})

            def do_GET(self):
                self._record()
                if fake.reject_status:
                    return self._reply(fake.reject_status, {"detail": "refused"})
                parts = urlsplit(self.path)
                if parts.path == f"/api/v1/pentest/jobs/{fake.job_id}/status":
                    with fake.lock:
                        status = (
                            fake.statuses.pop(0)
                            if len(fake.statuses) > 1
                            else fake.statuses[0]
                        )
                    return self._reply(200, {"status": status})
                if parts.path == "/api/v1/pentest/findings":
                    query = parse_qs(parts.query)
                    if query.get("job_id") != [fake.job_id]:
                        return self._reply(200, [])
                    start = int(query.get("cursor", ["0"])[0])
                    page = fake.findings[start : start + fake.page_size]
                    headers = {}
                    if start + fake.page_size < len(fake.findings):
                        headers["X-Next-Cursor"] = str(start + fake.page_size)
                    return self._reply(200, page, headers)
                if parts.path == f"/api/v1/pentest/jobs/{fake.job_id}/receipt":
                    if fake.receipt is None:
                        return self._reply(
                            409, {"detail": {"code": "RECEIPT_REQUIRES_FINISHED_JOB"}}
                        )
                    return self._reply(200, fake.receipt)
                return self._reply(404, {"detail": "unknown"})

        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.thread = threading.Thread(
            target=lambda: self.server.serve_forever(poll_interval=0.02), daemon=True
        )

    @property
    def url(self) -> str:
        host, port = self.server.server_address[:2]
        return f"http://{host}:{port}"

    def start(self):
        self.thread.start()
        return self

    def stop(self):
        self.server.shutdown()
        self.server.server_close()


def finding(identifier: int, severity: str, status: str = "VALIDATED", cwe="CWE-89"):
    return {
        "id": identifier,
        "fingerprint": f"{identifier:064x}",
        "title": f"Finding {identifier}",
        "severity": severity,
        "validation_status": status,
        "cwe": cwe,
        "location": f"src/file{identifier}.py",
    }


def receipt_document(job_id: str, outcome="COMPLETED_WITH_FINDINGS") -> dict:
    return {
        "receipt": {
            "schema": "checkii.release-receipt.v1",
            "subject": {"kind": "REPOSITORY_COMMIT", "commit": "a" * 40},
            "result": {"outcome": outcome, "findings_total": 1},
        },
        "seal": {
            "statement": {
                "schema": "checkii.release-receipt-seal.v1",
                "job_id": job_id,
                "outcome": outcome,
                "receipt_sha256": "c" * 64,
            },
            "signature_algorithm": "Ed25519",
            "signing_key_id": "hosted",
            "signing_public_key": "k",
            "signature": "s",
        },
    }
