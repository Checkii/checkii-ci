"""HTTPS client for the control plane: bearer token, no redirects, JSON only."""

from __future__ import annotations

import json
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass


class ApiFailure(RuntimeError):
    """An API call that did not return a usable answer.

    ``status`` is the HTTP status, or 0 when no HTTP answer arrived (network
    failure, timeout, malformed body). The message never carries the token.
    """

    def __init__(self, status: int, body: str):
        super().__init__(f"Checkii API returned HTTP {status}")
        self.status = status
        self.body = body


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


@dataclass
class ApiClient:
    base_url: str
    token: str
    timeout: float = 30.0

    def request(
        self,
        method: str,
        path: str,
        payload: dict | None = None,
        headers: dict[str, str] | None = None,
    ):
        body = (
            json.dumps(payload, separators=(",", ":")).encode()
            if payload is not None
            else None
        )
        request = urllib.request.Request(
            self.base_url.rstrip("/") + path,
            data=body,
            method=method,
            headers={
                "Authorization": f"Bearer {self.token}",
                "Accept": "application/json",
                **({"Content-Type": "application/json"} if body else {}),
                **(headers or {}),
            },
        )
        try:
            with urllib.request.build_opener(_NoRedirect).open(
                request, timeout=self.timeout
            ) as response:
                raw = response.read()
                return json.loads(raw) if raw else None, dict(response.headers)
        except urllib.error.HTTPError as exc:
            raise ApiFailure(
                exc.code, exc.read().decode("utf-8", "replace")[:4000]
            ) from exc
        except (urllib.error.URLError, TimeoutError, json.JSONDecodeError) as exc:
            raise ApiFailure(0, str(exc)) from exc


def fetch_findings(api: ApiClient, job_id: str) -> list[dict]:
    """Return every finding bound to ``job_id``, following the cursor."""
    values: list[dict] = []
    cursor = None
    while True:
        query = {"job_id": job_id, "limit": "200"}
        if cursor:
            query["cursor"] = cursor
        body, headers = api.request(
            "GET", "/api/v1/pentest/findings?" + urllib.parse.urlencode(query)
        )
        if not isinstance(body, list):
            raise ApiFailure(0, "invalid findings response")
        values.extend(body)
        cursor = headers.get("X-Next-Cursor") or headers.get("x-next-cursor")
        if not cursor:
            return values
