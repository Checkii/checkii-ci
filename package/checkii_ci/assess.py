"""Immutable base-to-head repository assessment with fail-closed exit codes.

Exit codes are stable and part of the contract:

    0  passed: no actionable finding at or above the threshold
    1  threshold: at least one actionable finding at or above the threshold
    2  error: configuration, network, timeout or control-plane failure
    3  policy denied: authorisation or scope refused (HTTP 401/403, or the job
       ended POLICY_DENIED)
    4  cancelled: the job was cancelled, stopped or expired

Anything that is not a confirmed pass is non-zero. A network failure is an
error, never a pass.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import sys
import tempfile
import time
import urllib.parse
from pathlib import Path
from typing import Callable

from checkii_ci.client import ApiClient, ApiFailure, fetch_findings

EXIT_PASSED = 0
EXIT_THRESHOLD = 1
EXIT_ERROR = 2
EXIT_POLICY_DENIED = 3
EXIT_CANCELLED = 4
TERMINAL = {"COMPLETED", "CANCELLED", "STOPPED", "FAILED", "EXPIRED", "POLICY_DENIED"}
SEVERITY = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
SHA = re.compile(r"^[0-9a-f]{40}$")
IDEMPOTENCY = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{7,199}$")
DEFAULT_TOOLS = ["safe-source", "component-inventory", "semgrep", "trivy", "gitleaks"]
NON_ACTIONABLE = {"FALSE_POSITIVE", "ACCEPTED_RISK", "REMEDIATED", "NOT_REPRODUCIBLE"}

# The token is read from the environment only. The first name wins.
TOKEN_VARIABLES = ("CHECKII_API_TOKEN", "AEGIS_API_TOKEN")
URL_VARIABLES = ("CHECKII_API_URL", "AEGIS_API_URL")
IDEMPOTENCY_VARIABLES = ("CHECKII_CI_IDEMPOTENCY_KEY", "AEGIS_CI_IDEMPOTENCY_KEY")


def environment(names: tuple[str, ...]) -> str | None:
    for name in names:
        value = os.getenv(name)
        if value:
            return value
    return None


def add_connection_arguments(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--api-url",
        default=environment(URL_VARIABLES),
        help="control-plane URL (HTTPS); default CHECKII_API_URL or AEGIS_API_URL",
    )
    parser.add_argument(
        "--timeout",
        "--timeout-seconds",
        dest="timeout_seconds",
        type=float,
        default=900.0,
        help="seconds to wait for the whole assessment (default 900)",
    )


def add_assess_arguments(parser: argparse.ArgumentParser) -> None:
    """Register the ``assess`` arguments on ``parser``.

    The historical flag spellings (``--threshold``, ``--sarif``,
    ``--timeout-seconds``) stay as aliases so existing pipelines run unchanged.
    """
    add_connection_arguments(parser)
    parser.add_argument("--engagement-id", type=int, required=True)
    parser.add_argument("--scope-version-id", type=int, required=True)
    parser.add_argument("--asset-id", type=int, required=True)
    parser.add_argument(
        "--provider", choices=("GITHUB", "GITLAB", "BITBUCKET"), required=True
    )
    parser.add_argument("--head-ref", required=True)
    parser.add_argument("--head-commit", required=True)
    parser.add_argument("--base-ref", required=True)
    parser.add_argument("--base-commit", required=True)
    parser.add_argument(
        "--tool",
        action="append",
        dest="tools",
        help="tool to request; repeatable; default " + " ".join(DEFAULT_TOOLS),
    )
    parser.add_argument("--worker-pool-id")
    parser.add_argument("--credential-reference-id")
    parser.add_argument(
        "--integration-connection-id",
        type=int,
        help="enqueue native provider analysis publication after completion",
    )
    parser.add_argument(
        "--fail-on",
        "--threshold",
        dest="threshold",
        choices=tuple(SEVERITY),
        default="high",
        help="lowest severity that fails the run with exit code 1 (default high)",
    )
    parser.add_argument(
        "--idempotency-key",
        default=environment(IDEMPOTENCY_VARIABLES),
        help="unique per CI run; default CHECKII_CI_IDEMPOTENCY_KEY",
    )
    parser.add_argument(
        "--sarif-out",
        "--sarif",
        dest="sarif",
        type=Path,
        default=Path("checkii-results.sarif"),
        help="where to write SARIF 2.1.0 (default checkii-results.sarif)",
    )
    parser.add_argument(
        "--json-out",
        dest="json_out",
        type=Path,
        help="write a machine-readable run summary (job id, status, counts) here",
    )
    parser.add_argument(
        "--annotations",
        type=Path,
        help="write a flat JSON list of finding annotations here",
    )
    parser.add_argument(
        "--receipt",
        type=Path,
        help="write the job's sealed release receipt (receipt and seal) here",
    )
    parser.add_argument("--poll-seconds", type=float, default=2.0)


def parser() -> argparse.ArgumentParser:
    """A stand-alone ``assess`` parser (the pre-package single-command form)."""
    instance = argparse.ArgumentParser(
        prog="checkii-ci assess",
        description="Run an immutable base-to-head repository assessment through Checkii",
    )
    add_assess_arguments(instance)
    return instance


def resolve_token(args) -> str:
    """Read the token from the environment; a flag is never accepted."""
    token = environment(TOKEN_VARIABLES)
    if not token:
        raise ValueError(
            "CHECKII_API_TOKEN (or AEGIS_API_TOKEN) must be set in the environment"
        )
    return token


def validate(args) -> None:
    if not args.api_url or not getattr(args, "token", None):
        raise ValueError(
            "the API URL (--api-url or CHECKII_API_URL) and CHECKII_API_TOKEN are required"
        )
    endpoint = urllib.parse.urlsplit(args.api_url)
    loopback = endpoint.scheme == "http" and endpoint.hostname in {
        "localhost",
        "127.0.0.1",
        "::1",
    }
    if (endpoint.scheme != "https" and not loopback) or not endpoint.hostname:
        raise ValueError(
            "the API URL must use HTTPS (HTTP is allowed only for loopback development)"
        )
    if not SHA.fullmatch(args.head_commit) or not SHA.fullmatch(args.base_commit):
        raise ValueError(
            "head and base commits must be immutable lowercase 40-character SHA-1 values"
        )
    if args.head_commit == args.base_commit:
        raise ValueError("head and base commits must differ")
    if not args.idempotency_key or not IDEMPOTENCY.fullmatch(args.idempotency_key):
        raise ValueError("a valid unique CI-run idempotency key is required")
    if args.poll_seconds < 0 or args.timeout_seconds <= 0:
        raise ValueError("poll and timeout values are outside bounds")
    if (
        args.integration_connection_id is not None
        and args.integration_connection_id <= 0
    ):
        raise ValueError("integration connection id must be positive")


def sarif(findings: list[dict]) -> dict:
    rules: dict[str, dict] = {}
    results = []
    for finding in findings:
        rule = finding.get("cwe") or finding["fingerprint"][:12]
        rules.setdefault(
            rule, {"id": rule, "shortDescription": {"text": finding["title"]}}
        )
        results.append(
            {
                "ruleId": rule,
                "level": {
                    "critical": "error",
                    "high": "error",
                    "medium": "warning",
                    "low": "note",
                    "info": "note",
                }.get(finding["severity"], "warning"),
                "message": {"text": finding["title"]},
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {"uri": finding["location"]}
                        }
                    }
                ],
                "properties": {
                    "aegisFindingId": finding["id"],
                    "validationStatus": finding["validation_status"],
                },
            }
        )
    return {
        "version": "2.1.0",
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "runs": [
            {
                "tool": {"driver": {"name": "Aegis", "rules": list(rules.values())}},
                "results": results,
            }
        ],
    }


def refuse_symlink(path: Path) -> None:
    """Refuse an output path that is, or whose parent is, a symbolic link.

    A link planted in an untrusted checkout must never redirect a write
    outside it. ``is_symlink`` uses ``lstat`` and never follows the link.
    """
    for candidate in (path, path.parent):
        if candidate.is_symlink():
            raise ValueError(
                f"refusing to write through a symbolic link: {candidate} "
                "(the output path and its parent must be real paths)"
            )


def check_outputs(args) -> None:
    for name in ("sarif", "json_out", "annotations", "receipt"):
        path = getattr(args, name, None)
        if path is not None:
            refuse_symlink(Path(path))


def write_json(path: Path, value) -> None:
    """Write ``value`` atomically: unique O_EXCL temp file, fsync, rename.

    The temporary file is created by ``tempfile`` next to the destination,
    so no predictable ``.tmp`` name can be pre-planted, and the final
    ``os.replace`` swaps the directory entry rather than following anything.
    """
    refuse_symlink(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    refuse_symlink(path)
    handle = tempfile.NamedTemporaryFile(
        "w", dir=path.parent, prefix=f".{path.name}.", suffix=".tmp", delete=False
    )
    try:
        with handle:
            handle.write(
                json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n"
            )
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(handle.name, path)
    except BaseException:
        try:
            os.unlink(handle.name)
        except OSError:
            pass
        raise


def receipt(api: ApiClient, job_id: str, path: Path) -> bool:
    """Fetch the sealed release receipt for a finished job and write it whole.

    A job the control plane will not receipt (still running, or a status it
    does not receipt) is reported, not invented; nothing is written then.
    """
    try:
        body, _ = api.request("GET", f"/api/v1/pentest/jobs/{job_id}/receipt")
    except ApiFailure as exc:
        if exc.status == 409:
            print(
                f"checkii-ci: no receipt yet for job {job_id} (control plane returned 409)",
                file=sys.stderr,
            )
            return False
        raise
    if (
        not isinstance(body, dict)
        or not isinstance(body.get("receipt"), dict)
        or not isinstance(body.get("seal"), dict)
        or body["receipt"].get("schema") != "checkii.release-receipt.v1"
        or body["seal"].get("statement", {}).get("job_id") != job_id
    ):
        raise ApiFailure(0, "invalid receipt response")
    write_json(path, body)
    return True


def actionable(findings: list[dict]) -> list[dict]:
    return [
        item for item in findings if item.get("validation_status") not in NON_ACTIONABLE
    ]


def severity_counts(findings: list[dict]) -> dict[str, int]:
    counts = {name: 0 for name in SEVERITY}
    for item in findings:
        name = item.get("severity")
        if name in counts:
            counts[name] += 1
    return counts


def summary(
    args,
    *,
    job_id: str | None,
    status: str | None,
    exit_code: int,
    findings: list[dict] | None = None,
    receipt_written: bool = False,
) -> dict:
    """The deterministic run summary ``--json-out`` writes."""
    document: dict = {
        "schema": "checkii.ci-run-summary.v1",
        "job_id": job_id,
        "status": status,
        "exit_code": exit_code,
        "threshold": args.threshold,
        "head_commit": args.head_commit,
        "base_commit": args.base_commit,
        "sarif": str(args.sarif) if findings is not None else None,
        "receipt": str(args.receipt) if receipt_written and args.receipt else None,
        "findings_total": None,
        "actionable_total": None,
        "actionable_by_severity": None,
    }
    if findings is not None:
        acted = actionable(findings)
        document["findings_total"] = len(findings)
        document["actionable_total"] = len(acted)
        document["actionable_by_severity"] = severity_counts(acted)
    return document


def _finish(args, document: dict) -> int:
    json_out = getattr(args, "json_out", None)
    if json_out is not None:
        try:
            write_json(json_out, document)
        except ValueError as exc:
            # Refusing the summary path must not turn a verdict into a pass.
            print(f"checkii-ci: {exc}", file=sys.stderr)
            return EXIT_ERROR
    return document["exit_code"]


def execute(
    args,
    api: ApiClient,
    *,
    clock: Callable[[], float] = time.monotonic,
    sleeper: Callable[[float], None] = time.sleep,
) -> int:
    payload = {
        "engagement_id": args.engagement_id,
        "scope_version_id": args.scope_version_id,
        "asset_id": args.asset_id,
        "provider": args.provider,
        "ref": args.head_ref,
        "expected_commit": args.head_commit,
        "base_ref": args.base_ref,
        "base_expected_commit": args.base_commit,
        "requested_tools": args.tools or list(DEFAULT_TOOLS),
        "credential_reference_id": args.credential_reference_id,
        "worker_pool_id": args.worker_pool_id,
    }
    issued, _ = api.request(
        "POST",
        "/api/v1/pentest/repository-jobs",
        payload,
        {"Idempotency-Key": args.idempotency_key},
    )
    job_id = issued.get("job_id") if isinstance(issued, dict) else None
    if not isinstance(job_id, str):
        raise ApiFailure(0, "invalid job issuance response")
    deadline = clock() + args.timeout_seconds
    while True:
        state, _ = api.request("GET", f"/api/v1/pentest/jobs/{job_id}/status")
        status = state.get("status") if isinstance(state, dict) else None
        if status in TERMINAL:
            break
        if not isinstance(status, str):
            raise ApiFailure(0, "invalid job status response")
        if clock() >= deadline:
            raise ApiFailure(0, "assessment timed out")
        sleeper(args.poll_seconds)
    receipt_path = getattr(args, "receipt", None)
    receipt_written = False
    if receipt_path is not None:
        # A failed or cancelled job still gets a receipt that says so.
        receipt_written = receipt(api, job_id, receipt_path)
    outcome = dict(job_id=job_id, status=status, receipt_written=receipt_written)
    if status in {"CANCELLED", "STOPPED", "EXPIRED"}:
        return _finish(args, summary(args, exit_code=EXIT_CANCELLED, **outcome))
    if status == "POLICY_DENIED":
        return _finish(args, summary(args, exit_code=EXIT_POLICY_DENIED, **outcome))
    if status != "COMPLETED":
        return _finish(args, summary(args, exit_code=EXIT_ERROR, **outcome))
    findings = fetch_findings(api, job_id)
    write_json(args.sarif, sarif(findings))
    if args.annotations is not None:
        write_json(
            args.annotations,
            [
                {
                    "path": item["location"],
                    "title": item["title"],
                    "severity": item["severity"],
                    "finding_id": item["id"],
                }
                for item in findings
            ],
        )
    acted = actionable(findings)
    if args.integration_connection_id is not None:
        publication_key = (
            "ci-analysis:"
            + hashlib.sha256(
                f"{args.idempotency_key}|{job_id}|{args.integration_connection_id}|{args.threshold}".encode()
            ).hexdigest()
        )
        api.request(
            "POST",
            f"/api/v1/integrations/connections/"
            f"{args.integration_connection_id}/analyses/{job_id}",
            {"threshold": args.threshold},
            {"Idempotency-Key": publication_key},
        )
    exit_code = (
        EXIT_THRESHOLD
        if any(
            SEVERITY.get(item.get("severity"), -1) >= SEVERITY[args.threshold]
            for item in acted
        )
        else EXIT_PASSED
    )
    return _finish(
        args, summary(args, exit_code=exit_code, findings=findings, **outcome)
    )


def exit_code_for(exc: ApiFailure) -> int:
    # 401/403 are authorisation failures. API bodies are never printed: they
    # may carry policy detail.
    return EXIT_POLICY_DENIED if exc.status in {401, 403} else EXIT_ERROR


def run(args) -> int:
    """Validate ``args``, run the assessment and map failures to exit codes."""
    try:
        args.token = resolve_token(args)
        validate(args)
        check_outputs(args)
        return execute(args, ApiClient(args.api_url, args.token))
    except ValueError as exc:
        print(f"checkii-ci: {exc}", file=sys.stderr)
        return _finish(args, _failure_summary(args, EXIT_ERROR))
    except ApiFailure as exc:
        print(f"checkii-ci: {exc}", file=sys.stderr)
        return _finish(args, _failure_summary(args, exit_code_for(exc)))


def _failure_summary(args, exit_code: int) -> dict:
    return summary(args, job_id=None, status=None, exit_code=exit_code)
