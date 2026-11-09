"""Fetch a job's findings and print them as a fixed-column table or JSON."""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

from checkii_ci.assess import (
    EXIT_ERROR,
    EXIT_PASSED,
    SEVERITY,
    add_connection_arguments,
    exit_code_for,
    resolve_token,
    write_json,
)
from checkii_ci.client import ApiClient, ApiFailure, fetch_findings

COLUMNS = ("id", "severity", "validation_status", "location", "title")
JOB_ID = r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,199}$"


def add_findings_arguments(parser: argparse.ArgumentParser) -> None:
    add_connection_arguments(parser)
    parser.add_argument("--job-id", required=True, help="the assessment job id")
    parser.add_argument(
        "--format",
        choices=("table", "json"),
        default="table",
        help="print a fixed-column table (default) or sorted JSON",
    )
    parser.add_argument(
        "--json-out",
        dest="json_out",
        type=Path,
        help="also write the findings as JSON here",
    )


def ordered(findings: list[dict]) -> list[dict]:
    """Highest severity first, then by id; a stable order for diffs."""
    return sorted(
        findings,
        key=lambda item: (
            -SEVERITY.get(str(item.get("severity")), -1),
            str(item.get("id")),
        ),
    )


def table(findings: list[dict]) -> str:
    rows = [
        [
            str(item.get(column, "") if item.get(column) is not None else "")
            for column in COLUMNS
        ]
        for item in ordered(findings)
    ]
    widths = [
        max(len(column), *(len(row[index]) for row in rows)) if rows else len(column)
        for index, column in enumerate(COLUMNS)
    ]
    lines = [
        "  ".join(column.ljust(widths[index]) for index, column in enumerate(COLUMNS)),
        "  ".join("-" * width for width in widths),
    ]
    for row in rows:
        lines.append(
            "  ".join(cell.ljust(widths[index]) for index, cell in enumerate(row))
        )
    lines.append(f"{len(rows)} finding(s)")
    return "\n".join(line.rstrip() for line in lines)


def render(findings: list[dict], fmt: str) -> str:
    if fmt == "json":
        return json.dumps(ordered(findings), sort_keys=True, indent=2)
    return table(findings)


def run(args) -> int:
    if not re.fullmatch(JOB_ID, args.job_id):
        print("checkii-ci: the job id is not a valid identifier", file=sys.stderr)
        return EXIT_ERROR
    try:
        token = resolve_token(args)
        if not args.api_url:
            raise ValueError("the API URL (--api-url or CHECKII_API_URL) is required")
        findings = fetch_findings(ApiClient(args.api_url, token), args.job_id)
    except ValueError as exc:
        print(f"checkii-ci: {exc}", file=sys.stderr)
        return EXIT_ERROR
    except ApiFailure as exc:
        print(f"checkii-ci: {exc}", file=sys.stderr)
        return exit_code_for(exc)
    if args.json_out is not None:
        write_json(args.json_out, ordered(findings))
    print(render(findings, args.format))
    return EXIT_PASSED
