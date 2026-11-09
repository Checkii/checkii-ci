"""Argument parsing, exit codes, SARIF shape, token handling and findings output."""

from __future__ import annotations

import json
import socket
import subprocess
import sys
from pathlib import Path

import pytest

from checkii_ci import __version__, cli
from checkii_ci.assess import (
    EXIT_CANCELLED,
    EXIT_ERROR,
    EXIT_PASSED,
    EXIT_POLICY_DENIED,
    EXIT_THRESHOLD,
)
from fake_control_plane import TOKEN, finding, receipt_document

HEAD = "a" * 40
BASE = "b" * 40
PACKAGE_ROOT = Path(__file__).resolve().parents[1]


def assess_argv(url: str, tmp_path: Path, *extra: str) -> list[str]:
    return [
        "assess",
        "--api-url",
        url,
        "--engagement-id",
        "1",
        "--scope-version-id",
        "2",
        "--asset-id",
        "3",
        "--provider",
        "GITHUB",
        "--head-ref",
        "refs/heads/feature",
        "--head-commit",
        HEAD,
        "--base-ref",
        "refs/heads/main",
        "--base-commit",
        BASE,
        "--idempotency-key",
        "pipeline:12345678",
        "--poll-seconds",
        "0",
        "--sarif-out",
        str(tmp_path / "out" / "results.sarif"),
        *extra,
    ]


def test_version_prints_the_package_version(capsys):
    assert cli.main(["version"]) == 0
    assert capsys.readouterr().out == f"checkii-ci {__version__}\n"


def test_assess_help_lists_the_documented_flags(capsys):
    with pytest.raises(SystemExit) as exit_code:
        cli.main(["assess", "--help"])
    assert exit_code.value.code == 0
    text = capsys.readouterr().out
    for flag in ("--sarif-out", "--json-out", "--fail-on", "--timeout", "--receipt"):
        assert flag in text
    assert "--token" not in text
    assert "CHECKII_API_URL" in text


def test_python_dash_m_runs_the_same_entry_point():
    completed = subprocess.run(
        [sys.executable, "-m", "checkii_ci", "version"],
        cwd=PACKAGE_ROOT,
        capture_output=True,
        text=True,
        check=False,
    )
    assert completed.returncode == 0
    assert completed.stdout == f"checkii-ci {__version__}\n"


def test_assess_runs_the_job_writes_sarif_and_summary_and_fails_on_high(
    control_plane, token_env, tmp_path, capsys
):
    control_plane.findings = [
        finding(7, "high"),
        finding(8, "critical", status="ACCEPTED_RISK"),
        finding(9, "low", cwe=None),
    ]
    summary = tmp_path / "summary.json"
    code = cli.main(
        assess_argv(control_plane.url, tmp_path, "--json-out", str(summary))
    )
    assert code == EXIT_THRESHOLD
    issued = control_plane.calls[0]
    assert issued["method"] == "POST"
    assert issued["path"] == "/api/v1/pentest/repository-jobs"
    assert issued["headers"]["Authorization"] == f"Bearer {TOKEN}"
    assert issued["headers"]["Idempotency-Key"] == "pipeline:12345678"
    assert issued["body"]["expected_commit"] == HEAD
    assert issued["body"]["base_expected_commit"] == BASE
    assert issued["body"]["requested_tools"][0] == "safe-source"
    statuses = [c for c in control_plane.calls if c["path"].endswith("/status")]
    assert len(statuses) == 2  # QUEUED then COMPLETED
    sarif = json.loads((tmp_path / "out" / "results.sarif").read_text())
    assert sarif["version"] == "2.1.0"
    assert sarif["$schema"] == "https://json.schemastore.org/sarif-2.1.0.json"
    run = sarif["runs"][0]
    assert run["tool"]["driver"]["name"] == "Aegis"
    assert {rule["id"] for rule in run["tool"]["driver"]["rules"]} == {
        "CWE-89",
        f"{9:064x}"[:12],
    }
    assert [result["level"] for result in run["results"]] == ["error", "error", "note"]
    assert run["results"][0]["properties"] == {
        "aegisFindingId": 7,
        "validationStatus": "VALIDATED",
    }
    assert "never-written" not in (tmp_path / "out" / "results.sarif").read_text()
    written = json.loads(summary.read_text())
    assert written["schema"] == "checkii.ci-run-summary.v1"
    assert written["job_id"] == control_plane.job_id
    assert written["status"] == "COMPLETED"
    assert written["exit_code"] == EXIT_THRESHOLD
    assert written["findings_total"] == 3
    assert written["actionable_total"] == 2
    assert written["actionable_by_severity"] == {
        "info": 0,
        "low": 1,
        "medium": 0,
        "high": 1,
        "critical": 0,
    }
    assert written["receipt"] is None
    captured = capsys.readouterr()
    assert TOKEN not in captured.out + captured.err
    assert TOKEN not in summary.read_text()


def test_fail_on_threshold_and_non_actionable_findings(
    control_plane, token_env, tmp_path
):
    control_plane.findings = [
        finding(7, "high"),
        finding(8, "critical", "FALSE_POSITIVE"),
    ]
    assert (
        cli.main(assess_argv(control_plane.url, tmp_path, "--fail-on", "critical"))
        == EXIT_PASSED
    )
    assert (
        cli.main(assess_argv(control_plane.url, tmp_path, "--threshold", "medium"))
        == EXIT_THRESHOLD
    )


def test_findings_are_paged_through_the_cursor(control_plane, token_env, tmp_path):
    control_plane.page_size = 2
    control_plane.findings = [finding(index, "low") for index in range(5)]
    summary = tmp_path / "summary.json"
    assert (
        cli.main(assess_argv(control_plane.url, tmp_path, "--json-out", str(summary)))
        == EXIT_PASSED
    )
    pages = [c for c in control_plane.calls if "/findings?" in c["path"]]
    assert len(pages) == 3
    assert json.loads(summary.read_text())["findings_total"] == 5


@pytest.mark.parametrize(
    ("status", "expected"),
    [
        ("CANCELLED", EXIT_CANCELLED),
        ("EXPIRED", EXIT_CANCELLED),
        ("POLICY_DENIED", EXIT_POLICY_DENIED),
        ("FAILED", EXIT_ERROR),
    ],
)
def test_terminal_statuses_map_to_exit_codes_and_summary(
    control_plane, token_env, tmp_path, status, expected
):
    control_plane.statuses = [status]
    summary = tmp_path / "summary.json"
    code = cli.main(
        assess_argv(control_plane.url, tmp_path, "--json-out", str(summary))
    )
    assert code == expected
    document = json.loads(summary.read_text())
    assert document["status"] == status
    assert document["exit_code"] == expected
    assert document["findings_total"] is None
    assert not (tmp_path / "out" / "results.sarif").exists()


def test_receipt_is_written_whole_when_present(control_plane, token_env, tmp_path):
    control_plane.receipt = receipt_document(control_plane.job_id)
    control_plane.findings = [finding(7, "high")]
    receipt = tmp_path / "receipt" / "receipt.json"
    summary = tmp_path / "summary.json"
    code = cli.main(
        assess_argv(
            control_plane.url,
            tmp_path,
            "--receipt",
            str(receipt),
            "--json-out",
            str(summary),
        )
    )
    assert code == EXIT_THRESHOLD
    assert json.loads(receipt.read_text()) == receipt_document(control_plane.job_id)
    assert json.loads(summary.read_text())["receipt"] == str(receipt)


def test_authorisation_failure_is_policy_denied(
    control_plane, token_env, tmp_path, capsys
):
    control_plane.reject_status = 403
    assert cli.main(assess_argv(control_plane.url, tmp_path)) == EXIT_POLICY_DENIED
    err = capsys.readouterr().err
    assert "HTTP 403" in err
    assert "refused" not in err  # bodies are never echoed
    assert TOKEN not in err


def test_network_failure_is_an_error_never_a_pass(token_env, tmp_path, capsys):
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        closed_port = probe.getsockname()[1]
    summary = tmp_path / "summary.json"
    code = cli.main(
        assess_argv(
            f"http://127.0.0.1:{closed_port}", tmp_path, "--json-out", str(summary)
        )
    )
    assert code == EXIT_ERROR
    assert json.loads(summary.read_text())["exit_code"] == EXIT_ERROR
    assert "HTTP 0" in capsys.readouterr().err


def test_token_comes_from_the_environment_only(
    control_plane, tmp_path, monkeypatch, capsys
):
    monkeypatch.delenv("CHECKII_API_TOKEN", raising=False)
    monkeypatch.delenv("AEGIS_API_TOKEN", raising=False)
    assert cli.main(assess_argv(control_plane.url, tmp_path)) == EXIT_ERROR
    assert "CHECKII_API_TOKEN" in capsys.readouterr().err
    assert control_plane.calls == []
    # A flag is refused before argparse can echo its value.
    secret = "aegis_sk_flagged_value"
    for spelling in (
        ["--token", secret],
        [f"--token={secret}"],
        ["--api-token", secret],
    ):
        assert (
            cli.main([*assess_argv(control_plane.url, tmp_path), *spelling])
            == EXIT_ERROR
        )
        captured = capsys.readouterr()
        assert secret not in captured.out + captured.err
        assert "never accepted" in captured.err
    assert control_plane.calls == []
    # The historical variable name still works.
    monkeypatch.setenv("AEGIS_API_TOKEN", TOKEN)
    assert cli.main(assess_argv(control_plane.url, tmp_path)) == EXIT_PASSED
    assert control_plane.calls[0]["headers"]["Authorization"] == f"Bearer {TOKEN}"


def test_configuration_errors_fail_closed(control_plane, token_env, tmp_path, capsys):
    bad = assess_argv(control_plane.url, tmp_path)
    bad[bad.index(HEAD)] = "main"
    assert cli.main(bad) == EXIT_ERROR
    assert "immutable" in capsys.readouterr().err
    remote_http = assess_argv("http://control-plane.example", tmp_path)
    assert cli.main(remote_http) == EXIT_ERROR
    assert "HTTPS" in capsys.readouterr().err
    assert control_plane.calls == []


def test_findings_table_is_fixed_column_and_ordered(control_plane, token_env, capsys):
    control_plane.findings = [
        finding(2, "low"),
        finding(1, "critical"),
        finding(3, "high", "ACCEPTED_RISK"),
    ]
    assert (
        cli.main(
            [
                "findings",
                "--api-url",
                control_plane.url,
                "--job-id",
                control_plane.job_id,
            ]
        )
        == 0
    )
    lines = capsys.readouterr().out.splitlines()
    assert lines[0].split() == [
        "id",
        "severity",
        "validation_status",
        "location",
        "title",
    ]
    assert set(lines[1]) == {"-", " "}
    assert [line.split()[0] for line in lines[2:5]] == ["1", "3", "2"]
    assert lines[2].split()[1:3] == ["critical", "VALIDATED"]
    assert lines[-1] == "3 finding(s)"
    assert TOKEN not in "\n".join(lines)


def test_findings_json_is_sorted_and_written(
    control_plane, token_env, tmp_path, capsys
):
    control_plane.findings = [finding(2, "low"), finding(1, "critical")]
    out = tmp_path / "findings.json"
    code = cli.main(
        [
            "findings",
            "--api-url",
            control_plane.url,
            "--job-id",
            control_plane.job_id,
            "--format",
            "json",
            "--json-out",
            str(out),
        ]
    )
    assert code == 0
    printed = json.loads(capsys.readouterr().out)
    assert [item["id"] for item in printed] == [1, 2]
    assert json.loads(out.read_text()) == printed
    assert control_plane.calls[0]["path"].startswith(
        f"/api/v1/pentest/findings?job_id={control_plane.job_id}&limit=200"
    )


def test_findings_rejects_a_malformed_job_id_and_maps_api_failures(
    control_plane, token_env, capsys
):
    assert (
        cli.main(["findings", "--api-url", control_plane.url, "--job-id", "../x"])
        == EXIT_ERROR
    )
    assert control_plane.calls == []
    control_plane.reject_status = 401
    assert (
        cli.main(["findings", "--api-url", control_plane.url, "--job-id", "job-1"])
        == EXIT_POLICY_DENIED
    )
    assert TOKEN not in capsys.readouterr().err


def test_pre_push_hook_derives_the_range_from_pre_commit_variables(
    control_plane, tmp_path
):
    control_plane.findings = [finding(7, "high")]
    env = {
        "PATH": "/usr/bin:/bin",
        "CHECKII_API_TOKEN": TOKEN,
        "CHECKII_API_URL": control_plane.url,
        "PRE_COMMIT_FROM_REF": BASE,
        "PRE_COMMIT_TO_REF": HEAD,
        "PRE_COMMIT_LOCAL_BRANCH": "refs/heads/feature",
        "PRE_COMMIT_REMOTE_BRANCH": "refs/heads/main",
    }
    completed = subprocess.run(
        [
            sys.executable,
            str(PACKAGE_ROOT / "bin" / "checkii-ci-pre-push"),
            "--engagement-id",
            "1",
            "--scope-version-id",
            "2",
            "--asset-id",
            "3",
            "--provider",
            "GITHUB",
            "--fail-on",
            "critical",
            "--sarif-out",
            str(tmp_path / "hook.sarif"),
        ],
        cwd=tmp_path,
        env=env,
        capture_output=True,
        text=True,
        check=False,
    )
    assert completed.returncode == EXIT_PASSED, completed.stderr
    issued = control_plane.calls[0]["body"]
    assert issued["expected_commit"] == HEAD
    assert issued["base_expected_commit"] == BASE
    assert issued["ref"] == "refs/heads/feature"
    assert issued["base_ref"] == "refs/heads/main"
    assert control_plane.calls[0]["headers"]["Idempotency-Key"] == (
        f"pre-push:{BASE[:12]}:{HEAD[:12]}"
    )
    assert (tmp_path / "hook.sarif").exists()
    assert TOKEN not in completed.stdout + completed.stderr
    # Without a range and without git reachable, the hook refuses rather than passes.
    refused = subprocess.run(
        [sys.executable, str(PACKAGE_ROOT / "bin" / "checkii-ci-pre-push")],
        cwd=tmp_path,
        env={"PATH": str(tmp_path), "CHECKII_API_TOKEN": TOKEN},
        capture_output=True,
        text=True,
        check=False,
    )
    assert refused.returncode == EXIT_ERROR
    assert "cannot determine the pushed range" in refused.stderr


def test_outputs_never_follow_a_planted_symlink(control_plane, token_env, tmp_path):
    control_plane.findings = [finding(7, "high")]
    outside = tmp_path / "outside" / "victim.txt"
    outside.parent.mkdir()
    outside.write_text("precious")
    checkout = tmp_path / "checkout"
    checkout.mkdir()
    # The destination itself is a link out of the checkout.
    (checkout / "results.sarif").symlink_to(outside)
    argv = assess_argv(control_plane.url, tmp_path)
    argv[argv.index("--sarif-out") + 1] = str(checkout / "results.sarif")
    assert cli.main(argv) == EXIT_ERROR
    assert control_plane.calls == []  # refused before any job is issued
    assert outside.read_text() == "precious"
    # The destination's parent is a link out of the checkout.
    (checkout / "out").symlink_to(outside.parent, target_is_directory=True)
    argv[argv.index("--sarif-out") + 1] = str(checkout / "out" / "results.sarif")
    assert cli.main(argv) == EXIT_ERROR
    assert control_plane.calls == []
    assert sorted(p.name for p in outside.parent.iterdir()) == ["victim.txt"]
    # A summary path that is a link is refused too, and the verdict is not a pass.
    (checkout / "summary.json").symlink_to(outside)
    argv[argv.index("--sarif-out") + 1] = str(checkout / "real.sarif")
    assert cli.main([*argv, "--json-out", str(checkout / "summary.json")]) == EXIT_ERROR
    assert outside.read_text() == "precious"
    assert control_plane.calls == []
    # A predictable ".tmp" name planted as a link is never used: the writer
    # creates a unique O_EXCL temporary and replaces the directory entry.
    planted = checkout / "real.sarif.tmp"
    planted.symlink_to(outside)
    assert cli.main(argv) == EXIT_THRESHOLD
    assert outside.read_text() == "precious"
    assert planted.is_symlink()
    assert json.loads((checkout / "real.sarif").read_text())["version"] == "2.1.0"
    assert not [p for p in checkout.iterdir() if p.name.startswith(".real.sarif.")]


def test_secret_flags_are_refused_in_every_spelling_and_errors_withhold_values(
    control_plane, token_env, tmp_path, capsys
):
    secret = "aegis_sk_misplaced_value_9f8e7d"
    base = assess_argv(control_plane.url, tmp_path)
    for spelling in (
        [f"-token={secret}"],
        ["-token", secret],
        [f"--api-key={secret}"],
        ["--client-secret", secret],
        ["--password", secret],
        ["-Key", secret],
    ):
        assert cli.main([*base, *spelling]) == EXIT_ERROR, spelling
        captured = capsys.readouterr()
        assert secret not in captured.out + captured.err, spelling
        assert "never accepted" in captured.err
    assert control_plane.calls == []
    # --idempotency-key is a legitimate flag and keeps working.
    assert cli.main(base) == EXIT_PASSED
    # An unknown flag that is not secret-looking still never has its value echoed.
    with pytest.raises(SystemExit) as unknown:
        cli.main([*base, f"--bogus={secret}", secret])
    assert unknown.value.code == 2
    err = capsys.readouterr().err
    assert secret not in err
    assert "unrecognized arguments (values withheld): --bogus" in err
    with pytest.raises(SystemExit):
        cli.main([*base, "--fail-on", secret])
    err = capsys.readouterr().err
    assert secret not in err
    assert "invalid choice: <value>" in err
