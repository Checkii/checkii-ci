# checkii-ci

Fail-closed pull-request assessment client for the Checkii control plane.
Standard library only; Python 3.10 or later (tested on 3.12). Apache-2.0.

Released to PyPI from tags `checkii-ci-vX.Y.Z` of Checkii/aegis-platform by
`.github/workflows/publish-checkii-ci.yml` (Trusted Publishing, attested), and
mirrored with the GitHub Action to the public repository
[Checkii/checkii-ci](https://github.com/Checkii/checkii-ci). Pin the version;
the mirror's `requirements.txt` carries the release's sha256 digests for
`--require-hashes` installs.

```sh
python -m pip install --no-deps "checkii-ci==0.1.0"
checkii-ci version
```

Until the first release is published, install from a reviewed commit:

```sh
python -m pip install --no-deps "checkii-ci @ git+https://github.com/Checkii/aegis-platform@<40-hex commit>#subdirectory=packages/checkii-ci"
```

The API token is read from `CHECKII_API_TOKEN` (or the older `AEGIS_API_TOKEN`)
and is never accepted as a flag; a `--token` flag is refused before its value
can reach a log. The URL comes from `--api-url` or `CHECKII_API_URL`; it must be
HTTPS (plain HTTP only for loopback development) and redirects are refused.

## Commands

```sh
checkii-ci assess   --engagement-id 42 --scope-version-id 7 --asset-id 19 --provider GITHUB \
                    --head-ref refs/heads/feature --head-commit <40-hex> \
                    --base-ref refs/heads/main    --base-commit <40-hex> \
                    --fail-on high --sarif-out checkii-results.sarif --json-out checkii-summary.json \
                    [--receipt checkii-receipt.json] [--timeout 900] [--tool semgrep ...]
checkii-ci findings --job-id <id> [--format table|json] [--json-out findings.json]
checkii-ci version
```

`assess` issues one immutable base-to-head repository job under a per-run
`Idempotency-Key` (`--idempotency-key` or `CHECKII_CI_IDEMPOTENCY_KEY`), waits
for a terminal status, writes SARIF 2.1.0, optionally the sealed release
receipt, and a run summary (`checkii.ci-run-summary.v1`: job id, status, exit
code, finding counts). `findings` prints a job's findings highest severity
first as a fixed-column table or sorted JSON. Output is deterministic.

| Exit | Meaning |
|---|---|
| 0 | passed: no actionable finding at or above `--fail-on` |
| 1 | threshold: an actionable finding at or above `--fail-on` |
| 2 | error: configuration, network, timeout or control-plane failure |
| 3 | policy denied: HTTP 401/403, or the job ended `POLICY_DENIED` |
| 4 | cancelled, stopped or expired |

A network failure is exit 2, never a pass. Findings governed as false
positive, accepted risk, remediated or not reproducible do not count toward
the threshold but stay in the SARIF.

Pipeline templates, the reusable GitHub Action and the pre-commit hook are
documented in `docs/integrations/ci-integration.md` of the repository.

## Tests

```sh
python -m pytest tests/ -q
```

The tests run the CLI against a loopback `http.server` control plane.
