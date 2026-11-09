# checkii-ci

Fail-closed pull-request assessment client for the Checkii control plane, and
its reusable GitHub Action. Apache-2.0. This repository is a release mirror:
it is written by the release workflow of `Checkii/aegis-platform` and is not
edited by hand; changes are made there and arrive with the next release.

Release: `0.1.0`, built from aegis-platform commit `7b585e930aaa65193f5607e27136feb58ed10ab8`.

## GitHub Action

```yaml
- uses: Checkii/checkii-ci@<40-hex commit>   # pin by commit; tags are vX.Y.Z
  with:
    token: ${{ secrets.CHECKII_API_TOKEN }}
    engagement-id: ${{ vars.CHECKII_ENGAGEMENT_ID }}
    scope-version-id: ${{ vars.CHECKII_SCOPE_VERSION_ID }}
    asset-id: ${{ vars.CHECKII_ASSET_ID }}
    fail-on: high
```

The action installs the package from `package/` in its own checkout, with no
network access at install time; see `templates/github-actions.yml` for a
complete workflow.

## pip

```sh
python -m pip install --no-deps --require-hashes -r requirements.txt   # the recorded release
checkii-ci version
```

`requirements.txt` names this release and the sha256 digests of its sdist and
wheel as published to PyPI with attestations. Exit codes: 0 passed, 1
threshold reached, 2 error (including network failure), 3 policy denied, 4
cancelled or expired; only 0 is a pass.

## Also here

`templates/gitlab-ci.yml` (GitLab CI job), `.pre-commit-hooks.yaml`
(pre-push hook), `package/README.md` (the client's commands and flags),
`LICENSE` and `NOTICE`.
