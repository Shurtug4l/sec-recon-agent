# Contributing

Single-author portfolio repo, but the workflow is the one a team would use: PR-only, protected `main`, required checks. This file documents the local setup and the flow any change follows.

## Local setup

```bash
uv sync --extra dev                  # backend deps + dev tooling
uv run pre-commit install            # writes .git/hooks/pre-commit
cd frontend && npm install --legacy-peer-deps && cd ..
```

`pre-commit` runs `ruff --fix`, `ruff format`, a tightly-scoped `mypy --strict src/`, plus the standard `pre-commit-hooks` suite (trailing-whitespace, end-of-file-fixer, YAML / TOML / merge-conflict / oversized-file checks) on every `git commit`. To run it manually across the whole tree:

```bash
uv run pre-commit run --all-files
```

Frontend lint stays in CI only: the npm install footprint is heavier than what a local hook should impose, and the frontend ESLint + TypeScript pipeline is already enforced by the `type-check + build` required check on every PR.

## Branch protection

`main` is a protected branch on GitHub. The protection rules are:

- **Pull-request only**: no direct push to `main`. Every change lands through a PR.
- **Required status checks**: `lint + type-check + tests` (backend) and `type-check + build` (frontend) must be green before a PR can be merged. The audit trail tests, the SBOM contract tests, and the red-team scorer all run inside the backend job.
- **Branches up to date before merging**: enforces rebase against `main` before the merge button is clickable.
- **Linear history**: prevents merge commits. The history reads as a clean sequence of intentional commits, never a tree of fix-ups.
- **No force pushes, no deletions, no bypasses**: applies to admins as well. The rules describe how the project actually works, not how it would work if someone remembers to follow them.

## PR flow

```bash
git checkout -b <type>/<slug>       # feat/, fix/, chore/, docs/, ci/
# ...edits, lint, mypy, pytest locally...
git push -u origin <type>/<slug>
gh pr create --title "<type>(<scope>): <subject>"
gh pr checks <n> --watch            # wait for CI
gh pr merge <n> --rebase --delete-branch
```

Commit subjects follow Conventional Commits; the body explains *why*, not *what* (the diff already says *what*). Public commit history under `git log` on `main` is the canonical record.

## Before touching behavior-bearing text

The system prompt (`src/sec_recon_agent/agent/prompts.py`) and the MCP tool descriptions the LLM consumes are behavior-bearing: a wording change can shift tool-selection or output quality. Any edit there requires re-running `make eval` and `make redteam` before merge, and comparing against the current [SCORECARD.md](SCORECARD.md).

This rule is partly enforced by CI: the replay gate (`tests/replay/`) hashes the LLM-visible surface (system prompt, MCP tool schemas, `TriageReport` schema) and hard-fails when it no longer matches the hash stamped in the committed cassettes. A PR that touches behavior-bearing text must ship re-recorded cassettes (`make record-cassettes`, bills the LLM against a live stack; see [docs/evaluation.md](docs/evaluation.md#record-replay-gate)).
