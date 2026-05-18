<!--
Thanks for the contribution. Keep the title in Conventional Commits
form: <type>(<scope>): <short summary>.
Types: feat, fix, chore, docs, refactor, test, ci, perf, build.
-->

## Summary

<!-- 1-3 bullets. What is changing and why. Not what file moved where. -->

-
-

## Test plan

<!-- Mark with [x] what you actually ran locally. Anything unchecked is
either out of scope or deferred to CI (note which). -->

- [ ] `uv run ruff check src tests`
- [ ] `uv run mypy src`
- [ ] `uv run pytest -m "not slow"`
- [ ] `npm run lint` + `npm run type-check` + `npm run build` (only if the PR touches `frontend/`)
- [ ] Manual smoke against a live stack (`make up && make triage Q="..."`)

## Security considerations

<!-- Required when the PR touches any of:
- src/sec_recon_agent/agent/prompts.py
- src/sec_recon_agent/audit/
- src/sec_recon_agent/mcp_server/security.py
- src/sec_recon_agent/mcp_server/tools/ (new tool or new external source)
- src/sec_recon_agent/redteam/
- .github/workflows/
- frontend dependencies (package-lock changes)
Skip the section with "N/A" otherwise. -->

-

## Related issues / docs

<!-- Closes #N, refs #M, link to the relevant docs/design.md decision
log entry, or "none" if the PR is self-contained. -->

-
