# Security policy

`sec-recon-agent` is a portfolio / research project that handles
adversarial input by design (CVE descriptions, vendor service banners,
SBOMs, user queries). Vulnerability reports are taken seriously even
though the project is single-tenant and not currently deployed in
production.

## Supported versions

Only `main` is supported. The `0.1.x` development versions tagged in
the past do not receive backported fixes.

## Reporting a vulnerability

**Please do not open public GitHub issues for security findings.**

Send a private report to:

- Email: `slaporta94@gmail.com`
- Subject line: `[sec-recon-agent] <one-line summary>`

Include in the report:

- A concrete description of the issue, with affected file(s) and
  function(s) when known.
- A minimal proof of concept (HTTP request, payload, input file).
- Your assessment of impact and likelihood.
- Whether you would like to be credited (and how) in any subsequent
  public advisory or commit message.

You will receive an acknowledgement within **5 business days**. A
remediation timeline (or an explicit "won't fix" with reasoning) will
follow within **30 calendar days** of the initial report.

## Coordinated disclosure

The default disclosure window is **90 days** from initial report.
Critical findings affecting users running the project may be disclosed
earlier; reports of theoretical risk with no exploitable impact may be
disclosed later, by agreement.

Public disclosure happens via:

- A GitHub Security Advisory on this repository (when the issue is
  validated and the fix is merged).
- A `fix(security): ...` commit whose message names the issue and
  credits the reporter.

## In scope

Findings that are interesting to receive:

- Prompt-injection and jailbreak vectors that the existing red-team
  battery does not catch (see `src/sec_recon_agent/redteam/`).
- Data exfiltration via tool output (especially via spans / audit log).
- Authentication bypass when API key auth is enabled.
- Resource exhaustion that the existing caps fail to prevent
  (ExploitDB CSV cap, KEV catalog cap, EPSS payload cap, Nmap port cap,
  semantic-search query truncation, audit-log growth).
- Container escape, privilege escalation, or capability escape against
  the published `python:3.13-slim` + `node:22-alpine` images.
- Supply-chain risk in the project's declared dependencies (pinned in
  `uv.lock`, `frontend/package-lock.json`).
- Audit-trail integrity issues (hash chain bypass, append-only trigger
  bypass, signature replay).

## Out of scope

- Bugs in upstream LLM providers (Anthropic API behavior, Claude
  model outputs) that do not interact with this project's controls.
- Issues that require attacker presence inside the host filesystem or
  inside the container's user namespace (those are post-compromise
  scenarios; the project does not claim to defend against them).
- Findings derived from running the agent against a real LLM with no
  rate limit configured and observing token-cost amplification — this
  is a known limitation and `slowapi` rate limiting is on the roadmap.
- Reports that consist solely of a vulnerability scanner output with
  no triage. Please add context.

## Safe harbor

Good-faith research that respects this policy will not be pursued
under any contract or applicable law that the maintainer can waive.
Specifically:

- Do not access user data, including queries logged via
  `AUDIT_INCLUDE_QUERY`.
- Do not run automated attacks that degrade availability for other
  hypothetical users.
- Do not exfiltrate, retain, or share findings beyond what is required
  to demonstrate the issue.

Acting within these bounds, the maintainer commits not to take legal
action and will publicly thank you in the resulting advisory if
desired.
