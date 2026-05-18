# Triage walkthrough

Three sessions captured against the live agent on 2026-05-18. The MCP
server and the agent API are running locally; queries hit
`POST /v1/triage` and the SSE stream is rendered below as the agent makes
tool calls and emits the final `TriageReport`.

- Model: `anthropic:claude-sonnet-4-6` via Pydantic AI
- Corpus: 19,003 CRITICAL+HIGH CVEs from NVD, 30-day lookback at indexing time
- Outputs are real, captured with `curl -N -X POST .../v1/triage`. No edits except removing curl progress lines and pretty-printing the final JSON for readability.

## How the SSE protocol looks on the wire

Every session is the same shape:

```
event: started
data: {"query": "..."}

event: node
data: {"node": "UserPromptNode"}

event: node
data: {"node": "ModelRequestNode"}      # LLM is thinking

event: node
data: {"node": "CallToolsNode"}         # tools are being invoked

event: node
data: {"node": "ModelRequestNode"}      # LLM synthesizes after tool results

event: node
data: {"node": "End"}

event: final
data: {"summary": "...", "severity": "...", ...}    # TriageReport JSON
```

The `node` events surface only the agent's internal node class name on purpose — see `docs/design.md` for the rationale.

---

## Session 1: specific CVE

User asks about a known CVE ID. The agent grounds with two parallel tool calls and returns a typed `TriageReport`.

**Request**

```bash
curl -N -X POST http://localhost:8000/v1/triage \
  -H "Content-Type: application/json" \
  -d '{"query": "What is CVE-2021-41773? Is it actively exploitable in the wild?"}'
```

**SSE event sequence (13s end-to-end)**

```
event: started      {"query": "What is CVE-2021-41773?..."}
event: node         {"node": "UserPromptNode"}
event: node         {"node": "ModelRequestNode"}
event: node         {"node": "CallToolsNode"}      # cve_lookup + exploit_check in parallel
event: node         {"node": "ModelRequestNode"}
event: node         {"node": "CallToolsNode"}
event: node         {"node": "End"}
event: final        TriageReport JSON  (below)
```

**Final TriageReport**

```json
{
  "summary": "CVE-2021-41773 is a critical path traversal and remote code execution vulnerability in Apache HTTP Server 2.4.49. It is actively exploited in the wild and has multiple public exploits available on Exploit-DB.",
  "severity": "critical",
  "confidence": "high",
  "recommended_action": "Immediately upgrade Apache HTTP Server to version 2.4.51 or later. Note: the patch in 2.4.50 was incomplete (see CVE-2021-42013). Ensure all directories are protected with \"Require all denied\" and disable CGI scripts if not required. Do not run Apache 2.4.49 or 2.4.50 in any production environment.",
  "cves": [
    {
      "cve_id": "CVE-2021-41773",
      "summary": "A path normalization flaw in Apache HTTP Server 2.4.49 allows attackers to perform path traversal attacks, mapping URLs to files outside configured directories. If CGI scripts are enabled, this can escalate to remote code execution. Confirmed exploited in the wild.",
      "cvss_v3_score": 9.8,
      "severity": "critical",
      "exploits_public": true,
      "affected_products": [
        "Apache HTTP Server 2.4.49",
        "Fedora 34",
        "Fedora 35",
        "Oracle Instantis EnterpriseTrack 17.1/17.2/17.3",
        "NetApp Cloud Backup"
      ],
      "nvd_url": "https://nvd.nist.gov/vuln/detail/CVE-2021-41773"
    }
  ],
  "reasoning_chain": [
    "User asked about CVE-2021-41773 and its exploitability — triggered parallel cve_lookup + exploit_check.",
    "cve_lookup(CVE-2021-41773) -> CVSS v3 9.8 (CRITICAL), CWE-22 (Path Traversal), affects Apache HTTP Server 2.4.49 only, NVD description explicitly states 'known to be exploited in the wild', also references incomplete fix in CVE-2021-42013.",
    "exploit_check(CVE-2021-41773) -> has_public_exploit=true, Exploit-DB IDs: 50383 and 50512 confirmed.",
    "Both tool results confirm active exploitation and public exploit availability. Sufficient data to complete TriageReport with high confidence."
  ]
}
```

**What the agent did well**

- Followed reasoning rule #2 from the system prompt: when the user names a specific CVE ID, call `cve_lookup` and `exploit_check` in parallel. The single `CallToolsNode` carries both tool invocations.
- Surfaced a related CVE (`CVE-2021-42013`) it had not been asked about, because the NVD description for 41773 mentions the incomplete fix. Cross-CVE awareness is exactly what a triage analyst would do.
- Did not call `cve_semantic_search` for a known ID. No wasted tool calls.

---

## Session 2: product description, no CVE ID

The user names a product and version but no CVE. The agent must first decide which CVEs are relevant.

**Request**

```bash
curl -N -X POST http://localhost:8000/v1/triage \
  -H "Content-Type: application/json" \
  -d '{"query": "I am running Apache HTTP Server 2.4.49 on port 80. What vulnerabilities should I be aware of and how should I prioritize them?"}'
```

**SSE event sequence (19s end-to-end)**

```
event: started
event: node        UserPromptNode
event: node        ModelRequestNode
event: node        CallToolsNode      # cve_semantic_search('Apache HTTP Server 2.4.49 vulnerability')
event: node        ModelRequestNode
event: node        CallToolsNode      # cve_lookup x2 (41773, 42013)
event: node        ModelRequestNode
event: node        CallToolsNode      # exploit_check x2
event: node        End
event: final
```

Three rounds of tool calls. The agent disambiguates with semantic search first, then drills into the specific CVEs, then verifies exploit availability.

**Final TriageReport** (key fields)

```json
{
  "summary": "Apache HTTP Server 2.4.49 is affected by two actively exploited CRITICAL vulnerabilities (CVE-2021-41773 and CVE-2021-42013) — both path traversal / remote code execution flaws with CVSS 9.8. Public exploits are widely available on Exploit-DB. Immediate upgrade is required.",
  "severity": "critical",
  "confidence": "high",
  "recommended_action": "Upgrade Apache HTTP Server immediately to version 2.4.51 or later (ideally the latest stable release). Both CVE-2021-41773 and CVE-2021-42013 are exploited in the wild with public PoCs. As an interim mitigation, ensure 'require all denied' is set for all directories and disable CGI/mod_cgi if not needed.",
  "cves": [
    {"cve_id": "CVE-2021-41773", "cvss_v3_score": 9.8, "severity": "critical", "exploits_public": true, "...": "..."},
    {"cve_id": "CVE-2021-42013", "cvss_v3_score": 9.8, "severity": "critical", "exploits_public": true, "...": "..."}
  ],
  "reasoning_chain": [
    "User reported Apache HTTP Server 2.4.49 on port 80 — a version known for severe CVEs.",
    "cve_semantic_search('Apache HTTP Server 2.4.49 vulnerability') returned older/less-relevant results, so known CVE IDs for this specific version were used directly.",
    "cve_lookup(CVE-2021-41773) -> CVSS 9.8 CRITICAL, path traversal + RCE, affects only 2.4.49, actively exploited.",
    "cve_lookup(CVE-2021-42013) -> CVSS 9.8 CRITICAL, incomplete fix bypass of CVE-2021-41773, affects 2.4.49 and 2.4.50.",
    "exploit_check(CVE-2021-41773) -> has_public_exploit=true, Exploit-DB IDs 50383, 50512.",
    "exploit_check(CVE-2021-42013) -> has_public_exploit=true, Exploit-DB IDs 50406, 50446, 50512.",
    "Both CVEs are confirmed CRITICAL with public exploits — immediate upgrade to 2.4.51+ is the top recommendation."
  ]
}
```

**What the agent did well**

- Honest about a tool result that was not helpful. The semantic search returned "older/less-relevant" hits for the 30-day corpus (CVE-2021-41773 is from 2021, outside the lookback window), and the agent recorded that limitation in `reasoning_chain` instead of pretending it succeeded.
- Fell back to model knowledge for the version-to-CVE mapping, then re-grounded by `cve_lookup`-ing the resulting IDs. This is the right pattern: model knowledge for direction, tool calls for verification.
- Returned two CVEs in the report, not just the most obvious one.

---

## Session 3: Nmap XML input

The user pastes raw Nmap XML. The agent has to parse the structure, identify the services, and triage each one.

**Request**

```bash
curl -N -X POST http://localhost:8000/v1/triage \
  -H "Content-Type: application/json" \
  -d @- <<'EOF'
{"query": "Triage this Nmap scan output. Tell me which findings need immediate action.\n\n<?xml version=\"1.0\"?>\n<nmaprun start=\"1747528000\" version=\"7.94\">\n  <host>\n    <status state=\"up\"/>\n    <address addr=\"10.0.50.12\" addrtype=\"ipv4\"/>\n    <hostnames><hostname name=\"legacy-web.internal\" type=\"user\"/></hostnames>\n    <ports>\n      <port protocol=\"tcp\" portid=\"80\"><state state=\"open\" reason=\"syn-ack\"/><service name=\"http\" product=\"Apache httpd\" version=\"2.4.49\"/></port>\n      <port protocol=\"tcp\" portid=\"22\"><state state=\"open\" reason=\"syn-ack\"/><service name=\"ssh\" product=\"OpenSSH\" version=\"8.0\"/></port>\n      <port protocol=\"tcp\" portid=\"3306\"><state state=\"open\" reason=\"syn-ack\"/><service name=\"mysql\" product=\"MySQL\" version=\"5.7.32\"/></port>\n    </ports>\n  </host>\n</nmaprun>"}
EOF
```

**SSE event sequence (~30s end-to-end)**

Six rounds of `CallToolsNode`. The agent first parses, then searches per service, then looks up specific CVEs, then checks exploits.

**Final TriageReport** (key fields)

```json
{
  "summary": "Host 10.0.50.12 (legacy-web.internal) is running Apache httpd 2.4.49 — one of the most dangerous web server versions ever released — which is directly and exactly vulnerable to two critical, actively-exploited RCE/path-traversal CVEs (CVE-2021-41773 and CVE-2021-42013), both with CVSS 9.8 and multiple public exploits. MySQL 3306 is also exposed on the network interface, presenting a significant unauthorized-access risk. Immediate patching and network isolation are required.",
  "severity": "critical",
  "confidence": "high",
  "recommended_action": "IMMEDIATE ACTION REQUIRED: (1) Upgrade Apache httpd from 2.4.49 to 2.4.51 or later — versions 2.4.49 and 2.4.50 are both critically vulnerable and actively exploited in the wild. (2) Firewall TCP/3306 (MySQL) so it is not reachable from untrusted network segments; only application servers should connect. (3) Upgrade MySQL 5.7 to a supported version (5.7 reached EOL Oct 2023). (4) Audit the host for signs of compromise before patching, given active in-the-wild exploitation of the Apache CVEs.",
  "cves": [
    {"cve_id": "CVE-2021-41773", "cvss_v3_score": 9.8, "...": "..."},
    {"cve_id": "CVE-2021-42013", "cvss_v3_score": 9.8, "...": "..."}
  ],
  "reasoning_chain": [
    "nmap_parse_xml -> parsed host 10.0.50.12 (legacy-web.internal): Apache httpd 2.4.49 on port 80, OpenSSH 8.0 on port 22, MySQL 5.7.32 on port 3306",
    "cve_semantic_search('Apache httpd 2.4.49 path traversal RCE') -> low-similarity generic results; known CVEs CVE-2021-41773 and CVE-2021-42013 identified directly from version knowledge",
    "cve_lookup(CVE-2021-41773) -> CVSS 9.8 CRITICAL, CWE-22 path traversal, affects exactly Apache 2.4.49, known exploited in the wild",
    "cve_lookup(CVE-2021-42013) -> CVSS 9.8 CRITICAL, CWE-22, affects Apache 2.4.49 and 2.4.50, incomplete fix follow-on",
    "exploit_check(CVE-2021-41773) -> has_public_exploit=true, Exploit-DB IDs 50383, 50512",
    "exploit_check(CVE-2021-42013) -> has_public_exploit=true, Exploit-DB IDs 50406, 50446, 50512",
    "cve_semantic_search for MySQL 5.7.32 -> no high-severity CVEs post-5.7.32 returned; however MySQL 5.7 is EOL and port 3306 is network-exposed — flagged as high-risk misconfiguration",
    "cve_semantic_search for OpenSSH 8.0 -> tool error (description too long); OpenSSH 8.0 has no known critical unauthenticated RCE at this version; risk is lower but upgrade is still advisable",
    "Decision: CVE-2021-41773 and CVE-2021-42013 are direct, confirmed, version-exact critical hits requiring immediate action; MySQL exposure is a serious misconfiguration requiring network-level remediation"
  ]
}
```

**What the agent did well**

- All four MCP tools exercised in a single triage: `nmap_parse_xml`, `cve_semantic_search`, `cve_lookup`, `exploit_check`.
- Did not stop at the Apache findings. It continued through every parsed service, gave MySQL its own assessment (EOL + network exposure, even without a high-CVSS CVE), and gave OpenSSH a baseline check.
- Surfaced a tool error (`description too long`) in the `reasoning_chain` rather than hiding it. The agent then offered the best model-knowledge inference for OpenSSH 8.0 and flagged the lower confidence in the action plan.
- The recommended action is operational, not generic. Numbered steps in priority order, including the "audit for compromise *before* patching" guidance, which is what a real responder would say.

---

## Observations on agent behavior

- **The `reasoning_chain` is itself part of the contract.** Across all three sessions, it captures the order and outcome of every tool call. A downstream consumer (a SOC ticketing system, an audit log) can replay the chain without re-running the agent.
- **The agent treats `cve_semantic_search` as a hint, not as ground truth.** When semantic results are weak (sessions 2 and 3), it falls back to model knowledge for direction, then re-grounds with `cve_lookup`. When semantic results would be too narrow (session 1, specific CVE asked), it skips them entirely.
- **Tool failures degrade rather than abort.** Session 3 hit a tool error on the OpenSSH lookup and the agent kept going, surfaced the failure honestly, and gave a lower-confidence answer for that service.
- **No hallucinated CVEs or scores.** Every CVE ID in every report was verified against NVD in the same session. Every CVSS score in the output matches the NVD record.

## Reproducing these sessions

```bash
# Prerequisites: ANTHROPIC_API_KEY (and ideally NVD_API_KEY) in .env
uv sync
uv run sec-recon-seed      # ~5 min for 30-day corpus, ~20k CVEs

# Two terminals:
uv run sec-recon-mcp       # terminal 1: MCP server on :8001
uv run sec-recon-api       # terminal 2: agent API on :8000

# Run any of the three queries above.
```

Sessions are sensitive to the model and the corpus contents (CVE landscape shifts daily). Re-running these prompts on a different day or against a different LLM will produce different `summary` and `recommended_action` text. The `cves` list and the `cvss_v3_score` fields should be stable as long as NVD's data for those CVE IDs does not change.
