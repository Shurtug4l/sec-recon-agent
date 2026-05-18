"""Curated golden set of triage queries with expected output traits.

Each case picks a CVE (or vulnerability pattern) with a stable public
record so the agent has a fair chance to recover it through cve_lookup
or cve_semantic_search. Cases marked `in_kev=True` are present on the
CISA KEV catalog at the time of authoring; they exercise the KEV signal
path in addition to the base NVD path.

Hard correctness is impossible for an LLM-driven pipeline; the
assertions in `scorer.py` are intentionally soft.
"""

from dataclasses import dataclass, field

from sec_recon_agent.agent.schema import Severity


@dataclass(frozen=True)
class GoldenCase:
    """A single eval case.

    Fields:
        id: short kebab-case identifier shown in the report.
        query: literal user query sent to /v1/triage.
        expected_severity: baseline severity; scorer accepts +-1 level.
        expected_cves: CVE IDs that should appear in TriageReport.cves;
            at least half must be present.
        expected_in_kev: when True, at least one CVE in the report must
            have in_kev_catalog=True.
        expected_ransomware: when True, at least one CVE must have
            known_ransomware_use=True.
        tags: free-form bucket labels for filtering / reporting.
    """

    id: str
    query: str
    expected_severity: Severity
    expected_cves: tuple[str, ...] = ()
    expected_in_kev: bool = False
    expected_ransomware: bool = False
    tags: tuple[str, ...] = field(default_factory=tuple)


GOLDEN_SET: tuple[GoldenCase, ...] = (
    GoldenCase(
        id="apache-path-traversal",
        query="Apache HTTP Server 2.4.49 path traversal vulnerability",
        expected_severity=Severity.CRITICAL,
        expected_cves=("CVE-2021-41773", "CVE-2021-42013"),
        expected_in_kev=True,
        tags=("named-product", "kev"),
    ),
    GoldenCase(
        id="xz-utils-backdoor",
        query="CVE-2024-3094",
        expected_severity=Severity.CRITICAL,
        expected_cves=("CVE-2024-3094",),
        expected_in_kev=True,
        tags=("by-id", "supply-chain", "kev"),
    ),
    GoldenCase(
        id="eternalblue-smbv1",
        query="EternalBlue SMBv1 remote code execution",
        expected_severity=Severity.CRITICAL,
        expected_cves=("CVE-2017-0144",),
        expected_in_kev=True,
        expected_ransomware=True,
        tags=("named-exploit", "ransomware", "kev"),
    ),
    GoldenCase(
        id="log4shell-jndi",
        query="Log4Shell JNDI injection in Apache Log4j",
        expected_severity=Severity.CRITICAL,
        expected_cves=("CVE-2021-44228",),
        expected_in_kev=True,
        tags=("named-vuln", "kev"),
    ),
    GoldenCase(
        id="spring4shell",
        query="Spring Framework remote code execution Spring4Shell",
        expected_severity=Severity.CRITICAL,
        expected_cves=("CVE-2022-22965",),
        expected_in_kev=True,
        tags=("named-vuln", "kev"),
    ),
    GoldenCase(
        id="cve-by-id-printnightmare",
        query="CVE-2021-34527",
        expected_severity=Severity.HIGH,
        expected_cves=("CVE-2021-34527",),
        expected_in_kev=True,
        tags=("by-id", "kev"),
    ),
    GoldenCase(
        id="heartbleed",
        query="OpenSSL Heartbleed memory disclosure",
        expected_severity=Severity.HIGH,
        expected_cves=("CVE-2014-0160",),
        tags=("named-vuln", "historical"),
    ),
    GoldenCase(
        id="shellshock",
        query="Bash environment variable command injection Shellshock",
        expected_severity=Severity.CRITICAL,
        expected_cves=("CVE-2014-6271",),
        expected_in_kev=True,
        tags=("named-vuln", "kev", "historical"),
    ),
    GoldenCase(
        id="unknown-cve-degrade",
        query="CVE-9999-99999",
        # A non-existent CVE should produce a LOW-confidence INFO report.
        # The scorer tolerates LOW / INFO / MEDIUM here.
        expected_severity=Severity.INFO,
        expected_cves=(),
        tags=("degrade", "negative"),
    ),
    GoldenCase(
        id="generic-rce-description",
        query="unauthenticated remote code execution in a popular web server",
        # Fuzzy query: the agent should call cve_semantic_search and
        # surface at least one CRITICAL-severity CVE, identity not
        # asserted.
        expected_severity=Severity.HIGH,
        expected_cves=(),
        tags=("semantic", "fuzzy"),
    ),
)
