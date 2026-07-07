"""Curated golden set of triage queries with expected output traits.

Each case picks a CVE (or vulnerability pattern) with a stable public
record so the agent has a fair chance to recover it through cve_lookup
or cve_semantic_search. Cases marked `expected_in_kev=True` are present
on the CISA KEV catalog at the time of authoring; they exercise the KEV
signal path in addition to the base NVD path. Cases marked
`expected_in_kev=False` are verified ABSENT from the catalog: a report
that flags them as KEV-listed is a fabrication and fails the case.
Ground truth here is a claim about an external catalog, so re-verify
against the live CISA feed before changing either direction.

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
        expected_any_cve_of: alternative acceptance set - satisfied when
            at least ONE listed CVE appears in the report. For families
            of near-identical CVEs (one advisory, one patch) where
            requiring a specific member would over-specify the ground
            truth. Independent of expected_cves; both apply when set.
        expected_in_kev: tri-state. True: at least one CVE in the report
            must have in_kev_catalog=True. False: no CVE may carry
            in_kev_catalog=True (the CVE is verified absent from the
            catalog, so a KEV flag is fabricated). None: not scored.
        expected_ransomware: when True, at least one CVE must have
            known_ransomware_use=True.
        tags: free-form bucket labels for filtering / reporting.
    """

    id: str
    query: str
    expected_severity: Severity
    expected_cves: tuple[str, ...] = ()
    expected_any_cve_of: tuple[str, ...] = ()
    expected_in_kev: bool | None = None
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
        # CISA never added the xz backdoor to KEV (no confirmed
        # in-the-wild exploitation; the implant needs the attacker's
        # private key). Verified against catalog 2026.07.07. False here
        # means a KEV flag on this CVE is fabricated, not missing.
        expected_in_kev=False,
        tags=("by-id", "supply-chain"),
    ),
    GoldenCase(
        id="eternalblue-smbv1",
        query="EternalBlue SMBv1 remote code execution",
        expected_severity=Severity.CRITICAL,
        # EternalBlue is canonically CVE-2017-0144, but the MS17-010
        # SMBv1 RCE family (0143/0144/0145/0146/0148) shares
        # near-identical NVD descriptions and a single patch. Retrieval
        # legitimately surfaces siblings; requiring exactly 0144
        # over-specified the ground truth (and stuffing the family into
        # expected_cves would fail a report carrying only 0144 via the
        # >=50% recall rule). Any family member grounds the case.
        expected_any_cve_of=(
            "CVE-2017-0144",
            "CVE-2017-0143",
            "CVE-2017-0145",
            "CVE-2017-0146",
            "CVE-2017-0148",
        ),
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
        id="sbom-log4j-cyclonedx",
        query=(
            '{"bomFormat":"CycloneDX","specVersion":"1.5",'
            '"components":['
            '{"type":"library","name":"log4j-core","version":"2.14.1",'
            '"purl":"pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1"},'
            '{"type":"library","name":"spring-webmvc","version":"5.3.20"}'
            "]}"
        ),
        expected_severity=Severity.CRITICAL,
        expected_cves=("CVE-2021-44228",),
        expected_in_kev=True,
        tags=("sbom", "cyclonedx", "kev"),
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
