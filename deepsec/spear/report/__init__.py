"""VulnClaw Report Module — structured report generation with vulnerability verification."""

from deepsec.spear.report.filter import ReportContentFilter, filter_report_content
from deepsec.spear.report.findings_output import (
    build_findings_document,
    is_report_included,
    to_sarif,
    write_findings_artifacts,
)
from deepsec.spear.report.generator import (
    generate_persistent_cycle_report,
    generate_report,
    generate_report_from_file,
)
from deepsec.spear.report.poc_builder import generate_pocs, generate_single_poc
from deepsec.spear.report.verifier import (
    PoCGenerator,
    VerificationResult,
    VerificationStatus,
    VerifiedFinding,
    VerifierExecutor,
    VulnerabilityVerifier,
)

__all__ = [
    # Generator
    "generate_report",
    "generate_report_from_file",
    "generate_persistent_cycle_report",
    # Verifier
    "VulnerabilityVerifier",
    "VerifiedFinding",
    "VerificationStatus",
    "VerificationResult",
    "PoCGenerator",
    "VerifierExecutor",
    # Filter
    "ReportContentFilter",
    "filter_report_content",
    # PoC
    "generate_pocs",
    "generate_single_poc",
    # Structured findings output (findings.json + SARIF)
    "build_findings_document",
    "to_sarif",
    "write_findings_artifacts",
    "is_report_included",
]
