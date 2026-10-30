from typing import Dict, Optional

from core.scanners.port.report import (
    analyze_saved_report as analyze_saved_ports,
    combine_saved_reports,
)
from core.vulnerability.report_review import review_report


def analyze_saved_report(
    report: Dict,
    level: str = "quick",
    api_key: Optional[str] = None,
    max_online_lookups: int = 6,
) -> Dict:
    """Combine port and vulnerability analysis for report data already on disk."""
    normalized_level = level.lower()
    if normalized_level not in {"quick", "medium", "deep"}:
        raise ValueError("level must be quick, medium, or deep")

    port_summary = analyze_saved_ports(report)
    findings, severity_counts = review_report(
        report,
        include_local=normalized_level in {"medium", "deep"},
        online=normalized_level == "deep",
        api_key=api_key,
        max_online_lookups=max_online_lookups if normalized_level == "deep" else 0,
    )
    combined = combine_saved_reports(port_summary, findings)
    return {
        **combined,
        "review_level": normalized_level,
        "severity_counts": severity_counts,
    }
