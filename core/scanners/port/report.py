from collections import Counter
from typing import Dict, List


def summarize_ports(report: Dict) -> Dict:
    """Summarize port/service data from an existing report without network access."""
    raw_services = report.get("raw_services", [])
    if raw_services:
        services = [
            {
                "port": service.get("port"),
                "protocol": service.get("proto", "unknown"),
                "name": service.get("name", "unknown"),
                "product": service.get("product", ""),
                "version": service.get("version", ""),
            }
            for service in raw_services
        ]
    else:
        services = _services_from_display(report.get("services", []))

    protocols = Counter(service["protocol"] for service in services)
    return {
        "target": report.get("target", "unknown"),
        "timestamp": report.get("timestamp", "unknown"),
        "os": report.get("os", "Unknown"),
        "open_service_count": len(services),
        "protocol_counts": dict(protocols),
        "services": sorted(
            services,
            key=lambda service: (
                str(service["protocol"]),
                int(service["port"]) if str(service["port"]).isdigit() else 65536,
            ),
        ),
    }


def analyze_saved_report(report: Dict) -> Dict:
    """Return a deterministic, offline port-discovery view of a saved report."""
    return summarize_ports(report)


def combine_saved_reports(port_report: Dict, vulnerability_review: List[Dict]) -> Dict:
    """Combine already-collected report data; this function never scans a target."""
    port_summary = (
        port_report
        if "open_service_count" in port_report and "protocol_counts" in port_report
        else analyze_saved_report(port_report)
    )
    return {
        "target": port_summary["target"],
        "timestamp": port_summary["timestamp"],
        "os": port_summary["os"],
        "open_service_count": port_summary["open_service_count"],
        "protocol_counts": port_summary["protocol_counts"],
        "services": port_summary["services"],
        "vulnerabilities": vulnerability_review,
    }


def _services_from_display(display_services: List[str]) -> List[Dict]:
    services = []
    for value in display_services:
        parts = value.split(maxsplit=2)
        if not parts or "/" not in parts[0]:
            continue
        protocol, port_text = parts[0].split("/", 1)
        try:
            port = int(port_text)
        except ValueError:
            continue
        details = parts[1:] if len(parts) > 1 else []
        services.append({
            "port": port,
            "protocol": protocol,
            "name": details[0] if details else "unknown",
            "product": details[1] if len(details) > 1 else "",
            "version": "",
        })
    return services
