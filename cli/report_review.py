from datetime import datetime

from cli.ui import Colors, confirm, pause, print_error, print_success, render_menu
from core.engine.report_analysis import analyze_saved_report
from core.vulnerability.report_review import find_latest_report, save_review_report


def review_saved_result():
    while True:
        render_menu("Saved Report Review", [
            ("1", "Quick review", "saved results only; fastest, offline"),
            ("2", "Medium review", "saved results + local signatures; offline"),
            ("3", "Deep review", "fresh NVD checks for up to 6 services"),
            ("0", "Back", "return to vulnerability menu"),
        ], hint="All review levels use the latest saved report for the IP.")
        choice = input(f"{Colors.CYAN}Select review level: {Colors.RESET}").strip()
        if choice == "0":
            return
        if choice not in ("1", "2", "3"):
            print_error("Invalid option. Choose 0, 1, 2, or 3.")
            pause()
            continue

        target_ip = input(f"{Colors.CYAN}Device IP address: {Colors.RESET}").strip()
        try:
            report = find_latest_report(target_ip)
        except ValueError:
            print_error("Enter a valid IPv4 or IPv6 address.")
            pause()
            continue
        if report is None:
            print(f"{Colors.YELLOW}No saved report found for this IP. Run a scan and save its report first.{Colors.RESET}")
            pause()
            continue

        api_key = None
        if choice == "3":
            api_key = input(f"{Colors.CYAN}NVD API key (optional; press Enter to skip): {Colors.RESET}").strip() or None
        level = {"1": "quick", "2": "medium", "3": "deep"}[choice]
        print(f"{Colors.MUTED}Loading {level} review for {report.get('target', target_ip)}...{Colors.RESET}")
        result = analyze_saved_report(report, level=level, api_key=api_key)
        _display_result(result, report)

        if confirm("Save this reviewed result as a separate report in ./reports/?"):
            output_path = save_review_report(report, result["vulnerabilities"])
            print_success(f"Reviewed report saved to {output_path}")
        pause()


def _display_result(result, report):
    from core import Reporter

    print(
        f"\n{Colors.CYAN}{result['review_level'].title()} review for {result['target']} "
        f"({result['timestamp']}): {result['open_service_count']} open service(s), "
        f"{len(result['vulnerabilities'])} finding(s){Colors.RESET}"
    )
    counts = result["severity_counts"]
    print(
        f"{Colors.RED}Critical: {counts['CRITICAL']}  High: {counts['HIGH']}  "
        f"Medium: {counts['MEDIUM']}  Low: {counts['LOW']}  "
        f"Unknown: {counts['UNKNOWN']}{Colors.RESET}"
    )
    fallbacks = sum(
        finding.get("data_source") == "local_cache_fallback"
        for finding in result["vulnerabilities"]
    )
    if fallbacks:
        print(f"{Colors.YELLOW}{fallbacks} result(s) came from cache fallback, not fresh NVD data.{Colors.RESET}")

    Reporter.console_report({
        "target": result["target"],
        "os": result["os"],
        "timestamp": report.get("timestamp", datetime.now().isoformat()),
        "services": report.get("services", []),
        "modules": report.get("modules", {}),
        "vulnerabilities": {"Reviewed findings": result["vulnerabilities"]},
        "raw_services": [],
    })
