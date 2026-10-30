import asyncio
from datetime import datetime
from pathlib import Path
from typing import List

from core import NemesisScanner, Reporter


def auto_save_filename(target: str, extension: str) -> str:
    reports_dir = Path("reports")
    reports_dir.mkdir(parents=True, exist_ok=True)
    safe_target = target.replace("/", "_").replace(":", "_").replace("\\", "_")
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    return str(reports_dir / f"{safe_target}_{timestamp}.{extension}")


async def run_scan(targets: List[str], scan_args, colors):
    if not targets:
        return
    print(f"{colors.CYAN}Starting scan of {len(targets)} target(s)...{colors.RESET}")
    tasks = []
    for target in targets:
        scanner = NemesisScanner(
            target=target,
            scan_mode=scan_args.mode,
            threads=scan_args.threads,
            stealth=scan_args.stealth,
            vuln_check=scan_args.vuln_check,
            nmap_args_extra=scan_args.nmap_args or "",
            nvd_api_key=getattr(scan_args, "nvd_key", None),
            vulners_api_key=getattr(scan_args, "vulners_key", None),
            aggressive=getattr(scan_args, "aggressive", False),
            turbo=getattr(scan_args, "turbo", False),
            fragment=getattr(scan_args, "fragment", False),
            source_port=getattr(scan_args, "source_port", None),
            spoof_mac=getattr(scan_args, "spoof_mac", None),
            decoys=getattr(scan_args, "decoys", None),
            ttl=getattr(scan_args, "ttl", None),
            auth_check=getattr(scan_args, "auth_check", False),
            deep_inspect=getattr(scan_args, "deep_inspect", True),
            skip_ping=getattr(scan_args, "skip_ping", False),
            ipv6=getattr(scan_args, "ipv6", False),
            vuln_source=getattr(scan_args, "vuln_source", "offline"),
        )
        tasks.append(scanner.full_analysis())

    results = await asyncio.gather(*tasks, return_exceptions=True)
    for result in results:
        if isinstance(result, Exception):
            print(f"{colors.RED}Scan error: {result}{colors.RESET}")
            continue
        if not result:
            continue
        Reporter.console_report(result, verbose=getattr(scan_args, "verbose", False))
        _write_requested_outputs(result, scan_args)
        if getattr(scan_args, "auto_save", False):
            extension = getattr(scan_args, "format", "json")
            if extension == "all":
                extension = "json"
            output_path = auto_save_filename(result["target"], extension)
            _write_report(result, output_path, extension)
            print(f"{colors.GREEN}Auto-saved report to {output_path}{colors.RESET}")


def run_scan_sync(targets: List[str], args, colors):
    asyncio.run(run_scan(targets, args, colors))


def _write_requested_outputs(result: dict, args) -> None:
    output_base = getattr(args, "output", None)
    if not output_base:
        return
    output_format = getattr(args, "format", "json")
    formats = ("json", "csv", "html") if output_format == "all" else (output_format,)
    for extension in formats:
        _write_report(result, f"{output_base}.{extension}", extension)


def _write_report(result: dict, output_path: str, extension: str) -> None:
    if extension == "json":
        Reporter.json_report(result, output_path)
    elif extension == "csv":
        Reporter.csv_report(result, output_path)
    elif extension == "html":
        Reporter.html_report(result, output_path)
