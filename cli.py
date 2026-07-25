#!/usr/bin/env python3
# =============================================================================
# cli.py – Nemesis Scanner | Interactive Menu + CLI + Auto-Save in reports/
# UI/UX inspired by Project Nemesis main dashboard
# Requires: core.py (NemesisScanner, Reporter, VERSION)
# =============================================================================
import sys
import os
import asyncio
import argparse
from datetime import datetime
from pathlib import Path
from typing import List, Optional

# ---------- Import core with fallback for package vs standalone ----------
try:
    from .core import NemesisScanner, Reporter, VERSION as CORE_VERSION
except ImportError:
    from core import NemesisScanner, Reporter, VERSION as CORE_VERSION

# ---------------------------------------------------------------------------
# Terminal colour & UI helpers (copied from main.py style)
# ---------------------------------------------------------------------------
class Colors:
    RED     = "\033[1;31m"
    MUTED   = "\033[0;31m"
    CYAN    = "\033[1;36m"
    YELLOW  = "\033[1;33m"
    GREEN   = "\033[1;32m"
    BOLD    = "\033[1m"
    RESET   = "\033[0m"
    # Box‑drawing (set to ASCII if not a TTY)
    HLINE = "─"
    VLINE = "│"
    TOPL  = "┌"
    TOPR  = "┐"
    BOTL  = "└"
    BOTR  = "┘"

if not sys.stdout.isatty():
    # Remove all ANSI escapes and use plain ASCII
    for attr in dir(Colors):
        if not attr.startswith("_") and isinstance(getattr(Colors, attr), str):
            setattr(Colors, attr, "")
    Colors.HLINE = "-"
    Colors.VLINE = "|"
    Colors.TOPL = "+"
    Colors.TOPR = "+"
    Colors.BOTL = "+"
    Colors.BOTR = "+"

def clear_screen():
    os.system("clear" if os.name != "nt" else "cls")

def banner(text: str):
    width = 60
    top = f"{Colors.RED}{Colors.TOPL}{Colors.HLINE * (width - 2)}{Colors.TOPR}"
    pad = (width - 2 - len(text)) // 2
    middle = (
        f"{Colors.VLINE}{' ' * pad}{Colors.BOLD}{text}{Colors.RESET}{Colors.RED}"
        f"{' ' * (width - 2 - len(text) - pad)}{Colors.VLINE}"
    )
    bottom = f"{Colors.BOTL}{Colors.HLINE * (width - 2)}{Colors.BOTR}{Colors.RESET}"
    print(top)
    print(middle)
    print(bottom)

def logo():
    clear_screen()
    print(f"""{Colors.RED}
███╗   ██╗███████╗███╗   ███╗███████╗███████╗██╗███████╗
████╗  ██║██╔════╝████╗ ████║██╔════╝██╔════╝██║██╔════╝
██╔██╗ ██║█████╗  ██╔████╔██║█████╗  ███████╗██║███████╗
██║╚██╗██║██╔══╝  ██║╚██╔╝██║██╔══╝  ╚════██║██║╚════██║
██║ ╚████║███████╗██║ ╚═╝ ██║███████╗███████║██║███████║
╚═╝  ╚═══╝╚══════╝╚═╝     ╚═╝╚══════╝╚══════╝╚═╝╚══════╝
{Colors.RESET}""")
    print(f"{Colors.MUTED}                 Nemesis Scanner – Shadow Edition v{CORE_VERSION}{Colors.RESET}\n")

def pause():
    input(f"\n{Colors.MUTED}Press Enter to return...{Colors.RESET}")

# ---------------------------------------------------------------------------
# Auto-save filename generator (inside reports/ folder)
# ---------------------------------------------------------------------------
def auto_save_filename(target: str, ext: str) -> str:
    reports_dir = Path("reports")
    reports_dir.mkdir(parents=True, exist_ok=True)
    safe_target = target.replace('/', '_').replace(':', '_').replace('\\', '_')
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    return str(reports_dir / f"{safe_target}_{timestamp}.{ext}")

# ---------------------------------------------------------------------------
# Async scan runner
# ---------------------------------------------------------------------------
async def run_scan(targets: List[str], scan_args):
    if not targets:
        return
    total = len(targets)
    # Simple progress indicator
    print(f"{Colors.CYAN}Starting scan of {total} target(s)...{Colors.RESET}")
    tasks = []
    for t in targets:
        scanner = NemesisScanner(
            target=t,
            scan_mode=scan_args.mode,
            threads=scan_args.threads,
            stealth=scan_args.stealth,
            vuln_check=scan_args.vuln_check,
            nmap_args_extra=scan_args.nmap_args or "",
            nvd_api_key=getattr(scan_args, 'nvd_key', None),
            vulners_api_key=getattr(scan_args, 'vulners_key', None),
            aggressive=getattr(scan_args, 'aggressive', False),
            turbo=getattr(scan_args, 'turbo', False),
            fragment=getattr(scan_args, 'fragment', False),
            source_port=getattr(scan_args, 'source_port', None),
            spoof_mac=getattr(scan_args, 'spoof_mac', None),
            decoys=getattr(scan_args, 'decoys', None),
            ttl=getattr(scan_args, 'ttl', None),
            auth_check=getattr(scan_args, 'auth_check', False),
        )
        tasks.append(scanner.full_analysis())
    results = await asyncio.gather(*tasks, return_exceptions=True)

    for result in results:
        if isinstance(result, Exception):
            print(f"{Colors.RED}Scan error: {result}{Colors.RESET}")
            continue
        if not result:
            continue
        Reporter.console_report(result, verbose=getattr(scan_args, 'verbose', False))

        # Save reports based on user choice
        if getattr(scan_args, 'output', None):
            base = scan_args.output
            fmt = getattr(scan_args, 'format', 'json')
            if fmt in ("json", "all"):
                Reporter.json_report(result, f"{base}.json")
            if fmt in ("csv", "all"):
                Reporter.csv_report(result, f"{base}.csv")
            if fmt in ("html", "all"):
                Reporter.html_report(result, f"{base}.html")

        if getattr(scan_args, 'auto_save', False):
            fmt = getattr(scan_args, 'format', 'json')
            if fmt == 'all':
                fmt = 'json'
            fname = auto_save_filename(result['target'], fmt)
            if fmt == "json":
                Reporter.json_report(result, fname)
            elif fmt == "csv":
                Reporter.csv_report(result, fname)
            elif fmt == "html":
                Reporter.html_report(result, fname)
            print(f"{Colors.GREEN}Auto-saved report to {fname}{Colors.RESET}")

def run_scan_sync(targets: List[str], args):
    asyncio.run(run_scan(targets, args))

# ---------------------------------------------------------------------------
# Scanner Menu – designed to match the main dashboard UI
# ---------------------------------------------------------------------------
class ScannerMenu:
    """Interactive menu interface for Nemesis Scanner."""

    @staticmethod
    def main_menu():
        while True:
            clear_screen()
            logo()
            banner("Scanner Main Menu")
            print(f"""{Colors.YELLOW}
  [1] Quick Scan (presets)
  [2] Advanced Configuration (wizard)
  [3] Enter raw scanner arguments
  [4] About
  [5] Update & Maintenance
  [0] Return to Dashboard
{Colors.RESET}""")
            choice = input(f"{Colors.CYAN}Choice: {Colors.RESET}").strip()
            if choice == "1":
                ScannerMenu.quick_menu()
            elif choice == "2":
                ScannerMenu.advanced_wizard()
            elif choice == "3":
                ScannerMenu.raw_args()
            elif choice == "4":
                ScannerMenu.about()
            elif choice == "5":
                ScannerMenu.update()
            elif choice == "0":
                return  # exit the scanner menu, back to main dashboard
            else:
                print(f"{Colors.RED}Invalid option.{Colors.RESET}")
                pause()

    # -------------------------------------------------------------------
    # About
    # -------------------------------------------------------------------
    ABOUT_ME = """
I'm Erfan Nahidi
Virtualization & Infrastructure Administrator

Focused on designing scalable, resilient, and high-performance datacenter
infrastructures. Passionate about virtualization, Linux systems, networking,
and low-level computing, with a strong interest in systems programming and
infrastructure engineering.
"""

    @staticmethod
    def about():
        clear_screen()
        logo()
        banner("About Nemesis Scanner")
        print(f"{Colors.CYAN}{ScannerMenu.ABOUT_ME.strip()}{Colors.RESET}")
        print(f"\n{Colors.MUTED}Version: {CORE_VERSION}{Colors.RESET}")
        print(f"{Colors.MUTED}GitHub: https://github.com/ErfanNahidi/Nemesis-Scanner{Colors.RESET}")
        pause()

    # -------------------------------------------------------------------
    # Update & Maintenance (simplified)
    # -------------------------------------------------------------------
    @staticmethod
    def update():
        clear_screen()
        logo()
        banner("Update & Maintenance")
        print(f"""{Colors.YELLOW}
  [1] Install/update Python dependencies (requirements.txt)
  [0] Back
{Colors.RESET}""")
        choice = input(f"{Colors.CYAN}Choice: {Colors.RESET}").strip()
        if choice == "1":
            if os.path.exists("requirements.txt"):
                print(f"{Colors.CYAN}Installing from requirements.txt...{Colors.RESET}")
                ret = os.system(f"{sys.executable} -m pip install -r requirements.txt")
                if ret == 0:
                    print(f"{Colors.GREEN}Dependencies updated.{Colors.RESET}")
                else:
                    print(f"{Colors.RED}Installation failed.{Colors.RESET}")
            else:
                print(f"{Colors.RED}requirements.txt not found.{Colors.RESET}")
            pause()
        # else just back

    # -------------------------------------------------------------------
    # Quick scan profiles
    # -------------------------------------------------------------------
    @staticmethod
    def quick_menu():
        while True:
            clear_screen()
            logo()
            banner("Quick Scan Profiles")
            print(f"""{Colors.YELLOW}
  [1] Quick scan (common ports, fast)
  [2] Common scan (top 1000 ports, version & scripts)
  [3] Full scan (all 65535 ports, very slow)
  [4] Security scan (common + vulnerability check)
  [5] Turbo scan (ultra-fast, top critical ports)
  [0] Back
{Colors.RESET}""")
            choice = input(f"{Colors.CYAN}Choice: {Colors.RESET}").strip()
            if choice in ("1","2","3","4","5"):
                target = input(f"{Colors.CYAN}Target (IP or CIDR): {Colors.RESET}").strip()
                if not target:
                    print(f"{Colors.RED}Target is required!{Colors.RESET}")
                    pause()
                    continue

                args = argparse.Namespace()
                args.targets = [target]
                args.threads = 10
                args.stealth = False
                args.vuln_check = False
                args.nmap_args = ""
                args.nvd_key = None
                args.vulners_key = None
                args.aggressive = False
                args.turbo = False
                args.fragment = False
                args.source_port = None
                args.spoof_mac = None
                args.decoys = None
                args.ttl = None
                args.auth_check = False
                args.output = None
                args.format = "json"
                args.verbose = False
                args.email = None
                args.slack = None
                args.auto_save = False

                if choice == "1":
                    args.mode = "quick"
                elif choice == "2":
                    args.mode = "common"
                elif choice == "3":
                    args.mode = "full"
                elif choice == "4":
                    args.mode = "common"
                    args.vuln_check = True
                elif choice == "5":
                    args.mode = "turbo"
                    args.turbo = True

                auto = input(f"{Colors.CYAN}Auto-save report with IP+time? [y/N]: {Colors.RESET}").strip().lower()
                if auto == "y":
                    args.auto_save = True
                    fmt = input(f"{Colors.CYAN}  Format (json/csv/html) [json]: {Colors.RESET}").strip().lower()
                    args.format = fmt if fmt in ("json", "csv", "html") else "json"

                run_scan_sync([target], args)
                pause()
            elif choice == "0":
                break
            else:
                print(f"{Colors.RED}Invalid option.{Colors.RESET}")
                pause()

    # -------------------------------------------------------------------
    # Advanced wizard
    # -------------------------------------------------------------------
    @staticmethod
    def advanced_wizard():
        clear_screen()
        logo()
        banner("Advanced Scanner Configuration")
        print(f"{Colors.MUTED}Configure scan options. Leave empty to use defaults.{Colors.RESET}\n")
        target = input(f"{Colors.CYAN}Target(s) (IP/CIDR, required): {Colors.RESET}").strip()
        if not target:
            print(f"{Colors.RED}Target is required.{Colors.RESET}")
            pause()
            return
        args = argparse.Namespace()
        args.targets = [t.strip() for t in target.split(',') if t.strip()]
        mode = input(f"{Colors.CYAN}Scan mode (quick/common/full/custom/turbo) [quick]: {Colors.RESET}").strip().lower()
        args.mode = mode if mode in ("quick","common","full","custom","turbo") else "quick"
        args.turbo = (args.mode == "turbo")
        args.stealth = input(f"{Colors.CYAN}Stealth mode? [y/N]: {Colors.RESET}").strip().lower() == "y"
        args.vuln_check = input(f"{Colors.CYAN}Vulnerability check (online NVD)? [y/N]: {Colors.RESET}").strip().lower() == "y"
        if args.vuln_check:
            args.nvd_key = input(f"{Colors.CYAN}  NVD API key (optional): {Colors.RESET}").strip() or None
            args.vulners_key = input(f"{Colors.CYAN}  Vulners API key (optional): {Colors.RESET}").strip() or None
        else:
            args.nvd_key = None
            args.vulners_key = None
        args.nmap_args = input(f"{Colors.CYAN}Extra Nmap arguments: {Colors.RESET}").strip() or ""
        threads = input(f"{Colors.CYAN}Max parallel threads [10]: {Colors.RESET}").strip()
        args.threads = int(threads) if threads.isdigit() else 10

        auto = input(f"{Colors.CYAN}Auto-save report with IP+time? [y/N]: {Colors.RESET}").strip().lower()
        args.auto_save = (auto == "y")
        if args.auto_save:
            fmt = input(f"{Colors.CYAN}  Format (json/csv/html) [json]: {Colors.RESET}").strip().lower()
            args.format = fmt if fmt in ("json", "csv", "html") else "json"
            args.output = None
        else:
            output = input(f"{Colors.CYAN}Output base filename (without extension, Enter to skip): {Colors.RESET}").strip()
            if output:
                args.output = output
                fmt = input(f"{Colors.CYAN}  Output format (json/csv/html/all) [json]: {Colors.RESET}").strip().lower()
                args.format = fmt if fmt in ("json","csv","html","all") else "json"
            else:
                args.output = None
                args.format = "json"

        args.verbose = input(f"{Colors.CYAN}Verbose console output? [y/N]: {Colors.RESET}").strip().lower() == "y"
        args.aggressive = input(f"{Colors.CYAN}Aggressive mode (T5, max speed)? [y/N]: {Colors.RESET}").strip().lower() == "y"
        args.fragment = input(f"{Colors.CYAN}Fragment IP packets (-f)? [y/N]: {Colors.RESET}").strip().lower() == "y"
        src_port = input(f"{Colors.CYAN}Source port spoof (number, Enter to skip): {Colors.RESET}").strip()
        args.source_port = int(src_port) if src_port.isdigit() else None
        args.spoof_mac = input(f"{Colors.CYAN}Spoof MAC address (Enter to skip): {Colors.RESET}").strip() or None
        decoys = input(f"{Colors.CYAN}Decoy IPs (comma-separated, Enter to skip): {Colors.RESET}").strip()
        args.decoys = decoys if decoys else None
        ttl = input(f"{Colors.CYAN}TTL value (Enter to skip): {Colors.RESET}").strip()
        args.ttl = int(ttl) if ttl.isdigit() else None
        args.auth_check = input(f"{Colors.CYAN}Basic auth check? [y/N]: {Colors.RESET}").strip().lower() == "y"
        args.email = None
        args.slack = None

        clear_screen()
        banner("Review Your Configuration")
        print(f"Target: {', '.join(args.targets)}")
        print(f"Mode: {args.mode}, Threads: {args.threads}, Stealth: {args.stealth}, VulnCheck: {args.vuln_check}")
        if args.turbo: print(f"{Colors.RED}Turbo mode ON (ultra-fast){Colors.RESET}")
        if args.nmap_args: print(f"Nmap extras: {args.nmap_args}")
        if args.auto_save: print(f"Auto-save: Yes (format: {args.format}) -> reports/ folder")
        elif args.output: print(f"Output: {args.output}.{args.format}")
        if args.aggressive: print(f"{Colors.RED}Aggressive mode ON{Colors.RESET}")
        if input(f"{Colors.CYAN}Start scan? [Y/n]: {Colors.RESET}").strip().lower() in ("", "y"):
            run_scan_sync(args.targets, args)
        pause()

    # -------------------------------------------------------------------
    # Raw CLI arguments entry
    # -------------------------------------------------------------------
    @staticmethod
    def raw_args():
        clear_screen()
        logo()
        banner("Enter Raw Scanner Arguments")
        print(f"{Colors.MUTED}Type arguments exactly as you would on the command line.{Colors.RESET}")
        print(f"{Colors.MUTED}Example: 192.168.1.0/24 -m quick --auto-save{Colors.RESET}\n")
        raw = input(f"{Colors.CYAN}Arguments: {Colors.RESET}").strip()
        if not raw:
            return
        old_argv = sys.argv
        try:
            sys.argv = ["cli.py"] + raw.split()
            args = parse_args()
            if not args.targets:
                print(f"{Colors.RED}No targets specified.{Colors.RESET}")
                pause()
                return
            run_scan_sync(args.targets, args)
        except SystemExit:
            pass
        finally:
            sys.argv = old_argv
        pause()

# ---------------------------------------------------------------------------
# Argparse for direct CLI usage (non-interactive)
# ---------------------------------------------------------------------------
def parse_args():
    parser = argparse.ArgumentParser(description="Nemesis Scanner", add_help=False)
    parser.add_argument("targets", nargs="*", help="Target(s)")
    parser.add_argument("-m", "--mode", default="quick")
    parser.add_argument("--stealth", action="store_true")
    parser.add_argument("--vuln-check", action="store_true")
    parser.add_argument("--nvd-key")
    parser.add_argument("--vulners-key")
    parser.add_argument("--nmap-args", default="")
    parser.add_argument("-t", "--threads", type=int, default=10)
    parser.add_argument("-o", "--output")
    parser.add_argument("--format", choices=["json","csv","html","all"], default="json")
    parser.add_argument("--verbose", action="store_true")
    parser.add_argument("--email")
    parser.add_argument("--slack")
    parser.add_argument("--aggressive", action="store_true")
    parser.add_argument("--turbo", action="store_true", help="Enable turbo mode (ultra-fast)")
    parser.add_argument("--fragment", action="store_true")
    parser.add_argument("--source-port", type=int)
    parser.add_argument("--spoof-mac")
    parser.add_argument("--decoys")
    parser.add_argument("--ttl", type=int)
    parser.add_argument("--auth-check", action="store_true")
    parser.add_argument("--auto-save", action="store_true", help="Auto-save report in reports/ folder with IP+timestamp")
    parser.add_argument("--config")
    parser.add_argument("--interactive", action="store_true", help="Force interactive menu")
    args, _ = parser.parse_known_args()
    return args

# ---------------------------------------------------------------------------
# Main entry point
# ---------------------------------------------------------------------------
def main():
    if len(sys.argv) == 1 or "--interactive" in sys.argv:
        try:
            ScannerMenu.main_menu()
        except KeyboardInterrupt:
            print(f"\n{Colors.YELLOW}Interrupted. Exiting...{Colors.RESET}")
    else:
        try:
            args = parse_args()
            if not args.targets:
                print(f"{Colors.RED}Error: No target specified. Use --interactive for menu.{Colors.RESET}")
                sys.exit(1)
            run_scan_sync(args.targets, args)
        except KeyboardInterrupt:
            print(f"\n{Colors.YELLOW}Scan interrupted by user.{Colors.RESET}")
        except Exception as e:
            print(f"{Colors.RED}Fatal error: {e}{Colors.RESET}")

if __name__ == "__main__":
    main()