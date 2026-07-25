#!/usr/bin/env python3
# =============================================================================
# cli.py – Nemesis Scanner | Interactive Menu + CLI + Auto-Save in reports/
# Requires: core.py (NemesisScanner, Reporter, VERSION)
# =============================================================================
import sys
import os
import asyncio
import argparse
from datetime import datetime
from pathlib import Path
from typing import List, Optional

from colorama import Fore, Style, init
from tqdm import tqdm

# Core imports
from core import NemesisScanner, Reporter, VERSION as CORE_VERSION

init(autoreset=True)

# ---------------------------------------------------------------------------
# ASCII Art & Colors
# ---------------------------------------------------------------------------
LOGO = f"""
{Fore.RED}
███╗   ██╗███████╗███╗   ███╗███████╗███████╗██╗███████╗
████╗  ██║██╔════╝████╗ ████║██╔════╝██╔════╝██║██╔════╝
██╔██╗ ██║█████╗  ██╔████╔██║█████╗  ███████╗██║███████╗
██║╚██╗██║██╔══╝  ██║╚██╔╝██║██╔══╝  ╚════██║██║╚════██║
██║ ╚████║███████╗██║ ╚═╝ ██║███████╗███████║██║███████║
╚═╝  ╚═══╝╚══════╝╚═╝     ╚═╝╚══════╝╚══════╝╚═╝╚══════╝
{Fore.CYAN}                 Nemesis Scanner – Shadow Edition v{CORE_VERSION}
{Fore.LIGHTBLACK_EX}              « Silence before the storm »
{Style.RESET_ALL}
"""

class Colors:
    RED = Fore.RED
    GREEN = Fore.GREEN
    YELLOW = Fore.YELLOW
    BLUE = Fore.BLUE
    CYAN = Fore.CYAN
    MAGENTA = Fore.MAGENTA
    MUTED = Fore.LIGHTBLACK_EX
    RESET = Style.RESET_ALL
    BOLD = Style.BRIGHT

def clear_screen():
    os.system('cls' if os.name == 'nt' else 'clear')

def banner(text: str):
    print(f"{Colors.BOLD}{Colors.CYAN}{'='*60}")
    print(f"  {text}")
    print(f"{'='*60}{Colors.RESET}")

def logo():
    print(LOGO)

# ---------------------------------------------------------------------------
# Auto-save filename generator (inside reports/ folder)
# ---------------------------------------------------------------------------
def auto_save_filename(target: str, ext: str) -> str:
    """
    Generate a filename like reports/192.168.178.1_20260725_143015.json
    Automatically creates the reports directory if missing.
    """
    reports_dir = Path("reports")
    reports_dir.mkdir(parents=True, exist_ok=True)

    safe_target = target.replace('/', '_').replace(':', '_').replace('\\', '_')
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = f"{safe_target}_{timestamp}.{ext}"
    return str(reports_dir / filename)

# ---------------------------------------------------------------------------
# Core scan execution (async wrapper)
# ---------------------------------------------------------------------------
async def run_scan(targets: List[str], scan_args):
    """Run scanner on multiple targets with progress display."""
    if not targets:
        return
    total = len(targets)
    with tqdm(total=total, desc="Scanning", unit="target", colour="green") as pbar:
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
        pbar.update(total)

    for result in results:
        if isinstance(result, Exception):
            print(f"{Colors.RED}Scan error: {result}{Colors.RESET}")
            continue
        if not result:
            continue

        Reporter.console_report(result, verbose=getattr(scan_args, 'verbose', False))

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

        if getattr(scan_args, 'email', None):
            pass
        if getattr(scan_args, 'slack', None):
            pass

def run_scan_sync(targets: List[str], args):
    asyncio.run(run_scan(targets, args))

# ---------------------------------------------------------------------------
# Menu Classes
# ---------------------------------------------------------------------------
class ScannerMenu:
    """Interactive menu interface for the Nemesis Scanner."""

    @staticmethod
    def main_menu():
        while True:
            clear_screen()
            logo()
            banner("Main Menu")
            print(f"""{Colors.YELLOW}
  [1] Quick Scan (presets)
  [2] Advanced Configuration (wizard)
  [3] Enter raw scanner arguments
  [4] About
  [5] Update             
  [0] Exit
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
                print(f"{Colors.GREEN}Exiting Nemesis Scanner...{Colors.RESET}")
                sys.exit(0)
            else:
                print(f"{Colors.RED}Invalid option, press Enter to continue...{Colors.RESET}")
                input()

    # -----------------------------------------------------------------------
    # About information
    # -----------------------------------------------------------------------
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
        print(f"{Colors.CYAN}Version: {CORE_VERSION}{Colors.RESET}")
        print(f"{Colors.MUTED}Author: Erfan Nahidi{Colors.RESET}")
        print(f"{Colors.MUTED}GitHub: https://github.com/ErfanNahidi/Nemesis-Scanner{Colors.RESET}")
        print(ScannerMenu.ABOUT_ME)
        print(f"\n{Colors.MUTED}Project: Nemesis Scanner – A powerful network scanner with vulnerability detection.{Colors.RESET}")
        input(f"{Colors.GREEN}Press Enter to continue...{Colors.RESET}")

    # -----------------------------------------------------------------------
    # Update & Maintenance (with clone, pull, and requirements)
    # -----------------------------------------------------------------------
    @staticmethod
    def update():
        clear_screen()
        logo()
        banner("Update & Maintenance")
        while True:
            print(f"""{Colors.YELLOW}
  [1] Update source code via git pull (if already cloned)
  [2] Clone repository from GitHub (if not cloned)
  [3] Install/update Python dependencies (requirements.txt)
  [0] Back
{Colors.RESET}""")
            choice = input(f"{Colors.CYAN}Choice: {Colors.RESET}").strip()
            if choice == "1":
                if os.path.isdir(".git"):
                    print(f"{Colors.CYAN}Running git pull...{Colors.RESET}")
                    ret = os.system("git pull origin main 2>&1")
                    if ret == 0:
                        print(f"{Colors.GREEN}Update successful.{Colors.RESET}")
                    else:
                        print(f"{Colors.RED}Update failed. Check your network or git configuration.{Colors.RESET}")
                else:
                    print(f"{Colors.RED}Not a git repository. Use option 2 to clone first.{Colors.RESET}")
                input("Press Enter to continue...")
            elif choice == "2":
                repo_url = "https://github.com/ErfanNahidi/Nemesis-Scanner.git"
                if os.path.exists(".git"):
                    print(f"{Colors.YELLOW}Already a git repository. If you want to re-clone, delete .git folder first.{Colors.RESET}")
                else:
                    print(f"{Colors.CYAN}Cloning repository from {repo_url} ...{Colors.RESET}")
                    ret = os.system(f"git clone {repo_url} . 2>&1")
                    if ret == 0:
                        print(f"{Colors.GREEN}Clone successful.{Colors.RESET}")
                    else:
                        print(f"{Colors.RED}Clone failed. Maybe directory is not empty or network issue.{Colors.RESET}")
                input("Press Enter to continue...")
            elif choice == "3":
                if os.path.exists("requirements.txt"):
                    print(f"{Colors.CYAN}Installing/updating dependencies from requirements.txt...{Colors.RESET}")
                    ret = os.system("pip install -r requirements.txt 2>&1")
                    if ret == 0:
                        print(f"{Colors.GREEN}Dependencies installed/updated successfully.{Colors.RESET}")
                    else:
                        print(f"{Colors.RED}Installation failed. Check pip and requirements file.{Colors.RESET}")
                else:
                    print(f"{Colors.RED}requirements.txt not found in current directory.{Colors.RESET}")
                input("Press Enter to continue...")
            elif choice == "0":
                break
            else:
                print(f"{Colors.RED}Invalid choice.{Colors.RESET}")
                input("Press Enter to continue...")

    # -----------------------------------------------------------------------
    # Quick scan profiles
    # -----------------------------------------------------------------------
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
                    input("Press Enter...")
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
                input(f"{Colors.GREEN}Press Enter to continue...{Colors.RESET}")
            elif choice == "0":
                break
            else:
                print(f"{Colors.RED}Invalid option.{Colors.RESET}")
                input("Press Enter...")

    # -----------------------------------------------------------------------
    # Advanced wizard
    # -----------------------------------------------------------------------
    @staticmethod
    def advanced_wizard():
        clear_screen()
        logo()
        banner("Advanced Scanner Configuration")
        print(f"{Colors.MUTED}Configure scan options. Leave empty to use defaults.{Colors.RESET}\n")
        target = input(f"{Colors.CYAN}Target(s) (IP/CIDR, required): {Colors.RESET}").strip()
        if not target:
            print(f"{Colors.RED}Target is required.{Colors.RESET}")
            input("Press Enter...")
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
        input(f"{Colors.GREEN}Press Enter to continue...{Colors.RESET}")

    # -----------------------------------------------------------------------
    # Raw CLI arguments entry
    # -----------------------------------------------------------------------
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
                return
            run_scan_sync(args.targets, args)
        except SystemExit:
            pass
        finally:
            sys.argv = old_argv
        input(f"{Colors.GREEN}Press Enter to continue...{Colors.RESET}")

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