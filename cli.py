#!/usr/bin/env python3
# =============================================================================
# cli.py – Nemesis Scanner | Interactive Menu + CLI + Auto-Save in reports/
# UI/UX inspired by Project Nemesis main dashboard
# Requires: core.py (NemesisScanner, Reporter, VERSION) – Monster Edition v3.0.0
# =============================================================================
import sys
import os
import asyncio
import argparse
import subprocess
import time
from datetime import datetime
from pathlib import Path
from typing import List, Optional

# ---------- Import core with fallback for various project structures ----------
try:
    from core import NemesisScanner, Reporter, VERSION as CORE_VERSION
except ImportError:
    try:
        from core.core import NemesisScanner, Reporter, VERSION as CORE_VERSION
    except ImportError:
        import core as core_mod
        NemesisScanner = core_mod.NemesisScanner
        Reporter = core_mod.Reporter
        CORE_VERSION = core_mod.VERSION

# ---------------------------------------------------------------------------
# Terminal colour & UI helpers
# ---------------------------------------------------------------------------
class Colors:
    RED     = "\033[1;31m"
    MUTED   = "\033[0;31m"
    CYAN    = "\033[1;36m"
    YELLOW  = "\033[1;33m"
    GREEN   = "\033[1;32m"
    BOLD    = "\033[1m"
    RESET   = "\033[0m"
    HLINE = "─"
    VLINE = "│"
    TOPL  = "┌"
    TOPR  = "┐"
    BOTL  = "└"
    BOTR  = "┘"

if not sys.stdout.isatty():
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
    print(f"{Colors.MUTED}                 Nemesis Scanner – Monster Edition v{CORE_VERSION}{Colors.RESET}\n")

def pause():
    input(f"\n{Colors.MUTED}Press Enter to return...{Colors.RESET}")

# ---------------------------------------------------------------------------
# Auto-save filename generator
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
            deep_inspect=getattr(scan_args, 'deep_inspect', True),
            skip_ping=getattr(scan_args, 'skip_ping', False),
            ipv6=getattr(scan_args, 'ipv6', False),
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
# Helper to build args namespace
# ---------------------------------------------------------------------------
def build_scan_args(targets: List[str], mode="quick", threads=10, stealth=False,
                    vuln_check=False, nmap_args="", nvd_key=None, vulners_key=None,
                    aggressive=False, turbo=False, fragment=False, source_port=None,
                    spoof_mac=None, decoys=None, ttl=None, auth_check=False,
                    deep_inspect=True, skip_ping=False, ipv6=False,
                    auto_save=False, format="json", output=None):
    args = argparse.Namespace()
    args.targets = targets
    args.mode = mode
    args.threads = threads
    args.stealth = stealth
    args.vuln_check = vuln_check
    args.nmap_args = nmap_args
    args.nvd_key = nvd_key
    args.vulners_key = vulners_key
    args.aggressive = aggressive
    args.turbo = turbo
    args.fragment = fragment
    args.source_port = source_port
    args.spoof_mac = spoof_mac
    args.decoys = decoys
    args.ttl = ttl
    args.auth_check = auth_check
    args.deep_inspect = deep_inspect
    args.skip_ping = skip_ping
    args.ipv6 = ipv6
    args.auto_save = auto_save
    args.format = format
    args.output = output
    args.verbose = False
    args.email = None
    args.slack = None
    return args

# ---------------------------------------------------------------------------
# Scanner Menu – redesigned with clear categories
# ---------------------------------------------------------------------------
class ScannerMenu:
    """Interactive menu interface for Nemesis Scanner."""

    # --------------------------- main menu ---------------------------------
    @staticmethod
    def main_menu():
        while True:
            clear_screen()
            logo()
            banner("Main Menu")
            print(f"""{Colors.YELLOW}
  [1] Network Discovery & Port Scanning
  [2] Vulnerability Assessment & Exploit Detection
  [3] Full Attack Surface Analysis (Network + Vulns)
  [4] About
  [5] Update & Maintenance
  [0] Exit / Return to Dashboard
{Colors.RESET}""")
            choice = input(f"{Colors.CYAN}Choice: {Colors.RESET}").strip()
            if choice == "1":
                ScannerMenu.network_scan_menu()
            elif choice == "2":
                ScannerMenu.vuln_scan_menu()
            elif choice == "3":
                ScannerMenu.combined_scan_menu()
            elif choice == "4":
                ScannerMenu.about()
            elif choice == "5":
                ScannerMenu.update()
            elif choice == "0":
                return
            else:
                print(f"{Colors.RED}Invalid option.{Colors.RESET}")
                pause()

    # --------------------------- about ------------------------------------
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

    # --------------------------- update -----------------------------------
    @staticmethod
    def update():
        while True:
            clear_screen()
            logo()
            banner("Update & Maintenance")
            print(f"{Colors.CYAN}Current version: {Colors.BOLD}{CORE_VERSION}{Colors.RESET}\n")
            print(f"""{Colors.YELLOW}
  [1] Check for updates (git pull)
  [2] Install/update Python dependencies (pip install -r requirements.txt)
  [3] Force reinstall all dependencies
  [4] View installed packages
  [0] Back
{Colors.RESET}""")
            
            choice = input(f"{Colors.CYAN}Choice: {Colors.RESET}").strip()
            
            if choice == "0":
                break
            
            elif choice == "1":
                # Git pull update
                print()
                if os.path.isdir('.git'):
                    print(f"{Colors.CYAN}Local Git repository detected.{Colors.RESET}")
                    print(f"{Colors.CYAN}Fetching latest changes...{Colors.RESET}")
                    
                    try:
                        # First fetch to check for updates
                        result = subprocess.run(['git', 'fetch'], capture_output=True, text=True)
                        if result.returncode != 0:
                            print(f"{Colors.RED}Failed to fetch from remote.{Colors.RESET}")
                            print(result.stderr)
                            pause()
                            continue
                        
                        # Check if we're behind
                        status = subprocess.run(['git', 'status', '-uno'], capture_output=True, text=True)
                        if 'Your branch is behind' in status.stdout:
                            print(f"{Colors.YELLOW}Updates available!{Colors.RESET}")
                            if input(f"{Colors.YELLOW}Run 'git pull' to update? [y/N]: {Colors.RESET}").strip().lower() in ("y","yes"):
                                print(f"{Colors.CYAN}Running git pull...{Colors.RESET}")
                                result = subprocess.run(['git', 'pull'], capture_output=True, text=True)
                                if result.returncode == 0:
                                    print(f"{Colors.GREEN}✓ Update successful!{Colors.RESET}")
                                    print(result.stdout)
                                    print(f"\n{Colors.YELLOW}Please restart the tool to use the new version.{Colors.RESET}")
                                    
                                    # Offer to update requirements
                                    if os.path.exists("requirements.txt"):
                                        if input(f"{Colors.CYAN}Update Python dependencies too? [Y/n]: {Colors.RESET}").strip().lower() not in ("n","no"):
                                            print(f"{Colors.CYAN}Updating dependencies...{Colors.RESET}")
                                            ret = os.system(f"{sys.executable} -m pip install -r requirements.txt")
                                            if ret == 0:
                                                print(f"{Colors.GREEN}✓ Dependencies updated.{Colors.RESET}")
                                            else:
                                                print(f"{Colors.RED}Dependency update failed.{Colors.RESET}")
                                else:
                                    print(f"{Colors.RED}Update failed:{Colors.RESET}")
                                    print(result.stderr)
                            else:
                                print(f"{Colors.MUTED}Update skipped.{Colors.RESET}")
                        elif 'Your branch is up to date' in status.stdout:
                            print(f"{Colors.GREEN}✓ You are already up to date!{Colors.RESET}")
                        else:
                            print(f"{Colors.YELLOW}Unable to determine update status.{Colors.RESET}")
                            print(f"{Colors.MUTED}Try manual: git pull{Colors.RESET}")
                    except Exception as e:
                        print(f"{Colors.RED}Error running git: {e}{Colors.RESET}")
                else:
                    print(f"{Colors.MUTED}No .git folder found.{Colors.RESET}")
                    print(f"{Colors.CYAN}To get updates, clone the repository:{Colors.RESET}")
                    print(f"  {Colors.BOLD}git clone https://github.com/ErfanNahidi/Nemesis-Scanner.git{Colors.RESET}")
                    print(f"{Colors.MUTED}Or download the latest release from GitHub.{Colors.RESET}")
                pause()
            
            elif choice == "2":
                # Install/update dependencies
                print()
                if os.path.exists("requirements.txt"):
                    print(f"{Colors.CYAN}Installing/updating dependencies from requirements.txt...{Colors.RESET}")
                    try:
                        result = subprocess.run(
                            [sys.executable, '-m', 'pip', 'install', '-r', 'requirements.txt'],
                            capture_output=True, text=True
                        )
                        if result.returncode == 0:
                            print(f"{Colors.GREEN}✓ Dependencies installed/updated successfully!{Colors.RESET}")
                            # Show what was installed
                            for line in result.stdout.split('\n'):
                                if 'Successfully installed' in line:
                                    print(f"  {Colors.CYAN}{line}{Colors.RESET}")
                        else:
                            print(f"{Colors.RED}Installation failed:{Colors.RESET}")
                            print(result.stderr)
                            print(f"\n{Colors.YELLOW}Tip: You may need to run with sudo or use a virtual environment.{Colors.RESET}")
                    except Exception as e:
                        print(f"{Colors.RED}Error running pip: {e}{Colors.RESET}")
                else:
                    print(f"{Colors.RED}requirements.txt not found in current directory.{Colors.RESET}")
                    print(f"{Colors.MUTED}Make sure you're in the project root directory.{Colors.RESET}")
                pause()
            
            elif choice == "3":
                # Force reinstall
                print()
                if os.path.exists("requirements.txt"):
                    print(f"{Colors.YELLOW}Force reinstalling all dependencies...{Colors.RESET}")
                    if input(f"{Colors.YELLOW}This will reinstall all packages. Continue? [y/N]: {Colors.RESET}").strip().lower() in ("y","yes"):
                        try:
                            result = subprocess.run(
                                [sys.executable, '-m', 'pip', 'install', '--force-reinstall', '-r', 'requirements.txt'],
                                capture_output=True, text=True
                            )
                            if result.returncode == 0:
                                print(f"{Colors.GREEN}✓ All dependencies reinstalled successfully!{Colors.RESET}")
                            else:
                                print(f"{Colors.RED}Reinstallation failed:{Colors.RESET}")
                                print(result.stderr)
                        except Exception as e:
                            print(f"{Colors.RED}Error running pip: {e}{Colors.RESET}")
                    else:
                        print(f"{Colors.MUTED}Reinstall cancelled.{Colors.RESET}")
                else:
                    print(f"{Colors.RED}requirements.txt not found.{Colors.RESET}")
                pause()
            
            elif choice == "4":
                # View installed packages
                print()
                print(f"{Colors.CYAN}Installed Python packages:{Colors.RESET}")
                try:
                    result = subprocess.run(
                        [sys.executable, '-m', 'pip', 'list'],
                        capture_output=True, text=True
                    )
                    print(result.stdout)
                except Exception as e:
                    print(f"{Colors.RED}Error listing packages: {e}{Colors.RESET}")
                pause()
            
            else:
                print(f"{Colors.RED}Invalid option.{Colors.RESET}")
                time.sleep(0.5)

    # -------------------------------------------------------------------
    # Network scan presets
    # -------------------------------------------------------------------
    @staticmethod
    def network_scan_menu():
        while True:
            clear_screen()
            logo()
            banner("Network Discovery & Port Scanning")
            print(f"""{Colors.YELLOW}
  [1] Quick TCP scan (common ports, fast)
  [2] Full TCP scan (1-65535, thorough)
  [3] Turbo scan (top critical ports, ultra-fast)
  [4] Stealth SYN scan (slow, firewall evasion)
  [5] IPv6 network scan
  [6] Custom scan (add your own Nmap arguments)
  [0] Back to Main Menu
{Colors.RESET}""")
            choice = input(f"{Colors.CYAN}Choice: {Colors.RESET}").strip()
            if choice in ("1","2","3","4","5","6"):
                target = input(f"{Colors.CYAN}Target (IP or CIDR): {Colors.RESET}").strip()
                if not target:
                    print(f"{Colors.RED}Target required!{Colors.RESET}")
                    pause()
                    continue
                args = None
                if choice == "1":
                    args = build_scan_args([target], mode="quick", threads=10,
                                           vuln_check=False, auto_save=False)
                elif choice == "2":
                    args = build_scan_args([target], mode="full", threads=10,
                                           vuln_check=False, auto_save=False)
                elif choice == "3":
                    args = build_scan_args([target], mode="turbo", turbo=True,
                                           vuln_check=False, auto_save=False)
                elif choice == "4":
                    args = build_scan_args([target], mode="quick", stealth=True,
                                           fragment=True, vuln_check=False,
                                           auto_save=False)
                elif choice == "5":
                    args = build_scan_args([target], mode="quick", ipv6=True,
                                           vuln_check=False, auto_save=False)
                elif choice == "6":
                    extra = input(f"{Colors.CYAN}Extra Nmap arguments: {Colors.RESET}").strip()
                    args = build_scan_args([target], mode="custom", nmap_args=extra,
                                           vuln_check=False, auto_save=False)
                auto = input(f"{Colors.CYAN}Auto-save report? [y/N]: {Colors.RESET}").strip().lower()
                if auto == "y":
                    args.auto_save = True
                    fmt = input(f"{Colors.CYAN}  Format (json/csv/html) [json]: {Colors.RESET}").strip().lower()
                    args.format = fmt if fmt in ("json","csv","html") else "json"
                run_scan_sync(args.targets, args)
                pause()
            elif choice == "0":
                break
            else:
                print(f"{Colors.RED}Invalid option.{Colors.RESET}")
                pause()

    # -------------------------------------------------------------------
    # Vulnerability scan presets
    # -------------------------------------------------------------------
    @staticmethod
    def vuln_scan_menu():
        while True:
            clear_screen()
            logo()
            banner("Vulnerability Assessment & Exploit Detection")
            print(f"""{Colors.YELLOW}
  [1] Quick security scan (fast, essential ports, NSE scripts)
  [2] Common security scan (balanced, top 1000 ports, version & NSE)
  [3] Deep vulnerability scan (thorough, online CVE lookups, exploit search)
  [4] Web application security scan (HTTP headers, TLS, SSL issues)
  [5] Active Directory / Kerberos focused scan
  [6] Custom vulnerability scan (choose mode and options)
  [0] Back to Main Menu
{Colors.RESET}""")
            choice = input(f"{Colors.CYAN}Choice: {Colors.RESET}").strip()
            if choice in ("1","2","3","4","5","6"):
                target = input(f"{Colors.CYAN}Target (IP or hostname): {Colors.RESET}").strip()
                if not target:
                    print(f"{Colors.RED}Target required!{Colors.RESET}")
                    pause()
                    continue
                args = None
                if choice == "1":
                    args = build_scan_args([target], mode="quick", vuln_check=True,
                                           threads=10, auto_save=False)
                elif choice == "2":
                    args = build_scan_args([target], mode="common", vuln_check=True,
                                           threads=10, auto_save=False)
                elif choice == "3":
                    nvd = input(f"{Colors.CYAN}NVD API key (optional): {Colors.RESET}").strip() or None
                    vulners = input(f"{Colors.CYAN}Vulners API key (optional): {Colors.RESET}").strip() or None
                    args = build_scan_args([target], mode="common", vuln_check=True,
                                           nvd_key=nvd, vulners_key=vulners,
                                           deep_inspect=True, auto_save=False)
                elif choice == "4":
                    args = build_scan_args([target], mode="quick", vuln_check=False,
                                           deep_inspect=True, auto_save=False)
                elif choice == "5":
                    extra = input(f"{Colors.CYAN}Additional Nmap args (or Enter): {Colors.RESET}").strip()
                    args = build_scan_args([target], mode="common", vuln_check=True,
                                           nmap_args=extra, auto_save=False)
                elif choice == "6":
                    mode = input(f"{Colors.CYAN}Mode (quick/common/full) [quick]: {Colors.RESET}").strip().lower() or "quick"
                    vuln = input(f"{Colors.CYAN}Use NSE vuln scripts? [Y/n]: {Colors.RESET}").strip().lower() != "n"
                    nvd = input(f"{Colors.CYAN}NVD API key (optional): {Colors.RESET}").strip() or None
                    vulners = input(f"{Colors.CYAN}Vulners API key (optional): {Colors.RESET}").strip() or None
                    deep = input(f"{Colors.CYAN}Enable deep active inspection? [Y/n]: {Colors.RESET}").strip().lower() != "n"
                    args = build_scan_args([target], mode=mode, vuln_check=vuln,
                                           nvd_key=nvd, vulners_key=vulners,
                                           deep_inspect=deep, auto_save=False)
                auto = input(f"{Colors.CYAN}Auto-save report? [y/N]: {Colors.RESET}").strip().lower()
                if auto == "y":
                    args.auto_save = True
                    fmt = input(f"{Colors.CYAN}  Format (json/csv/html) [json]: {Colors.RESET}").strip().lower()
                    args.format = fmt if fmt in ("json","csv","html") else "json"
                run_scan_sync(args.targets, args)
                pause()
            elif choice == "0":
                break
            else:
                print(f"{Colors.RED}Invalid option.{Colors.RESET}")
                pause()

    # -------------------------------------------------------------------
    # Combined network + vulnerability scan
    # -------------------------------------------------------------------
    @staticmethod
    def combined_scan_menu():
        while True:
            clear_screen()
            logo()
            banner("Full Attack Surface Analysis")
            print(f"""{Colors.YELLOW}
  [1] Standard full scan (all TCP, version detection, vulnerability scripts)
  [2] Aggressive full scan (fast, with online CVE lookups)
  [3] Stealth full scan (slow, evasive, with vulnerability checks)
  [4] Turbo combo (critical ports + vulnerability detection)
  [0] Back to Main Menu
{Colors.RESET}""")
            choice = input(f"{Colors.CYAN}Choice: {Colors.RESET}").strip()
            if choice in ("1","2","3","4"):
                target = input(f"{Colors.CYAN}Target (IP or CIDR): {Colors.RESET}").strip()
                if not target:
                    print(f"{Colors.RED}Target required!{Colors.RESET}")
                    pause()
                    continue
                args = None
                if choice == "1":
                    args = build_scan_args([target], mode="full", vuln_check=True,
                                           deep_inspect=True, threads=10,
                                           auto_save=False)
                elif choice == "2":
                    nvd = input(f"{Colors.CYAN}NVD API key (optional): {Colors.RESET}").strip() or None
                    vulners = input(f"{Colors.CYAN}Vulners API key (optional): {Colors.RESET}").strip() or None
                    args = build_scan_args([target], mode="full", vuln_check=True,
                                           aggressive=True, nvd_key=nvd,
                                           vulners_key=vulners, deep_inspect=True,
                                           auto_save=False)
                elif choice == "3":
                    args = build_scan_args([target], mode="full", vuln_check=True,
                                           stealth=True, fragment=True,
                                           deep_inspect=False, auto_save=False)
                elif choice == "4":
                    args = build_scan_args([target], mode="turbo", turbo=True,
                                           vuln_check=True, deep_inspect=True,
                                           auto_save=False)
                auto = input(f"{Colors.CYAN}Auto-save report? [y/N]: {Colors.RESET}").strip().lower()
                if auto == "y":
                    args.auto_save = True
                    fmt = input(f"{Colors.CYAN}  Format (json/csv/html) [json]: {Colors.RESET}").strip().lower()
                    args.format = fmt if fmt in ("json","csv","html") else "json"
                run_scan_sync(args.targets, args)
                pause()
            elif choice == "0":
                break
            else:
                print(f"{Colors.RED}Invalid option.{Colors.RESET}")
                pause()

    # -------------------------------------------------------------------
    # Advanced wizard (kept for raw arguments)
    # -------------------------------------------------------------------
    @staticmethod
    def raw_args():
        clear_screen()
        logo()
        banner("Enter Raw Scanner Arguments")
        print(f"{Colors.MUTED}Type arguments as you would on command line.{Colors.RESET}")
        print(f"{Colors.MUTED}Example: 192.168.1.1 -m quick --vuln-check --auto-save{Colors.RESET}\n")
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
    parser.add_argument("--turbo", action="store_true")
    parser.add_argument("--fragment", action="store_true")
    parser.add_argument("--source-port", type=int)
    parser.add_argument("--spoof-mac")
    parser.add_argument("--decoys")
    parser.add_argument("--ttl", type=int)
    parser.add_argument("--auth-check", action="store_true")
    parser.add_argument("--auto-save", action="store_true")
    parser.add_argument("--deep-inspect", action="store_true", default=True)
    parser.add_argument("--no-deep-inspect", action="store_false", dest="deep_inspect")
    parser.add_argument("--skip-ping", action="store_true", default=False)
    parser.add_argument("--ipv6", action="store_true", default=False)
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