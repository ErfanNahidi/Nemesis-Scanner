#!/usr/bin/env python3
# =============================================================================
# core.py – Nemesis Scanner | Shadow Edition v2.1.0
# Author: Erfan Nahidi
# Use only on systems you own or have explicit written permission to test.
# =============================================================================

import sys
import os
import json
import csv
import logging
import asyncio
import concurrent.futures
import time
import random
import socket
import struct
import ssl
import smtplib
from email.message import EmailMessage
from pathlib import Path
from typing import Dict, List, Optional, Tuple, Union
from collections import defaultdict
from datetime import datetime

import nmap                     # python-nmap
import requests                 # for APIs
from colorama import Fore, Style, init

# Optional imports
try:
    import yaml
    HAS_YAML = True
except ImportError:
    HAS_YAML = False

try:
    from jinja2 import Template
    HAS_JINJA = True
except ImportError:
    HAS_JINJA = False

# Initialize colorama
init(autoreset=True)

# ---------------------------------------------------------------------------
# Constants & Configuration
# ---------------------------------------------------------------------------
VERSION = "2.1.0"

# API endpoints
NVD_API_BASE = "https://services.nvd.nist.gov/rest/json/cves/2.0"
VULNERS_API = "https://vulners.com/api/v3/search/lucene/"
EXPLOITDB_SEARCH = "https://www.exploit-db.com/search?cve="

# Attack Surface Modules (service-based, OS-agnostic)
MODULE_PORTS = {
    "DHCP Attacker":       {"ports": [67, 68],          "proto": "udp"},
    "DNS Attacker":        {"ports": [53],              "proto": "tcp"},
    "AD Attacker":         {"ports": [389,636,88,464,3268,3269,135,139],"proto": "tcp"},
    "SMB Attacker":        {"ports": [445,139],         "proto": "tcp"},
    "SNMP Sniffinger":     {"ports": [161,162],         "proto": "udp"},
    "DoS Amplification":   {"ports": [19,123,520,1900,11211],"proto": "udp"},
    "Install & Update":    {"ports": [8530,8531,5985,5986,3389,80,443],"proto": "tcp"},
    "Print Spooler":       {"ports": [515, 9100],       "proto": "tcp"},
    "LDAP Signing":        {"ports": [389, 636],        "proto": "tcp"},
    "MSSQL Attacker":      {"ports": [1433],            "proto": "tcp"},
    "Kerberos Attacker":   {"ports": [88],              "proto": "tcp"},
    "WinRM Attacker":      {"ports": [5985,5986],       "proto": "tcp"},
    "RDP Attacker":        {"ports": [3389],            "proto": "tcp"},
    "FTP / SSH Brute":     {"ports": [21,22],           "proto": "tcp"},
    "HTTP(S) Exploitation": {"ports": [80,443,8080,8443], "proto": "tcp"},
}

# Port lists
QUICK_TCP = [21,22,23,25,53,80,88,110,111,135,139,143,389,443,445,464,587,593,636,
             993,995,1433,1723,3268,3269,3306,3389,5432,5900,5985,5986,8080,8443,8530,8531,
             9090,10000]
FULL_TCP_RANGE = (1, 65535)
FULL_UDP_PORTS = [53,67,68,69,123,135,137,138,139,161,162,445,500,514,520,1194,1900,4500,5353,11211]

# Turbo scan ports (top critical ports, cross-platform)
TURBO_TCP = [21,22,80,443,445,135,139,3389,5985,5986,8080,8443,1433,3306,5900]
TURBO_UDP = [53,161,162,67,68,123]

# Static vulnerability DB (extended)
STATIC_VULNS = {
    ("smb", "1.0"): ["MS17-010 (EternalBlue) – RCE via SMBv1"],
    ("smb", "3.1.1"): ["CVE-2020-0796 (SMBGhost) – RCE"],
    ("smb", "2.0"): ["CVE-2017-0144 (EternalChampion/EternalSynergy)"],
    ("rdp", ""): ["CVE-2019-0708 (BlueKeep) – RCE", "CVE-2020-0610 – RCE"],
    ("dns", ""): ["CVE-2020-1350 (SigRed) – RCE"],
    ("snmp", ""): ["Default community strings – info disclosure"],
    ("winrm", ""): ["CVE-2015-0010 – auth bypass (older versions)"],
    ("mssql", ""): ["CVE-2020-0618 – RCE (Reporting Services)", "CVE-2019-1068 – SQL Server RCE"],
    ("http", "apache"): ["CVE-2021-41773 (Path Traversal/RCE in Apache 2.4.49)"],
    ("http", "iis"): ["CVE-2017-7269 (IIS 6.0 RCE)", "CVE-2015-1635 (HTTP.sys RCE)"],
}

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------
logging.basicConfig(level=logging.INFO, format='%(asctime)s [%(levelname)s] %(message)s')
logger = logging.getLogger("NemesisScanner")

# ---------------------------------------------------------------------------
# API Helpers
# ---------------------------------------------------------------------------
def lookup_cves_nvd(service: str, product: str, version: str, api_key: str = None) -> List[str]:
    """Query NVD for CVEs."""
    query_parts = []
    if product: query_parts.append(product)
    if version: query_parts.append(version)
    if service and service not in query_parts: query_parts.append(service)
    if not query_parts: return []
    keyword = " ".join(query_parts)
    headers = {}
    if api_key: headers["apiKey"] = api_key
    params = {"keywordSearch": keyword, "resultsPerPage": 5}
    try:
        resp = requests.get(NVD_API_BASE, headers=headers, params=params, timeout=15)
        if resp.status_code == 200:
            data = resp.json()
            cves = []
            for vuln in data.get("vulnerabilities", []):
                cve_id = vuln["cve"]["id"]
                desc = vuln["cve"]["descriptions"][0]["value"][:120]
                cves.append(f"{cve_id} – {desc}")
            return cves
        else:
            logger.warning(f"NVD API status {resp.status_code}")
    except Exception as e:
        logger.error(f"NVD lookup error: {e}")
    return []

def search_exploits_vulners(query: str, api_key: str = None) -> List[Dict]:
    """Search Vulners API for exploits matching a CVE or keyword."""
    if not api_key:
        return []
    headers = {"Content-Type": "application/json"}
    payload = {
        "query": query,
        "type": "exploit",
        "apiKey": api_key,
        "size": 5
    }
    try:
        resp = requests.post(VULNERS_API, headers=headers, json=payload, timeout=10)
        if resp.status_code == 200:
            return resp.json().get("data", {}).get("search", [])
        else:
            logger.warning(f"Vulners API error: {resp.status_code}")
    except Exception as e:
        logger.error(f"Vulners lookup error: {e}")
    return []

def get_exploitdb_links(cve_id: str) -> str:
    """Return a search URL for Exploit-DB."""
    return f"{EXPLOITDB_SEARCH}{cve_id}"

# ---------------------------------------------------------------------------
# Core Scanner Class – Cross-Platform, Ultra-Fast
# ---------------------------------------------------------------------------
class NemesisScanner:
    """Nemesis Scanner – deep service & vulnerability discovery for any OS."""

    def __init__(
        self,
        target: str,
        scan_mode: str = "quick",
        threads: int = 10,
        stealth: bool = False,
        vuln_check: bool = False,
        nmap_args_extra: str = "",
        nvd_api_key: str = None,
        vulners_api_key: str = None,
        aggressive: bool = False,
        turbo: bool = False,
        fragment: bool = False,
        source_port: int = None,
        spoof_mac: str = None,
        decoys: str = None,
        ttl: int = None,
        auth_check: bool = False,
    ):
        self.target = target
        self.threads = threads
        self.stealth = stealth
        self.vuln_check = vuln_check
        self.nmap_extra = nmap_args_extra
        self.nvd_api_key = nvd_api_key
        self.vulners_api_key = vulners_api_key
        self.aggressive = aggressive
        self.fragment = fragment
        self.source_port = source_port
        self.spoof_mac = spoof_mac
        self.decoys = decoys
        self.ttl = ttl
        self.auth_check = auth_check

        # Turbo mode overrides scan_mode and forces insane speed
        self.turbo = turbo
        if turbo:
            self.scan_mode = "turbo"
        else:
            self.scan_mode = scan_mode.lower()

        self.nm = nmap.PortScanner()
        self.scan_data = None
        self.os_info = "Unknown"

    def _build_port_spec(self) -> str:
        if self.scan_mode == "turbo":
            tcp = TURBO_TCP
            udp = TURBO_UDP
            return f"T:{','.join(map(str,tcp))},U:{','.join(map(str,udp))}"
        elif self.scan_mode == "quick":
            tcp = QUICK_TCP
            udp = [53,161,162,67,68,123,520,1900,11211]
            return f"T:{','.join(map(str,tcp))},U:{','.join(map(str,udp))}"
        elif self.scan_mode == "common":
            udp = FULL_UDP_PORTS
            return f"T:1-1000,U:{','.join(map(str,udp))}"
        elif self.scan_mode == "full":
            udp = FULL_UDP_PORTS
            return f"T:1-65535,U:{','.join(map(str,udp))}"
        elif self.scan_mode == "custom":
            return ""  # rely on nmap_extra
        else:
            raise ValueError(f"Unknown scan mode: {self.scan_mode}")

    def _nmap_arguments(self) -> str:
        port_spec = self._build_port_spec()
        args = []
        if port_spec:
            args.append(f"-p {port_spec}")

        # ---------- Turbo mode: insane speed ----------
        if self.turbo:
            args.append("-T5 --min-rate 10000 --max-rtt-timeout 100ms")
            args.append("--max-retries 0 --host-timeout 30s")
            args.append("-Pn -n")   # no ping, no DNS
            args.append("--min-parallelism 100 --max-parallelism 256")
            args.append("--max-scan-delay 0")
            args.append("-sS")      # SYN scan (fast)
            if self.vuln_check:
                args.append("-sV --version-intensity 2")
                args.append("--script vulners,vuln --script-timeout 30s")
            if self.nmap_extra:
                args.append(self.nmap_extra)
            return " ".join(args)

        # ---------- Standard modes ----------
        if self.scan_mode in ("common", "full", "custom"):
            args.append("-sV --version-intensity 5")
            if self.vuln_check:
                args.append("--script vulners,vuln,smb-vuln-*,rdp-vuln-*,http-vuln-*,ssl-*")
            args.append("-O --osscan-guess")

        # Timing & aggressiveness
        if self.stealth:
            args.append("-T2 --max-retries 2 --scan-delay 500ms --randomize-hosts")
            self.threads = min(self.threads, 2)
        elif self.aggressive:
            args.append("-T5 --min-rate 2000 --host-timeout 1m --max-rtt-timeout 500ms")
            args.append("--max-scan-delay 0")
        else:
            if self.scan_mode == "quick":
                args.append("-T5 --min-rate 1500 --host-timeout 2m")
            else:
                args.append("-T4 --min-rate 800 --host-timeout 8m")

        # Evasion & advanced options
        if self.fragment:
            args.append("-f")
        if self.source_port:
            args.append(f"--source-port {self.source_port}")
        if self.spoof_mac:
            args.append(f"--spoof-mac {self.spoof_mac}")
        if self.decoys:
            args.append(f"-D {self.decoys}")
        if self.ttl:
            args.append(f"--ttl {self.ttl}")

        if self.nmap_extra:
            args.append(self.nmap_extra)

        return " ".join(args)

    async def run_scan_async(self):
        loop = asyncio.get_running_loop()
        nmap_args = self._nmap_arguments()
        logger.info(f"Scanning {self.target} with args: {nmap_args}")
        with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
            await loop.run_in_executor(
                pool,
                lambda: self.nm.scan(self.target, arguments=nmap_args, sudo=True)
            )
        if self.target in self.nm.all_hosts():
            self.scan_data = self.nm[self.target]
            os_matches = self.scan_data.get("osmatch", [])
            if os_matches:
                self.os_info = os_matches[0]["name"]
            logger.info(f"Scan complete. OS: {self.os_info}")
        else:
            logger.error(f"Host {self.target} not reachable.")
            self.scan_data = None

    def extract_services(self) -> List[Dict]:
        if not self.scan_data:
            return []
        tcp = self.scan_data.get("tcp", {})
        udp = self.scan_data.get("udp", {})
        services = []
        for proto, port_dict in [("tcp", tcp), ("udp", udp)]:
            for port, info in port_dict.items():
                if info["state"] in ("open", "open|filtered"):
                    services.append({
                        "port": port,
                        "proto": proto,
                        "name": info["name"],
                        "product": info.get("product", ""),
                        "version": info.get("version", ""),
                        "extrainfo": info.get("extrainfo", ""),
                        "script": info.get("script", {}),
                    })
        return services

    def get_static_vulns(self, service: Dict) -> List[str]:
        name = service["name"].lower()
        product = service.get("product", "").lower()
        version = service.get("version", "").lower()
        found = []
        for (svc_pat, ver_pat), vulns in STATIC_VULNS.items():
            if svc_pat in name or (product and svc_pat in product):
                if ver_pat == "" or (version and ver_pat in version):
                    found.extend(vulns)
        return found

    async def _correlate_cves(self, service: Dict) -> List[Dict]:
        cves = []
        static_vulns = self.get_static_vulns(service)
        import re
        for v in static_vulns:
            cve_match = re.search(r'(CVE-\d{4}-\d{4,})', v)
            cve_id = cve_match.group(1) if cve_match else ""
            cves.append({"cve": cve_id, "description": v, "exploits": []})

        if self.vuln_check:
            live_cves = await asyncio.get_event_loop().run_in_executor(
                None,
                lookup_cves_nvd,
                service["name"],
                service.get("product", ""),
                service.get("version", ""),
                self.nvd_api_key,
            )
            for lcve in live_cves:
                cve_id = lcve.split(" – ")[0] if " – " in lcve else ""
                desc = lcve.split(" – ", 1)[1] if " – " in lcve else lcve
                if not any(c["cve"] == cve_id for c in cves):
                    cves.append({"cve": cve_id, "description": desc, "exploits": []})

        for cve_entry in cves:
            if cve_entry["cve"] and self.vulners_api_key:
                exploits = await asyncio.get_event_loop().run_in_executor(
                    None,
                    search_exploits_vulners,
                    cve_entry["cve"],
                    self.vulners_api_key,
                )
                cve_entry["exploits"] = [{
                    "title": e.get("title", ""),
                    "url": e.get("href", ""),
                    "type": e.get("type", ""),
                } for e in exploits]
            cve_entry["exploitdb_url"] = get_exploitdb_links(cve_entry["cve"])

        return cves

    async def correlate_vulns(self, services: List[Dict]) -> Dict[str, List[Dict]]:
        vuln_map = {}
        for svc in services:
            key = f"{svc['proto']}/{svc['port']} {svc['name']} {svc['product']} {svc['version']}".strip()
            vulns = await self._correlate_cves(svc)
            for script_name, output in svc.get("script", {}).items():
                if "vuln" in script_name.lower() and output:
                    vulns.append({
                        "cve": "",
                        "description": f"Script {script_name}: {output.strip()[:200]}",
                        "exploits": [],
                        "exploitdb_url": ""
                    })
            if vulns:
                vuln_map[key] = vulns
        return vuln_map

    def module_classification(self, services: List[Dict]) -> Dict[str, List[str]]:
        modules = defaultdict(list)
        for svc in services:
            port = svc["port"]
            proto = svc["proto"]
            for mod, info in MODULE_PORTS.items():
                if info["proto"] == proto and port in info["ports"]:
                    service_str = f"{proto}/{port} {svc['name']} {svc['product']} {svc['version']}".strip()
                    modules[mod].append(service_str)
        return modules

    async def full_analysis(self):
        await self.run_scan_async()
        if not self.scan_data:
            return None
        services = self.extract_services()
        vulns = await self.correlate_vulns(services)
        modules = self.module_classification(services)
        return {
            "target": self.target,
            "os": self.os_info,
            "timestamp": datetime.now().isoformat(),
            "services": [f"{s['proto']}/{s['port']} {s['name']} {s['product']} {s['version']}".strip()
                         for s in services],
            "modules": modules,
            "vulnerabilities": vulns,
            "raw_services": services,
        }

# ---------------------------------------------------------------------------
# Reporter – Multi-format output
# ---------------------------------------------------------------------------
class Reporter:
    @staticmethod
    def console_report(data: dict, verbose: bool = False):
        print(Fore.CYAN + "="*70)
        print(Fore.YELLOW + f"  Scan Report for {data['target']}")
        print(Fore.YELLOW + f"  OS: {data.get('os', 'Unknown')} | Time: {data['timestamp']}")
        print(Fore.CYAN + "="*70 + Style.RESET_ALL)

        print(Fore.GREEN + "\n[Services]")
        for s in data["services"]:
            print(f"  {s}")
        if not data["services"]:
            print("  No open services found.")

        print(Fore.GREEN + "\n[Module Classification]")
        if data["modules"]:
            for mod, svcs in data["modules"].items():
                if svcs:
                    print(Fore.MAGENTA + f"  {mod}:")
                    for s in svcs:
                        print(f"    - {s}")
        else:
            print("  No modules matched.")

        if data.get("vulnerabilities"):
            print(Fore.RED + "\n[Vulnerabilities & Exploits]")
            for svc, vulns in data["vulnerabilities"].items():
                print(f"  {svc}:")
                for v in vulns:
                    print(Fore.RED + f"    [!] {v.get('description', '')}")
                    if v.get("cve"):
                        print(Fore.YELLOW + f"        CVE: {v['cve']}  | Exploit-DB: {v.get('exploitdb_url','')}")
                    for exp in v.get("exploits", []):
                        print(Fore.MAGENTA + f"        Exploit: {exp['title']} ({exp['url']})")

    @staticmethod
    def json_report(data: dict, output_path: str):
        with open(output_path, "w") as f:
            json.dump(data, f, indent=2, default=str)
        logger.info(f"JSON report saved to {output_path}")

    @staticmethod
    def csv_report(data: dict, output_path: str):
        with open(output_path, "w", newline="") as f:
            writer = csv.writer(f)
            writer.writerow(["Proto/Port", "Service", "Product", "Version", "CVE", "Description", "Exploit Links"])
            for svc in data.get("raw_services", []):
                key = f"{svc['proto']}/{svc['port']} {svc['name']} {svc.get('product','')} {svc.get('version','')}"
                vulns = data.get("vulnerabilities", {}).get(key.strip(), [])
                if not vulns:
                    writer.writerow([
                        f"{svc['proto']}/{svc['port']}",
                        svc["name"],
                        svc.get("product", ""),
                        svc.get("version", ""),
                        "", "", ""
                    ])
                else:
                    for v in vulns:
                        exploit_links = "; ".join([e["url"] for e in v.get("exploits", [])])
                        writer.writerow([
                            f"{svc['proto']}/{svc['port']}",
                            svc["name"],
                            svc.get("product", ""),
                            svc.get("version", ""),
                            v.get("cve", ""),
                            v.get("description", ""),
                            exploit_links
                        ])
        logger.info(f"CSV report saved to {output_path}")

    @staticmethod
    def html_report(data: dict, output_path: str):
        if not HAS_JINJA:
            logger.warning("Jinja2 not installed, skipping HTML report.")
            return
        template_str = """<!DOCTYPE html>
<html><head><title>Scan Report {{ target }}</title>
<style>body{font-family:Arial;margin:20px;}table{border-collapse:collapse;width:100%;}
th,td{border:1px solid #ddd;padding:8px;}th{background:#4CAF50;color:white;}
.vuln{color:red;}.exploit{color:darkorange;}</style></head><body>
<h1>Scan Report: {{ target }}</h1>
<p>OS: {{ os }} | Time: {{ timestamp }}</p>
<h2>Open Services</h2>
<table><tr><th>Proto/Port</th><th>Service</th><th>Product</th><th>Version</th><th>Vulnerabilities</th></tr>
{% for s in raw_services %}
{% set key = (s.proto~'/'~s.port~' '~s.name~' '~(s.product or '')~' '~(s.version or '')).strip() %}
{% set vlist = vuln_map.get(key, []) %}
{% if vlist %}
  {% for v in vlist %}
  <tr>
    <td>{{ s.proto }}/{{ s.port }}</td>
    <td>{{ s.name }}</td>
    <td>{{ s.product or '' }}</td>
    <td>{{ s.version or '' }}</td>
    <td class="vuln">
      {{ v.description }} ({{ v.cve }})
      <br><span class="exploit">Exploit-DB: <a href="{{ v.exploitdb_url }}">{{ v.exploitdb_url }}</a></span>
      {% for e in v.exploits %}
        <br><a href="{{ e.url }}">{{ e.title }}</a>
      {% endfor %}
    </td>
  </tr>
  {% endfor %}
{% else %}
  <tr>
    <td>{{ s.proto }}/{{ s.port }}</td>
    <td>{{ s.name }}</td>
    <td>{{ s.product or '' }}</td>
    <td>{{ s.version or '' }}</td>
    <td></td>
  </tr>
{% endif %}
{% endfor %}
</table>
<h2>Attack Surface Modules</h2>
{% for mod, svcs in modules.items() %}{% if svcs %}
<h3>{{ mod }}</h3><ul>{% for s in svcs %}<li>{{ s }}</li>{% endfor %}</ul>
{% endif %}{% endfor %}
</body></html>"""
        rendered = Template(template_str).render(
            target=data["target"],
            os=data.get("os", ""),
            timestamp=data["timestamp"],
            raw_services=data.get("raw_services", []),
            modules=data.get("modules", {}),
            vuln_map=data.get("vulnerabilities", {})
        )
        with open(output_path, "w") as f:
            f.write(rendered)
        logger.info(f"HTML report saved to {output_path}")

    @staticmethod
    def send_email(data: dict, smtp_config: dict):
        try:
            msg = EmailMessage()
            msg["Subject"] = f"⚡ Scan Report for {data['target']} – {len(data['vulnerabilities'])} vulns found"
            msg["From"] = smtp_config["from"]
            msg["To"] = smtp_config["to"]
            body = f"OS: {data.get('os')}\n\nServices:\n"
            body += "\n".join(data["services"])
            if data.get("vulnerabilities"):
                body += "\n\nCRITICAL VULNERABILITIES:\n"
                for svc, vulns in data["vulnerabilities"].items():
                    body += f"\n{svc}:\n"
                    for v in vulns:
                        body += f"  - {v['description']} ({v.get('cve','')})\n"
            msg.set_content(body)
            context = ssl.create_default_context()
            with smtplib.SMTP(smtp_config["server"], smtp_config["port"]) as s:
                s.ehlo()
                s.starttls(context=context)
                s.login(smtp_config["user"], smtp_config["password"])
                s.send_message(msg)
            logger.info("Email sent successfully.")
        except Exception as e:
            logger.error(f"Email failed: {e}")

    @staticmethod
    def slack_webhook(data: dict, webhook_url: str):
        blocks = [
            {"type": "section", "text": {"type": "mrkdwn", "text": f"*⚡ Scan Report for {data['target']}*\nOS: {data.get('os')}"}},
            {"type": "divider"},
            {"type": "section", "text": {"type": "mrkdwn", "text": "Services:\n" + "\n".join(f"• {s}" for s in data["services"])}}
        ]
        if data.get("vulnerabilities"):
            vuln_text = "⚠️ *Vulnerabilities:*\n"
            for svc, vulns in list(data["vulnerabilities"].items())[:5]:
                vuln_text += f"\n*{svc}*:\n"
                for v in vulns[:2]:
                    vuln_text += f"  - {v['description']} ({v.get('cve','')})\n"
            blocks.append({"type": "section", "text": {"type": "mrkdwn", "text": vuln_text}})
        payload = {"text": f"Scan complete: {data['target']}", "blocks": blocks}
        try:
            r = requests.post(webhook_url, json=payload, timeout=10)
            if r.status_code == 200:
                logger.info("Slack notification sent.")
            else:
                logger.warning(f"Slack webhook failed: {r.status_code}")
        except Exception as e:
            logger.error(f"Slack error: {e}")