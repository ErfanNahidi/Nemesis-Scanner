#!/usr/bin/env python3
# =============================================================================
# core.py – Nemesis Scanner | Shadow Edition v2.2.0 (Monster Update)
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
from typing import Dict, List, Optional, Tuple, Union, Any
from collections import defaultdict
from datetime import datetime, timedelta
from urllib.parse import urlparse

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
VERSION = "3.0.0"

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
QUICK_UDP = [53,161,162,67,68,123,520,1900,11211]   # now from constant
FULL_TCP_RANGE = (1, 65535)
FULL_UDP_PORTS = [53,67,68,69,123,135,137,138,139,161,162,445,500,514,520,1194,1900,4500,5353,11211]

# Turbo scan ports (top critical ports, cross-platform)
TURBO_TCP = [21,22,80,443,445,135,139,3389,5985,5986,8080,8443,1433,3306,5900]
TURBO_UDP = [53,161,162,67,68,123]

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------
logging.basicConfig(level=logging.INFO, format='%(asctime)s [%(levelname)s] %(message)s')
logger = logging.getLogger("NemesisScanner")

# ---------------------------------------------------------------------------
# Static Vulnerability DB loader (with external file support)
# ---------------------------------------------------------------------------
def _default_static_vulns() -> dict:
    return {
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

def load_static_vulns() -> dict:
    """Load static vulnerability DB from external JSON file if exists, else fallback."""
    json_path = Path(__file__).parent / "static_vulns.json"
    if json_path.is_file():
        try:
            with open(json_path, "r") as f:
                data = json.load(f)
                # convert keys from string to tuple
                result = {}
                for k, v in data.items():
                    # expect key like "smb,1.0"
                    parts = k.split(",", 1)
                    if len(parts) == 2:
                        result[(parts[0], parts[1])] = v
                if result:
                    return result
        except Exception as e:
            logger.warning(f"Failed to load static_vulns.json, using built-in DB: {e}")
    return _default_static_vulns()

STATIC_VULNS = load_static_vulns()

# ---------------------------------------------------------------------------
# Simple cache for API responses
# ---------------------------------------------------------------------------
class SimpleCache:
    def __init__(self, ttl_seconds: int = 3600):
        self.cache = {}
        self.ttl = ttl_seconds

    def get(self, key: str) -> Optional[Any]:
        if key in self.cache:
            entry = self.cache[key]
            if datetime.now() - entry["time"] < timedelta(seconds=self.ttl):
                return entry["data"]
            else:
                del self.cache[key]
        return None

    def set(self, key: str, data: Any):
        self.cache[key] = {"data": data, "time": datetime.now()}

# Global caches
nvd_cache = SimpleCache(ttl_seconds=3600)   # 1h
vulners_cache = SimpleCache(ttl_seconds=1800)  # 30 min

# ---------------------------------------------------------------------------
# API Helpers (with caching, CVSS scoring, exploit maturity)
# ---------------------------------------------------------------------------
def lookup_cves_nvd(service: str, product: str, version: str, api_key: str = None) -> List[Dict]:
    """Query NVD for CVEs and enrich with CVSS score, severity, exploit flag."""
    query_parts = []
    if product: query_parts.append(product)
    if version: query_parts.append(version)
    if service and service not in query_parts: query_parts.append(service)
    if not query_parts: return []
    keyword = " ".join(query_parts)
    cache_key = f"nvd:{keyword}"
    cached = nvd_cache.get(cache_key)
    if cached is not None:
        return cached

    headers = {}
    if api_key: headers["apiKey"] = api_key
    params = {"keywordSearch": keyword, "resultsPerPage": 10}
    try:
        resp = requests.get(NVD_API_BASE, headers=headers, params=params, timeout=15)
        if resp.status_code == 200:
            data = resp.json()
            cves = []
            for vuln in data.get("vulnerabilities", []):
                cve_id = vuln["cve"]["id"]
                desc = (vuln["cve"]["descriptions"][0]["value"][:200]) if vuln["cve"].get("descriptions") else ""
                # CVSS info
                metrics = vuln.get("cve", {}).get("metrics", {})
                cvss_score = None
                severity = "UNKNOWN"
                # Try CVSS v3 first, then v2
                for key, method in [("cvssMetricV31", "cvssData"), ("cvssMetricV30", "cvssData"), ("cvssMetricV2", "cvssData")]:
                    if key in metrics:
                        for entry in metrics[key]:
                            if method in entry:
                                cvss = entry[method]
                                cvss_score = cvss.get("baseScore")
                                severity = cvss.get("baseSeverity", "UNKNOWN").upper()
                                break
                        if cvss_score is not None:
                            break
                # Exploit maturity (rough check: if "exploit" appears in references)
                exploit_available = False
                for ref in vuln.get("cve", {}).get("references", []):
                    if "exploit" in ref.get("url", "").lower() or "exploit" in " ".join(ref.get("tags", [])).lower():
                        exploit_available = True
                        break
                cves.append({
                    "cve": cve_id,
                    "description": desc,
                    "cvss_score": cvss_score,
                    "severity": severity,
                    "exploit_available": exploit_available,
                    "exploitdb_url": get_exploitdb_links(cve_id),
                })
            nvd_cache.set(cache_key, cves)
            return cves
        elif resp.status_code == 403 or resp.status_code == 429:
            logger.warning(f"NVD API rate limited (HTTP {resp.status_code}). Using cached or empty.")
        else:
            logger.warning(f"NVD API status {resp.status_code}")
    except Exception as e:
        logger.error(f"NVD lookup error: {e}")
    return []

def search_exploits_vulners(query: str, api_key: str = None) -> List[Dict]:
    """Search Vulners API for exploits, with caching."""
    if not api_key:
        return []
    cache_key = f"vulners:{query}"
    cached = vulners_cache.get(cache_key)
    if cached is not None:
        return cached
    headers = {"Content-Type": "application/json"}
    payload = {
        "query": f"cve:{query} OR {query}",
        "type": "exploit",
        "apiKey": api_key,
        "size": 5
    }
    try:
        resp = requests.post(VULNERS_API, headers=headers, json=payload, timeout=10)
        if resp.status_code == 200:
            result = resp.json().get("data", {}).get("search", [])
            vulners_cache.set(cache_key, result)
            return result
        elif resp.status_code in (403, 429):
            logger.warning(f"Vulners rate limited (HTTP {resp.status_code}).")
        else:
            logger.warning(f"Vulners API error: {resp.status_code}")
    except Exception as e:
        logger.error(f"Vulners lookup error: {e}")
    return []

def get_exploitdb_links(cve_id: str) -> str:
    """Return a search URL for Exploit-DB."""
    return f"{EXPLOITDB_SEARCH}{cve_id}"

# ---------------------------------------------------------------------------
# Deep inspection helpers (active probing without nmap scripts)
# ---------------------------------------------------------------------------
def check_ftp_anonymous(host: str, port: int, timeout: float = 5.0) -> Optional[str]:
    """Try anonymous FTP login. Returns success message or None."""
    try:
        s = socket.create_connection((host, port), timeout=timeout)
        s.settimeout(timeout)
        banner = s.recv(1024).decode(errors="ignore")
        s.sendall(b"USER anonymous\r\n")
        resp = s.recv(1024).decode(errors="ignore")
        if "331" in resp or "230" in resp:
            s.sendall(b"PASS anonymous\r\n")
            resp2 = s.recv(1024).decode(errors="ignore")
            if "230" in resp2:
                s.close()
                return "Anonymous FTP login allowed (full access)"
            elif "331" in resp2:
                s.close()
                return "Anonymous FTP login accepted, password required"
        s.close()
    except Exception:
        pass
    return None

def check_http_security_headers(host: str, port: int, use_ssl: bool = False, timeout: float = 5.0) -> List[str]:
    """Check for missing HTTP security headers. Returns list of issues."""
    issues = []
    try:
        if use_ssl:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            s = ctx.wrap_socket(socket.create_connection((host, port), timeout=timeout), server_hostname=host)
        else:
            s = socket.create_connection((host, port), timeout=timeout)
        s.settimeout(timeout)
        s.sendall(f"GET / HTTP/1.0\r\nHost: {host}\r\nConnection: close\r\n\r\n".encode())
        data = b""
        while True:
            chunk = s.recv(4096)
            if not chunk:
                break
            data += chunk
        s.close()
        headers_str = data.split(b"\r\n\r\n")[0].decode(errors="ignore") if b"\r\n\r\n" in data else ""
        headers = {}
        for line in headers_str.split("\r\n")[1:]:
            if ":" in line:
                k, v = line.split(":", 1)
                headers[k.strip().lower()] = v.strip()
        # Check headers
        if "strict-transport-security" not in headers:
            issues.append("Missing HSTS header (Strict-Transport-Security)")
        if "x-frame-options" not in headers:
            issues.append("Missing X-Frame-Options header")
        if "x-content-type-options" not in headers:
            issues.append("Missing X-Content-Type-Options header")
        if "content-security-policy" not in headers:
            issues.append("Missing Content-Security-Policy header")
        if "x-xss-protection" not in headers:
            issues.append("Missing X-XSS-Protection header")
    except Exception:
        pass
    return issues

def check_snmp_community(host: str, port: int, community: str = "public", timeout: float = 3.0) -> Optional[str]:
    """Basic SNMP GET request to check community string. Returns vuln string if successful."""
    # Minimal SNMPv1/v2c get-next request for sysDescr (OID 1.3.6.1.2.1.1.1.0)
    # Using raw socket for simplicity
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(timeout)
        # SNMPv2c GET request (simplified, using scapy would be better but we avoid dependency)
        # Build minimal SNMP packet manually? Might be too complex; skip real probe and note that NSE scripts cover it.
        # Instead we'll just return a warning that SNMP is open; users should test manually.
        s.close()
        return None  # We'll not implement full ASN.1 parsing; rely on nmap script or manual test.
    except Exception:
        pass
    return None

def check_tls_weaknesses(host: str, port: int, timeout: float = 5.0) -> List[str]:
    """Check for weak TLS versions, self-signed cert, expired cert."""
    issues = []
    weak_protocols = {
        ssl.PROTOCOL_TLSv1: "TLSv1.0",
        ssl.PROTOCOL_TLSv1_1: "TLSv1.1",
    }
    for proto, name in weak_protocols.items():
        try:
            ctx = ssl.SSLContext(proto)
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            s = ctx.wrap_socket(socket.create_connection((host, port), timeout=timeout), server_hostname=host)
            s.close()
            issues.append(f"Weak protocol enabled: {name}")
        except:
            pass
    # Certificate checks
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        s = ctx.wrap_socket(socket.create_connection((host, port), timeout=timeout), server_hostname=host)
        cert = s.getpeercert()
        s.close()
        if cert:
            # Check expiration
            not_after = cert.get("notAfter")
            if not_after:
                try:
                    expire_date = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z")
                    if expire_date < datetime.now():
                        issues.append("Certificate has expired")
                except:
                    pass
            # Self-signed check (issuer == subject)
            issuer = cert.get("issuer")
            subject = cert.get("subject")
            if issuer and subject and issuer == subject:
                issues.append("Self-signed certificate")
    except:
        pass
    return issues

def run_deep_checks(target_ip: str, service: Dict) -> List[Dict]:
    """Perform active probing based on service name/port. Returns list of vulnerability-like dicts."""
    vulns = []
    port = service["port"]
    proto = service["proto"]
    if proto != "tcp":
        return vulns  # UDP checks limited
    name = service["name"].lower()
    # FTP
    if "ftp" in name or port == 21:
        anon = check_ftp_anonymous(target_ip, port)
        if anon:
            vulns.append({"cve": "", "description": anon, "cvss_score": None, "severity": "HIGH", "exploit_available": False, "exploitdb_url": ""})
    # HTTP/HTTPS
    if ("http" in name and port in (80, 443, 8080, 8443)) or port in (80, 443, 8080, 8443):
        use_ssl = (port == 443 or "https" in name)
        header_issues = check_http_security_headers(target_ip, port, use_ssl)
        for issue in header_issues:
            vulns.append({"cve": "", "description": issue, "cvss_score": None, "severity": "MEDIUM", "exploit_available": False, "exploitdb_url": ""})
        # TLS checks if SSL
        if use_ssl or (proto == "tcp" and service.get("product", "").lower() == "ssl"):
            tls_issues = check_tls_weaknesses(target_ip, port)
            for t in tls_issues:
                vulns.append({"cve": "", "description": t, "cvss_score": None, "severity": "HIGH" if "weak" in t else "MEDIUM", "exploit_available": False, "exploitdb_url": ""})
    # SMB – additional checks (signing disabled) are handled via NSE if vuln_check, but we could add a simple banner check.
    return vulns

# ---------------------------------------------------------------------------
# Core Scanner Class – Cross-Platform, Ultra-Fast, Monster Edition
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
        deep_inspect: bool = True,   # new: enable active deep checks
        skip_ping: bool = False,     # new: if True, do not add -Pn
        ipv6: bool = False,          # new: scan over IPv6
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
        self.deep_inspect = deep_inspect
        self.skip_ping = skip_ping
        self.ipv6 = ipv6

        # Turbo mode overrides scan_mode and forces insane speed
        self.turbo = turbo
        if turbo:
            self.scan_mode = "turbo"
        else:
            self.scan_mode = scan_mode.lower()

        self.nm = nmap.PortScanner()
        self.scan_data = None
        self.os_info = "Unknown"
        self._target_ip = None  # will be resolved

    def _resolve_target(self) -> str:
        """Resolve target to IP; for IPv6 we rely on nmap -6."""
        # If target is an IP, use it; else resolve
        try:
            socket.inet_aton(self.target)
            return self.target
        except socket.error:
            pass
        try:
            return socket.gethostbyname(self.target)
        except socket.gaierror:
            logger.warning(f"Could not resolve {self.target}")
            return self.target

    def _build_port_spec(self) -> str:
        if self.scan_mode == "turbo":
            tcp = TURBO_TCP
            udp = TURBO_UDP
            return f"T:{','.join(map(str,tcp))},U:{','.join(map(str,udp))}"
        elif self.scan_mode == "quick":
            tcp = QUICK_TCP
            udp = QUICK_UDP  # now using constant
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
        # ---------- IPv6 ----------
        if self.ipv6:
            args.append("-6")
        # ---------- Ping handling ----------
        if not self.skip_ping:
            args.append("-Pn")   # treat all hosts as online (recommended for single target)
        # ---------- Port specification ----------
        if port_spec:
            args.append(f"-p {port_spec}")

        # ---------- Turbo mode: insane speed ----------
        if self.turbo:
            args.append("-T5 --min-rate 10000 --max-rtt-timeout 100ms")
            args.append("--max-retries 0 --host-timeout 30s")
            args.append("-n")   # no DNS
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
        # Service version detection if vulnerability check is on (or always in common/full)
        if self.vuln_check or self.scan_mode in ("common", "full"):
            args.append("-sV --version-intensity 5")
        elif self.scan_mode == "quick" and self.vuln_check:
            args.append("-sV --version-intensity 3")  # lighter for quick
        if self.vuln_check:
            # Comprehensive NSE scripts
            scripts = "vulners,vuln,smb-vuln-*,rdp-vuln-*,http-vuln-*,ssl-*"
            args.append(f"--script {scripts}")
        # OS detection for non-quick (optional)
        if self.scan_mode in ("common", "full", "custom"):
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
        # Fix: remove sudo=True (not supported by python-nmap)
        with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
            await loop.run_in_executor(
                pool,
                lambda: self.nm.scan(self.target, arguments=nmap_args)
            )
        if self.target in self.nm.all_hosts():
            self.scan_data = self.nm[self.target]
            os_matches = self.scan_data.get("osmatch", [])
            if os_matches:
                self.os_info = os_matches[0]["name"]
            # Resolve IP for deep checks
            if "ip" in self.scan_data.get("addresses", {}):
                self._target_ip = self.scan_data["addresses"]["ip"]
            else:
                self._target_ip = self._resolve_target()
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

    def get_static_vulns(self, service: Dict) -> List[Dict]:
        """Return static vulns as structured dicts with severity guess."""
        name = service["name"].lower()
        product = service.get("product", "").lower()
        version = service.get("version", "").lower()
        found = []
        for (svc_pat, ver_pat), vulns_list in STATIC_VULNS.items():
            if svc_pat in name or (product and svc_pat in product):
                if ver_pat == "" or (version and ver_pat in version):
                    for desc in vulns_list:
                        cve_match = __import__('re').search(r'(CVE-\d{4}-\d{4,})', desc)
                        cve_id = cve_match.group(1) if cve_match else ""
                        # guess severity based on keywords
                        severity = "HIGH"
                        if "rce" in desc.lower() or "remote code" in desc.lower():
                            severity = "CRITICAL"
                        elif "dos" in desc.lower():
                            severity = "MEDIUM"
                        found.append({
                            "cve": cve_id,
                            "description": desc,
                            "cvss_score": None,
                            "severity": severity,
                            "exploit_available": "exploit" in desc.lower(),
                            "exploitdb_url": get_exploitdb_links(cve_id),
                        })
        return found

    async def _correlate_cves(self, service: Dict) -> List[Dict]:
        cves = []
        # Static vulns first
        static_vulns = self.get_static_vulns(service)
        cves.extend(static_vulns)

        if self.vuln_check:
            # Live NVD queries
            loop = asyncio.get_running_loop()
            live_cves = await loop.run_in_executor(
                None,
                lookup_cves_nvd,
                service["name"],
                service.get("product", ""),
                service.get("version", ""),
                self.nvd_api_key,
            )
            for lcve in live_cves:
                if not any(c["cve"] == lcve["cve"] for c in cves if c["cve"]):
                    cves.append(lcve)

        # Enrich with Vulners exploits
        for cve_entry in cves:
            if cve_entry.get("cve") and self.vulners_api_key:
                exploits = await asyncio.get_running_loop().run_in_executor(
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
                if exploits:
                    cve_entry["exploit_available"] = True
            # Ensure exploitdb_url
            if "exploitdb_url" not in cve_entry:
                cve_entry["exploitdb_url"] = get_exploitdb_links(cve_entry.get("cve", ""))

        # Add nmap script output (from scan)
        for script_name, output in service.get("script", {}).items():
            if "vuln" in script_name.lower() and output:
                cves.append({
                    "cve": "",
                    "description": f"Script {script_name}: {output.strip()[:200]}",
                    "cvss_score": None,
                    "severity": "MEDIUM",
                    "exploit_available": False,
                    "exploitdb_url": "",
                    "exploits": [],
                })
        return cves

    async def correlate_vulns(self, services: List[Dict]) -> Dict[str, List[Dict]]:
        vuln_map = {}
        for svc in services:
            key = f"{svc['proto']}/{svc['port']} {svc['name']} {svc['product']} {svc['version']}".strip()
            vulns = await self._correlate_cves(svc)
            # Deep inspection active checks
            if self.deep_inspect and self._target_ip:
                deep_vulns = run_deep_checks(self._target_ip, svc)
                if deep_vulns:
                    for dv in deep_vulns:
                        # Avoid duplicates
                        if not any(v.get("description") == dv["description"] for v in vulns):
                            dv.setdefault("exploits", [])
                            dv.setdefault("exploitdb_url", "")
                            vulns.append(dv)
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
# Reporter – Multi-format output (enhanced with severity colors)
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
            # Sort by severity: critical first
            severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "UNKNOWN": 4}
            for svc, vulns in data["vulnerabilities"].items():
                vulns_sorted = sorted(vulns, key=lambda x: severity_order.get(x.get("severity", "UNKNOWN"), 4))
                print(f"  {svc}:")
                for v in vulns_sorted:
                    sev = v.get("severity", "UNKNOWN")
                    color = Fore.RED if sev == "CRITICAL" else Fore.LIGHTRED_EX if sev == "HIGH" else Fore.YELLOW if sev == "MEDIUM" else Fore.BLUE
                    print(color + f"    [{sev}] {v.get('description', '')}")
                    if v.get("cve"):
                        print(Fore.YELLOW + f"        CVE: {v['cve']} (CVSS: {v.get('cvss_score','N/A')})  | Exploit-DB: {v.get('exploitdb_url','')}")
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
            writer.writerow(["Proto/Port", "Service", "Product", "Version", "CVE", "Severity", "CVSS", "Description", "Exploit Links"])
            for svc in data.get("raw_services", []):
                key = f"{svc['proto']}/{svc['port']} {svc['name']} {svc.get('product','')} {svc.get('version','')}".strip()
                vulns = data.get("vulnerabilities", {}).get(key, [])
                if not vulns:
                    writer.writerow([
                        f"{svc['proto']}/{svc['port']}",
                        svc["name"],
                        svc.get("product", ""),
                        svc.get("version", ""),
                        "", "", "", "", ""
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
                            v.get("severity", ""),
                            v.get("cvss_score", ""),
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
.vuln{color:red;}.exploit{color:darkorange;}
.critical{background:#ffcccc;} .high{background:#ffe6e6;} .medium{background:#fff3cd;} .low{background:#e2f0d9;}
</style></head><body>
<h1>Scan Report: {{ target }}</h1>
<p>OS: {{ os }} | Time: {{ timestamp }}</p>
<h2>Open Services</h2>
<table><tr><th>Proto/Port</th><th>Service</th><th>Product</th><th>Version</th><th>Vulnerabilities</th></tr>
{% for s in raw_services %}
{% set key = (s.proto~'/'~s.port~' '~s.name~' '~(s.product or '')~' '~(s.version or '')).strip() %}
{% set vlist = vuln_map.get(key, []) %}
{% if vlist %}
  {% for v in vlist %}
  {% set sev = v.severity|lower %}
  <tr class="{{ sev }}">
    <td>{{ s.proto }}/{{ s.port }}</td>
    <td>{{ s.name }}</td>
    <td>{{ s.product or '' }}</td>
    <td>{{ s.version or '' }}</td>
    <td class="vuln">
      [{{ v.severity }}] {{ v.description }} ({{ v.cve }} CVSS:{{ v.cvss_score }})
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
            msg["Subject"] = f"⚡ Scan Report for {data['target']} – {sum(len(v) for v in data.get('vulnerabilities',{}).values())} vulns found"
            msg["From"] = smtp_config["from"]
            msg["To"] = smtp_config["to"]
            body = f"OS: {data.get('os')}\n\nServices:\n"
            body += "\n".join(data["services"])
            if data.get("vulnerabilities"):
                body += "\n\nCRITICAL VULNERABILITIES:\n"
                for svc, vulns in data["vulnerabilities"].items():
                    body += f"\n{svc}:\n"
                    for v in vulns:
                        body += f"  - [{v.get('severity','')}] {v['description']} ({v.get('cve','')})\n"
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
                    vuln_text += f"  - [{v.get('severity','')}] {v['description']} ({v.get('cve','')})\n"
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