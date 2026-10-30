#!/usr/bin/env python3
# =============================================================================
# core.py – Nemesis Scanner v4.1.0
# Author: Erfan Nahidi
# Use only on systems you own or have explicit written permission to test.
# =============================================================================

import logging
import asyncio
import concurrent.futures
import socket
import ssl
from typing import Dict, List, Optional, Any
from collections import defaultdict
from datetime import datetime, timedelta

import nmap                     # python-nmap
from .vulnerability import (
    lookup_local_vulnerabilities,
    lookup_nvd_vulnerabilities,
    search_exploits_vulners,
)


# ---------------------------------------------------------------------------
# Constants & Configuration
# ---------------------------------------------------------------------------
VERSION = "4.1.0"

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
# Core Scanner Class – Cross-Platform
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
        vuln_source: str = "offline",
    ):
        self.target = target
        self.threads = threads
        self.stealth = stealth
        self.vuln_check = vuln_check
        if vuln_source not in {"offline", "online"}:
            raise ValueError("vuln_source must be 'offline' or 'online'")
        self.vuln_source = vuln_source
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
        self._deep_check_cache = {}
        self._cve_cache = {}

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
        return lookup_local_vulnerabilities(
            service["name"],
            service.get("product", ""),
            service.get("version", ""),
        )

    def _service_cache_key(self, service: Dict) -> tuple:
        return (
            service.get("proto"),
            service.get("port"),
            service.get("name", ""),
            service.get("product", ""),
            service.get("version", ""),
            self.vuln_source,
        )

    async def _correlate_cves(self, service: Dict) -> List[Dict]:
        cache_key = self._service_cache_key(service)
        if cache_key in self._cve_cache:
            return self._cve_cache[cache_key]

        cves = []
        # Static vulns first
        static_vulns = self.get_static_vulns(service)
        cves.extend(static_vulns)

        if self.vuln_check:
            # Live NVD queries
            loop = asyncio.get_running_loop()
            live_cves = await loop.run_in_executor(
                None,
                lookup_nvd_vulnerabilities,
                service["name"],
                service.get("product", ""),
                service.get("version", ""),
                self.nvd_api_key,
                self.vuln_source == "online",
            )
            for lcve in live_cves:
                if not any(c["cve"] == lcve["cve"] for c in cves if c["cve"]):
                    cves.append(lcve)

        # Enrich with Vulners exploits
        for cve_entry in cves:
            if (
                self.vuln_source == "online"
                and cve_entry.get("cve")
                and self.vulners_api_key
            ):
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

        self._cve_cache[cache_key] = cves
        return cves

    async def _correlate_service(self, service: Dict):
        key = f"{service['proto']}/{service['port']} {service['name']} {service['product']} {service['version']}".strip()
        vulns = await self._correlate_cves(service)

        if self.deep_inspect and self._target_ip:
            deep_check_key = self._service_cache_key(service)
            if deep_check_key not in self._deep_check_cache:
                self._deep_check_cache[deep_check_key] = run_deep_checks(self._target_ip, service)
            deep_vulns = self._deep_check_cache[deep_check_key]
            if deep_vulns:
                for dv in deep_vulns:
                    if not any(v.get("description") == dv["description"] for v in vulns):
                        dv.setdefault("exploits", [])
                        dv.setdefault("exploitdb_url", "")
                        vulns.append(dv)
        return key, vulns

    async def correlate_vulns(self, services: List[Dict]) -> Dict[str, List[Dict]]:
        if not services:
            return {}

        tasks = [self._correlate_service(svc) for svc in services]
        results = await asyncio.gather(*tasks)

        vuln_map = {}
        for key, vulns in results:
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

