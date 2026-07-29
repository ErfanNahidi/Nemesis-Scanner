[🇮🇷 فارسی](README_FA.md)

# Nemesis Scanner – Monster Edition v3.0.0

[![Python 3.8+](https://img.shields.io/badge/python-3.8+-blue.svg)](https://www.python.org/downloads/)
[![License](https://img.shields.io/badge/license-Custom-red.svg)](LICENSE)
[![Version](https://img.shields.io/badge/Version-3.0.0-green.svg)]()

**Author:** Erfan Nahidi  
**License:** For authorised security testing only.  
**Repository:** [https://github.com/ErfanNahidi/Nemesis-Scanner](https://github.com/ErfanNahidi/Nemesis-Scanner)

---

## 📖 Table of Contents

1. [Introduction](#introduction)
2. [What's New in v3.0.0](#whats-new-in-v300)
3. [System Requirements](#system-requirements)
4. [Installation](#installation)
5. [Quick Start](#quick-start)
6. [Scan Modes](#scan-modes)
7. [Command-Line Reference](#command-line-reference)
8. [Interactive Menu](#interactive-menu)
9. [Output & Reporting](#output--reporting)
10. [Auto-Save Feature](#auto-save-feature)
11. [Attack Surface Modules](#attack-surface-modules)
12. [Vulnerability Detection](#vulnerability-detection)
13. [Deep Inspection](#deep-inspection)
14. [Evasion & Advanced Options](#evasion--advanced-options)
15. [Configuration File](#configuration-file)
16. [Examples](#examples)
17. [FAQ](#faq)
18. [Legal Disclaimer](#legal-disclaimer)

---

## 1. Introduction

**Nemesis Scanner** is an advanced, cross‑platform network reconnaissance and vulnerability scanner.  
It uses Nmap as its core engine and enriches results with:

- Service & version detection
- OS fingerprinting
- Attack surface mapping
- Static & dynamic CVE databases (NVD, Vulners)
- **Deep active inspection** (FTP anonymous, HTTP security headers, TLS weaknesses)
- **CVSS severity scoring** and exploit maturity flags
- **API response caching** to respect rate limits
- Multi‑format reporting (console, JSON, CSV, HTML)
- **Turbo mode** for ultra‑fast critical‑port scanning
- Separate interactive workflows for **Network Discovery**, **Vulnerability Assessment**, and **Full Attack Surface Analysis**

Designed for penetration testers, red teamers, and auditors who need speed, depth, and portability across any operating system.

---

## 2. What's New in v3.0.0

- 🔍 **Deep Inspection** – active checks: anonymous FTP, missing HTTP security headers, weak TLS protocols, expired/self‑signed certificates.
- 📊 **Severity & CVSS** – vulnerabilities now carry severity ratings (Critical/High/Medium/Low) and CVSS scores from NVD.
- ⚡ **Speed Boost** – `-Pn` enabled by default (skip host discovery), fine‑tuned timing, better parallelism.
- 💾 **Caching** – NVD and Vulners results cached for 1h / 30min to avoid rate‑limit bans.
- 📁 **External Static Vuln DB** – load custom `static_vulns.json` to extend built‑in signatures.
- 📋 **Redesigned Menus** – clear separation: Network Discovery, Vulnerability Assessment, Full Attack Surface Analysis.
- 🌐 **IPv6 Support** – scan IPv6 targets with `--ipv6` flag.
- 🛡️ **New CLI Options** – `--deep-inspect`, `--no-deep-inspect`, `--skip-ping`, `--ipv6`.

---

## 3. System Requirements

- **Operating System:** Linux, macOS, Windows (Nmap required)
- **Python:** 3.8 or higher
- **Nmap:** 7.80+ (must be in PATH; root/sudo required for SYN scan, UDP scan, OS detection)
- **RAM:** 2 GB minimum
- **Network:** Internet for live CVE/exploit lookup (optional)

---

## 4. Installation

### 1. Install Nmap

```bash
# Debian/Ubuntu/Kali
sudo apt update && sudo apt install nmap -y

# macOS (Homebrew)
brew install nmap

# Windows: download from https://nmap.org/download.html
```

2. Install Python dependencies

```bash
pip install -r requirements.txt
```

requirements.txt:

```
python-nmap
requests
colorama
pyyaml
jinja2
```

3. Download the scanner

Clone the repository or copy core.py and cli.py into the same directory.

4. (Optional) Get API keys for extended features

· NVD API key: https://nvd.nist.gov/developers/request-an-api-key
    (increases rate limit from 5 to 50 requests per 30 seconds)
· Vulners API key: https://vulners.com (free registration)
    (required for exploit search)

---

5. Quick Start

Command line:

```bash
sudo python3 cli.py 192.168.1.10 -m quick
```

Interactive menu:

```bash
sudo python3 cli.py
```

Choose the desired category: Network Discovery, Vulnerability Assessment, or Full Attack Surface Analysis.

---

6. Scan Modes

Mode TCP Ports UDP Ports Version / OS Scripts / Vuln Check Speed
quick ~38 critical ports ~10 common UDP Optional Yes (if vuln check) Fast
common Top 1000 TCP 20 common UDP Yes Yes (if vuln check) Medium
full All 65,535 TCP 20 common UDP Yes Yes (if vuln check) Very Slow
custom Defined by --nmap-args As per args As per args Yes (if vuln check) Varies
turbo Top 15 critical TCP + UDP Top 6 UDP Optional Yes (if vuln check) Ultra‑Fast

Turbo mode optimisations:

· T5 timing, 10k pps minimum rate
· No retries, no ping, no DNS
· Max parallelism 256 probes
· 100ms RTT timeout, 30s host timeout
· Lightweight version detection (-sV --version-intensity 2) if vulnerability check is enabled.

---

7. Command‑Line Reference

```
usage: cli.py [targets] [options]

positional arguments:
  targets               Target IP(s) or CIDR (space or comma separated)

optional arguments:
  -m, --mode {quick,common,full,custom,turbo}
                        Scan mode (default: quick)
  --stealth             Enable stealth mode (T2, delays, decoys)
  --vuln-check          Enable vulnerability detection (NSE + NVD)
  --nvd-key KEY         NVD API key
  --vulners-key KEY     Vulners API key for exploit search
  --nmap-args ARGS      Additional Nmap arguments
  -t, --threads N       Max parallel target scans (default: 10)
  -o, --output NAME     Base filename for report (without extension)
  --format {json,csv,html,all}
                        Output format (default: json)
  --verbose             Verbose console output
  --aggressive          Aggressive timing (T5, 2000 pps)
  --turbo               Enable turbo mode (ultra-fast)
  --fragment            Fragment IP packets (-f)
  --source-port PORT    Spoof source port number
  --spoof-mac MAC       Spoof MAC address
  --decoys IP1,IP2,...  Comma-separated decoy IPs
  --ttl VALUE           Set IP time-to-live
  --auth-check          Attempt basic auth checks on services
  --auto-save           Auto-save report in reports/ folder with IP+timestamp
  --deep-inspect        Enable deep active inspection (default: on)
  --no-deep-inspect     Disable deep inspection
  --skip-ping           Do NOT add -Pn (let Nmap perform host discovery)
  --ipv6                Scan using IPv6
  --email ADDRESS       Send report via email (requires SMTP config)
  --slack URL           Slack webhook URL for notification
  --config FILE         YAML/JSON config file with defaults
  --interactive         Force interactive menu
```

---

8. Interactive Menu

Running cli.py without arguments opens the categorised main menu:

```
[1] Network Discovery & Port Scanning
[2] Vulnerability Assessment & Exploit Detection
[3] Full Attack Surface Analysis (Network + Vulns)
[4] About
[5] Update & Maintenance
[0] Exit
```

Network Discovery Sub‑menu

· Quick TCP scan (common ports, fast)
· Full TCP scan (1‑65535, thorough)
· Turbo scan (top critical ports, ultra‑fast)
· Stealth SYN scan (slow, firewall evasion)
· IPv6 network scan
· Custom scan (add your own Nmap arguments)

Vulnerability Assessment Sub‑menu

· Quick security scan (common ports + NSE vuln scripts)
· Common security scan (top 1000 ports, version + NSE)
· Deep vulnerability scan (online NVD/Vulners, deep inspection)
· Web application security scan (HTTP headers, TLS, SSL issues)
· Active Directory / Kerberos focused scan
· Custom vulnerability scan

Full Attack Surface Analysis Sub‑menu

· Standard full scan (all TCP, version detection, vulnerability scripts)
· Aggressive full scan (fast, with online CVE lookups)
· Stealth full scan (slow, evasive, with vulnerability checks)
· Turbo combo (critical ports + vulnerability detection)

Each preset can be followed by auto‑save and format choice.

---

9. Output & Reporting

Reports are generated in four formats:

· Console: Coloured summary with severity‑aware output (Critical=Red, High=Light Red, Medium=Yellow, Low=Blue).
· JSON: Full structured data including CVSS, severity, exploit links.
· CSV: Spreadsheet‑ready table with columns: Proto/Port, Service, Product, Version, CVE, Severity, CVSS, Description, Exploit Links.
· HTML: Styled page with colour‑coded severity rows and clickable exploit links.

Use --format all to generate JSON, CSV, and HTML simultaneously.

---

10. Auto‑Save Feature

With --auto-save, reports are saved in the reports/ folder (created automatically) using the naming pattern:

```
reports/<target>_<timestamp>.<ext>
```

Example: reports/192.168.1.10_20260729_143015.json

The timestamp follows YYYYMMDD_HHMMSS format. Combine with --format to choose the file type (json, csv, html).

---

11. Attack Surface Modules

Open ports are automatically mapped to attack modules:

Module Ports Proto Attack Examples
DHCP Attacker 67, 68 UDP DHCP spoofing, starvation
DNS Attacker 53 TCP Cache poisoning, tunnelling
AD Attacker 88,135,139,389,464,636,3268,3269 TCP Kerberoasting, DCSync, LDAP injection
SMB Attacker 139, 445 TCP EternalBlue, SMBGhost, Pass‑the‑hash
SNMP Sniffinger 161, 162 UDP Default communities, info disclosure
DoS Amplification 19,123,520,1900,11211 UDP NTP amp, SSDP amp, memcached amp
Install & Update 80,443,3389,5985,5986,8530,8531 TCP WSUS hijack, WinRM abuse, RDP brute
Print Spooler 515, 9100 TCP PrintNightmare
LDAP Signing 389, 636 TCP LDAP without signing / channel binding
MSSQL Attacker 1433 TCP SQL injection, RCE
Kerberos Attacker 88 TCP Kerberoasting
WinRM Attacker 5985, 5986 TCP Remote command execution
RDP Attacker 3389 TCP BlueKeep, password spraying
FTP / SSH Brute 21, 22 TCP Bruteforce, weak credentials
HTTP(S) Exploitation 80,443,8080,8443 TCP Web app attacks, path traversal

---

12. Vulnerability Detection

The scanner uses multiple layers to detect and enrich vulnerabilities:

1. Static Database – built‑in signatures for well‑known CVEs (MS17-010, BlueKeep, SMBGhost, SigRed, etc.). Can be extended via static_vulns.json.
2. NSE Scripts – when --vuln-check is active, comprehensive NSE scripts are executed (vulners, vuln, smb-vuln-*, rdp-vuln-*, http-vuln-*, ssl-*). Results are parsed and added to the vulnerability list.
3. Live NVD Lookup – service name, product, and version are sent to the NVD API. Results include CVE ID, description, CVSS score, and severity (Critical, High, Medium, Low, Unknown). Caching avoids repeated calls.
4. Vulners Exploit Search – when a Vulners API key is provided, the scanner searches for public exploits for each CVE and provides direct links.
5. Exploit‑DB – an automatic search link is generated for every CVE.

All vulnerabilities are displayed with:

· Severity colour coding (console and HTML)
· Exploit maturity flag (public exploit available yes/no)
· CVSS score for risk assessment

---

13. Deep Inspection

With deep inspection enabled (default), the scanner performs active, non‑destructive checks directly against services:

· FTP: attempts anonymous login (anonymous/anonymous)
· HTTP/HTTPS: checks for missing security headers (HSTS, X-Frame-Options, X-Content-Type-Options, CSP, X-XSS-Protection)
· TLS/SSL: tests for weak protocols (TLSv1.0/1.1), expired certificates, and self‑signed certificates

These findings are reported as vulnerabilities with appropriate severity and appear alongside CVE results.

Disable deep inspection with --no-deep-inspect if you prefer passive scanning only.

---

14. Evasion & Advanced Options

· Stealth Mode (--stealth): T2 timing, 500ms delays, random host order, reduced threads (max 2).
· Aggressive Mode (--aggressive): T5, 2000 pps minimum, short timeouts.
· Packet Fragmentation (--fragment), Source Port Spoof (--source-port), MAC Spoof (--spoof-mac), Decoys (--decoys), Custom TTL (--ttl).
· Host Discovery Control: -Pn is used by default to skip ping. Use --skip-ping to let Nmap perform host discovery (useful for large subnets where you want to skip dead hosts).
· IPv6 Scanning: activate with --ipv6.

---

15. Configuration File

Store default options and SMTP settings in YAML (or JSON):

```yaml
mode: common
vuln_check: true
nvd_key: "your-nvd-api-key"
vulners_key: "your-vulners-key"
deep_inspect: true
auto_save: true
format: json
threads: 5
smtp:
  server: smtp.gmail.com
  port: 587
  user: you@gmail.com
  password: app-password
  from: you@gmail.com
  to: security@company.com
```

Usage: sudo python3 cli.py 192.168.1.0/24 --config config.yaml
Command‑line arguments override config file values.

---

16. Examples

Quick network scan (ports only)

```bash
sudo python3 cli.py 192.168.1.10 -m quick
```

Common security scan with auto‑save

```bash
sudo python3 cli.py 192.168.1.0/24 -m common --vuln-check --auto-save --format html
```

Deep vulnerability scan with API keys

```bash
sudo python3 cli.py 10.0.0.1 -m common --vuln-check --nvd-key YOUR_KEY --vulners-key YOUR_KEY --deep-inspect --auto-save
```

Turbo scan with vulnerability detection

```bash
sudo python3 cli.py target.com --turbo --vuln-check --auto-save
```

IPv6 scan

```bash
sudo python3 cli.py fe80::1 --ipv6 -m quick
```

Stealth scan with decoys, no deep inspection

```bash
sudo python3 cli.py 10.0.0.0/24 --stealth --decoys 10.0.0.1,10.0.0.2 --no-deep-inspect --vuln-check
```

Custom Nmap arguments + deep inspection

```bash
sudo python3 cli.py 192.168.1.1 -m custom --nmap-args "-p 80,443 --script http-enum" --deep-inspect
```

---

17. FAQ

Q: Do I need root privileges?
A: Yes, for SYN scan, UDP scan, and OS detection.

Q: How long does a full scan take?
A: For a single host, a full 65535‑port scan may take 1–4 hours. Turbo mode finishes in under 30 seconds.

Q: Is the scanner OS‑agnostic?
A: Yes. Works on Windows, Linux, macOS, and most network devices.

Q: What if I don't have an API key?
A: CVE lookups still work but are rate‑limited. Exploit search requires a Vulners key.

Q: Can I extend the static vulnerability database?
A: Yes, create a static_vulns.json file in the scanner's directory following the required format.

Q: Where are reports saved?
A: In the reports/ subfolder next to cli.py.

---

18. Legal Disclaimer

⚠️ WARNING
This tool is intended for authorised security testing only.
You must have explicit written permission from the system owner before scanning any network or host.

Unauthorised scanning is illegal under applicable laws (CFAA, Computer Misuse Act, etc.).
The author assumes no liability for misuse or damage caused by this tool.

Use at your own risk.
