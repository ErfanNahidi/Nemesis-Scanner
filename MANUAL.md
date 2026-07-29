# Nemesis Scanner – Monster Edition v3.0.0 | Manual

**Full documentation and usage guide**  
*Author: Erfan Nahidi*

---

## Table of Contents

1. [Introduction](#1-introduction)
2. [Installation](#2-installation)
3. [Basic Usage](#3-basic-usage)
4. [Scan Modes Explained](#4-scan-modes-explained)
5. [Command‑Line Reference](#5-commandline-reference)
6. [Interactive Menu Guide](#6-interactive-menu-guide)
7. [Output & Reporting](#7-output--reporting)
8. [Auto‑Save Feature](#8-autosave-feature)
9. [Attack Surface Modules](#9-attack-surface-modules)
10. [Vulnerability Detection Pipeline](#10-vulnerability-detection-pipeline)
11. [Deep Inspection](#11-deep-inspection)
12. [Evasion & Advanced Options](#12-evasion--advanced-options)
13. [Configuration File](#13-configuration-file)
14. [API Keys Setup](#14-api-keys-setup)
15. [Troubleshooting](#15-troubleshooting)
16. [Legal Disclaimer](#16-legal-disclaimer)

---

## 1. Introduction

**Nemesis Scanner** is an advanced, cross‑platform network reconnaissance and vulnerability assessment tool built on top of **Nmap**. It combines the speed and reliability of Nmap with additional layers:

- **Service & version detection**
- **OS fingerprinting**
- **Attack surface mapping** – open ports are automatically linked to known attack modules (SMB, AD, RDP, etc.)
- **Static vulnerability database** – built‑in signatures for well‑known CVEs (expandable via JSON)
- **Live CVE lookup** via NIST NVD and **exploit search** via Vulners
- **Deep active inspection** – checks for anonymous FTP, missing HTTP headers, weak TLS, and more
- **Caching** – minimises repeated API calls to avoid rate limits
- **Severity & CVSS scores** – vulnerabilities are coloured and scored (Critical/High/Medium/Low)
- **Multi‑format reporting** – console, JSON, CSV, HTML
- **Turbo mode** – ultra‑fast scanning of only critical ports
- **Interactive menus** – separated workflows for network discovery, vulnerability assessment, and full attack surface analysis.

The tool is designed for **penetration testers**, **red teams**, and **security auditors** who need a single portable scanner that works on **Windows, Linux, macOS, and embedded devices**.

---

## 2. Installation

### 2.1 Prerequisites

- **Operating System:** Any system that can run Nmap and Python 3.8+
- **Nmap** version 7.80 or newer installed and in the system `PATH`
- **Python** 3.8 or newer
- **pip** (Python package manager)

### 2.2 Install Nmap

| Platform | Command |
|----------|---------|
| Debian/Ubuntu/Kali | `sudo apt update && sudo apt install nmap -y` |
| macOS (Homebrew)   | `brew install nmap` |
| Windows            | Download installer from [nmap.org](https://nmap.org/download.html) |

### 2.3 Install Python dependencies

Create a `requirements.txt` file (if not already present) with:

```

python-nmap
requests
colorama
pyyaml
jinja2

```

Then run:

```bash
pip install -r requirements.txt
```

Alternatively, install each package manually:

```bash
pip install python-nmap requests colorama pyyaml jinja2
```

2.4 Download the Scanner

Clone the repository or simply copy core.py and cli.py into a working directory.

```bash
git clone https://github.com/ErfanNahidi/Nemesis-Scanner.git
cd Nemesis-Scanner
```

2.5 API Keys (Optional but Recommended)

· NVD API key – increases the rate limit from 5 requests per 30 seconds to 50. Request one at https://nvd.nist.gov/developers/request-an-api-key.
· Vulners API key – free registration at https://vulners.com, needed for exploit search.

Store the keys in a configuration file or pass them directly as command‑line arguments.

---

3. Basic Usage

All scans require root privileges (sudo on Linux/macOS) for SYN scan, UDP scan, and OS detection.

Command‑line (direct):

```bash
sudo python3 cli.py <target> [options]
```

Interactive menu:

```bash
sudo python3 cli.py
```

If run without arguments, the interactive menu opens automatically. Use --interactive to force it even when arguments are supplied.

---

4. Scan Modes Explained

Mode TCP Ports UDP Ports Version Detection OS Detection NSE Scripts (if vuln-check) Speed
quick ~38 commonly attacked ports 10 common UDP ports Optional No Yes (if enabled) Fast
common Top 1000 TCP ports 20 common UDP ports Always Yes Yes (if enabled) Medium
full All 65535 TCP ports 20 common UDP ports Always Yes Yes (if enabled) Very Slow
custom Defined by --nmap-args As per args As per args As per args Yes (if enabled) Varies
turbo Top 15 critical ports 6 critical UDP ports Optional No Yes (if enabled) Ultra‑Fast

Turbo Mode Details

Turbo mode is optimised for sheer speed:

· T5 timing, 10 000 packets per second minimum rate
· No ping (-Pn), no DNS resolution, no retries
· Parallelism up to 256 probes
· RTT timeout of 100 ms, host timeout of 30 seconds
· Only 15 TCP ports (21,22,80,443,445,135,139,3389,5985,5986,8080,8443,1433,3306,5900) and 6 UDP ports (53,161,162,67,68,123)
· If --vuln-check is added, a lightweight version scan (-sV --version-intensity 2) is included, keeping scans under 30 seconds for a single host.

---

5. Command‑Line Reference

```
usage: cli.py [targets] [options]

Positional arguments:
  targets               IP address(es), hostname(s) or CIDR notation

Optional arguments:
  -m, --mode            Scan mode: quick|common|full|custom|turbo (default: quick)
  --stealth             Stealth mode (T2, delays, decoys)
  --vuln-check          Enable vulnerability detection (NSE scripts + NVD lookup)
  --nvd-key KEY         NVD API key for higher rate limit
  --vulners-key KEY     Vulners API key for exploit search
  --nmap-args ARGS      Additional Nmap arguments (used with custom mode)
  -t, --threads N       Number of parallel target scans (default: 10, capped at 2 in stealth)
  -o, --output NAME     Base name for report files (without extension)
  --format              Output format: json|csv|html|all (default: json)
  --verbose             Show detailed console output
  --aggressive          Aggressive timing (T5, 2000 pps)
  --turbo               Enable turbo mode
  --fragment            Fragment IP packets (-f)
  --source-port PORT    Spoof source port
  --spoof-mac MAC       Spoof MAC address
  --decoys IP1,IP2,...  Comma‑separated decoy IPs
  --ttl VALUE           Set TTL for packets
  --auth-check          Attempt basic authentication checks (future expansion)
  --auto-save           Automatically save report in reports/ folder
  --deep-inspect        Enable deep active inspection (default: on)
  --no-deep-inspect     Disable deep inspection
  --skip-ping           Do NOT add -Pn (let Nmap perform host discovery)
  --ipv6                Scan using IPv6
  --email ADDRESS       Send report via email (requires SMTP config)
  --slack URL           Slack webhook URL for notification
  --config FILE         YAML/JSON configuration file
  --interactive         Force interactive menu
```

---

6. Interactive Menu Guide

Running cli.py without arguments opens the main menu with three scanning categories.

Main Menu

```
[1] Network Discovery & Port Scanning
[2] Vulnerability Assessment & Exploit Detection
[3] Full Attack Surface Analysis (Network + Vulns)
[4] About
[5] Update & Maintenance
[0] Exit
```

6.1 Network Discovery Sub‑menu

Option Description
1 – Quick TCP scan Common ports, fast, no version/vuln
2 – Full TCP scan All 65535 ports, thorough
3 – Turbo scan Ultra‑fast critical ports only
4 – Stealth SYN scan Slow, fragmented, evasive
5 – IPv6 network scan Scan IPv6 targets
6 – Custom scan Enter your own Nmap flags

6.2 Vulnerability Assessment Sub‑menu

Option Description
1 – Quick security scan Quick mode + NSE vuln scripts (no online API)
2 – Common security scan Top 1000 ports + version detection + NSE scripts
3 – Deep vulnerability scan Online NVD/Vulners lookups + deep inspection
4 – Web application scan HTTP headers, TLS/SSL weaknesses only
5 – AD / Kerberos scan AD‑specific ports with vulnerability scripts
6 – Custom vulnerability scan Choose mode, API keys, deep inspection manually

6.3 Full Attack Surface Analysis Sub‑menu

Option Description
1 – Standard full scan Full TCP + version + vulnerability scripts
2 – Aggressive full scan Fast full scan with online CVE lookups
3 – Stealth full scan Slow, evasive full scan with vulnerability checks
4 – Turbo combo Critical ports + vulnerability detection

After selecting a preset, you are prompted for a target and optionally for auto‑save and format.

---

7. Output & Reporting

Reports are produced in the following formats:

Format File Extension Description
Console – Coloured, real‑time summary with services, modules, vulnerabilities (severity‑coloured)
JSON .json Complete machine‑readable data including CVSS, severity, exploit links
CSV .csv Spreadsheet‑friendly: Proto/Port, Service, Product, Version, CVE, Severity, CVSS, Description, Exploit Links
HTML .html Styled page with colour‑coded severity rows and clickable exploit links

Use --format all to generate all three file types.

When -o my_scan is specified, files are created as my_scan.json, my_scan.csv, my_scan.html.

HTML reports require the Jinja2 library (already in requirements).

---

8. Auto‑Save Feature

If --auto-save is enabled (or selected in the interactive menus), reports are saved in a reports/ subdirectory. The directory is created automatically.

Filename format:

```
reports/<sanitized_target>_<YYYYMMDD_HHMMSS>.<ext>
```

Example: reports/192.168.1.10_20260729_143015.json

This is ideal for running regular scans and keeping historical records.

---

9. Attack Surface Modules

The scanner automatically classifies open ports into attack modules. This helps you quickly identify possible attack vectors.

Module Ports Protocol Common Attacks / Exploits
DHCP Attacker 67, 68 UDP DHCP spoofing, starvation
DNS Attacker 53 TCP DNS cache poisoning, tunneling
AD Attacker 88,135,139,389,464,636,3268,3269 TCP Kerberoasting, DCSync, LDAP injection
SMB Attacker 139, 445 TCP EternalBlue (MS17-010), SMBGhost, Pass‑the‑Hash
SNMP Sniffinger 161, 162 UDP Default community strings, information disclosure
DoS Amplification 19,123,520,1900,11211 UDP NTP amplification, SSDP, memcached
Install & Update 80,443,3389,5985,5986,8530,8531 TCP WSUS hijack, WinRM abuse, RDP brute force
Print Spooler 515, 9100 TCP PrintNightmare
LDAP Signing 389, 636 TCP LDAP without signing / channel binding
MSSQL Attacker 1433 TCP SQL injection, remote code execution
Kerberos Attacker 88 TCP Kerberoasting
WinRM Attacker 5985, 5986 TCP Remote command execution
RDP Attacker 3389 TCP BlueKeep, password spraying
FTP / SSH Brute 21, 22 TCP Brute‑force, weak credentials
HTTP(S) Exploitation 80,443,8080,8443 TCP Web app vulnerabilities, path traversal

---

10. Vulnerability Detection Pipeline

The scanner employs a multi‑step approach to identify and enrich vulnerabilities.

10.1 Static Database

A built‑in dictionary (extendable via static_vulns.json) maps (service, version) to known vulnerabilities. Examples:

· (smb, 1.0) → MS17‑010 (EternalBlue)
· (rdp, "") → CVE‑2019‑0708 (BlueKeep), CVE‑2020‑0610
· (http, apache) → CVE‑2021‑41773

You can add your own entries in a JSON file placed next to core.py.

10.2 NSE Scripts

When --vuln-check is active, a suite of NSE scripts is executed:

· vulners
· vuln
· smb-vuln-*
· rdp-vuln-*
· http-vuln-*
· ssl-*

Results are parsed and displayed. In turbo mode only vulners and vuln are used.

10.3 Live NVD Lookup

Service name, product, and version are sent to the NVD API (requires --vuln-check). Each returned CVE includes:

· CVE ID
· Description
· CVSS base score
· Severity (Critical/High/Medium/Low)

Results are cached for 1 hour to respect rate limits.

10.4 Vulners Exploit Search

If a Vulners API key is provided, the scanner queries Vulners for public exploits for each CVE. Links to the exploits are included in reports.

10.5 Exploit‑DB Links

Every CVE is linked to an Exploit‑DB search URL for manual research.

---

11. Deep Inspection

Deep inspection is enabled by default and performs non‑intrusive checks directly against open TCP services.

Check What it does
FTP Anonymous Tries USER anonymous / PASS anonymous, reports if login is allowed
HTTP Security Headers Sends a GET request and checks for missing: HSTS, X‑Frame‑Options, X‑Content‑Type‑Options, CSP, X‑XSS‑Protection
TLS/SSL Weaknesses Attempts connections with TLSv1.0 and TLSv1.1; checks for expired or self‑signed certificates

These findings are treated as vulnerabilities with appropriate severity (e.g., anonymous FTP = HIGH, missing HSTS = MEDIUM).

Disable deep inspection with --no-deep-inspect for a passive‑only scan.

---

12. Evasion & Advanced Options

12.1 Stealth Mode (--stealth)

· T2 timing template (paranoid)
· 500 ms scan delay
· Random host order
· Maximum 2 parallel threads
· Automatically enables --fragment

12.2 Aggressive Mode (--aggressive)

· T5 timing
· Minimum 2000 packets per second
· Short timeouts (500 ms RTT, 1 min host)

12.3 Other Evasion Techniques

Option Description
--fragment Fragment IP packets (Nmap -f)
--source-port Spoof a source port (e.g., 53 for DNS)
--spoof-mac Spoof a MAC address
--decoys Use decoy IPs (comma‑separated)
--ttl Set a custom TTL

12.4 Host Discovery Control

By default, the scanner uses -Pn (no ping), meaning it assumes the target is up. For subnet scans where you want to skip dead hosts, use --skip-ping to let Nmap perform its usual host discovery.

12.5 IPv6 Support

Add --ipv6 to scan an IPv6 target. Nmap’s -6 flag is automatically included.

---

13. Configuration File

You can store recurring settings in a YAML or JSON configuration file. Command‑line arguments override the file.

Example YAML config (config.yaml):

```yaml
mode: common
vuln_check: true
nvd_key: "abcdef123456"
vulners_key: "xyz7890"
deep_inspect: true
auto_save: true
format: json
threads: 5
output: "my_scan"
smtp:
  server: smtp.gmail.com
  port: 587
  user: you@gmail.com
  password: app-password
  from: you@gmail.com
  to: security@company.com
```

Usage:

```bash
sudo python3 cli.py 192.168.1.0/24 --config config.yaml
```

---

14. API Keys Setup

NVD API Key

1. Go to https://nvd.nist.gov/developers/request-an-api-key
2. Fill in the form (a valid email is required)
3. You will receive a key via email
4. Use it with --nvd-key or in the configuration file

Without a key, the scanner is limited to 5 requests per 30 seconds. Caching helps but large scans will be slower.

Vulners API Key

1. Sign up at https://vulners.com
2. Go to your profile → API Keys → create a new key
3. Pass it via --vulners-key or the config file

Without a key, exploit search is disabled.

---

15. Troubleshooting

Q: I get nmap program was not found or nmap is not installed.
A: Ensure Nmap is installed and in your PATH. On Linux/macOS, try which nmap. On Windows, add the Nmap installation folder to the system PATH.

Q: The scan runs but reports no open ports on a target I know is alive.
A: Check that you’re running as root. Without root, SYN scan (-sS) can’t be used and a slower connect scan may miss filtered ports. Also, try adding --skip-ping to enable host discovery.

Q: The HTML report shows no styling or layout.
A: Install jinja2 (pip install jinja2). Without it, the HTML report is skipped.

Q: Deep inspection returns no results or hangs.
A: Some firewalls may block the probing packets. Try --no-deep-inspect to skip active checks.

Q: NVD lookups are extremely slow.
A: Without an API key, you’re rate‑limited. Obtain a free key and use --nvd-key.

Q: Turbo scan misses services I know exist on non‑default ports.
A: Turbo only checks the top 15 TCP and 6 UDP ports. For full coverage, use common or full mode.

---

16. Legal Disclaimer

⚠️ This tool is designed for authorised security testing only.

You must have explicit written permission from the system owner before scanning any network or host. Unauthorised scanning is illegal under computer misuse laws (e.g., CFAA, UK Computer Misuse Act 1990). The author assumes no liability for misuse or damage caused by this tool.

Use at your own risk.
