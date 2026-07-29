# Nemesis Scanner – Monster Edition v3.0.0

[🇮🇷 فارسی](README_FA.md)

**Author:** Erfan Nahidi  
**License:** For authorised security testing only.  
**Repository:** [https://github.com/ErfanNahidi/Nemesis-Scanner](https://github.com/ErfanNahidi/Nemesis-Scanner)

---

## 📖 Table of Contents

1. [Introduction](#introduction)
2. [What's New in v2.2.0](#whats-new-in-v220)
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
- New interactive menus: separate **Network**, **Vulnerability**, and **Full Attack Surface** workflows

Designed for penetration testers, red teamers, and auditors who need speed, depth, and portability.

---

## 2. What's New in v3.0.0

- 🔍 **Deep Inspection** – active checks: anonymous FTP, missing HTTP security headers, weak TLS protocols, expired/self‑signed certificates.
- 📊 **Severity & CVSS** – vulnerabilities now carry severity ratings (Critical/High/Medium/Low) and CVSS scores from NVD.
- ⚡ **Turbo & Speed Boost** – `-Pn` enabled by default (skip host discovery), fine‑tuned timing, better parallelism.
- 💾 **Caching** – NVD and Vulners results cached for 1h / 30min to avoid rate‑limit bans.
- 📁 **External Static Vuln DB** – load custom `static_vulns.json` to extend built‑in signatures.
- 📋 **Redesigned Menus** – clear separation: Network Discovery, Vulnerability Assessment, Full Attack Surface Analysis.
- 🌐 **IPv6 Support** – scan IPv6 targets with `--ipv6` flag.
- 🛡️ **New CLI Options** – `--deep-inspect`, `--no-deep-inspect`, `--skip-ping`, `--ipv6`.

---

## 3. System Requirements

- **Operating System:** Linux, macOS, Windows (Nmap required)
- **Python:** 3.8+
- **Nmap:** 7.80+ (in PATH; root for SYN/UDP/OS detection)
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

### 2. Install Python dependencies

```bash
pip install -r requirements.txt
```

*requirements.txt*:
```
python-nmap
requests
colorama
pyyaml
jinja2
```

### 3. Download

Place `core.py` and `cli.py` in the same directory.

### 4. (Optional) API keys

- **NVD API key:** [https://nvd.nist.gov/developers/request-an-api-key](https://nvd.nist.gov/developers/request-an-api-key)
- **Vulners API key:** [https://vulners.com](https://vulners.com) (free registration)

---

## 5. Quick Start

**Command line:**
```bash
sudo python3 cli.py 192.168.1.10 -m quick
```

**Interactive menu:**
```bash
sudo python3 cli.py
```
Then choose the desired category (Network, Vulnerability, or Full Analysis) and follow the prompts.

---

## 6. Scan Modes

| Mode       | TCP Ports               | UDP Ports       | Version / OS | Scripts / Vuln Check | Speed  |
|------------|--------------------------|-----------------|--------------|----------------------|--------|
| `quick`    | ~38 critical ports       | ~10 common UDP  | Optional     | Yes (if vuln check)  | Fast   |
| `common`   | Top 1000 TCP             | 20 common UDP   | Yes          | Yes (if vuln check)  | Medium |
| `full`     | All 65,535 TCP           | 20 common UDP   | Yes          | Yes (if vuln check)  | Very Slow |
| `custom`   | Defined by `--nmap-args` | As per args     | As per args  | Yes (if vuln check)  | Varies |
| `turbo`    | Top 15 critical TCP + UDP| Top 6 UDP       | Optional     | Yes (if vuln check)  | Ultra‑Fast |

**Turbo mode** optimisations:
- T5, 10k pps min rate, no retries, no ping, no DNS
- Max parallelism 256
- 100ms RTT timeout, 30s host timeout
- Lightweight version detection (`-sV --version-intensity 2`) if vulnerability check enabled.

---

## 7. Command‑Line Reference

```
usage: cli.py [targets] [options]

positional arguments:
  targets               Target IP(s) or CIDR

optional arguments:
  -m, --mode {quick,common,full,custom,turbo}
                        Scan mode (default: quick)
  --stealth             Enable stealth mode (T2, delays, decoys)
  --vuln-check          Enable vulnerability detection (NSE + NVD)
  --nvd-key KEY         NVD API key
  --vulners-key KEY     Vulners API key
  --nmap-args ARGS      Additional Nmap arguments
  -t, --threads N       Max parallel target scans (default: 10)
  -o, --output NAME     Base filename for report (without extension)
  --format {json,csv,html,all}
                        Output format (default: json)
  --verbose             Verbose console output
  --aggressive          Aggressive timing (T5, 2000 pps)
  --turbo               Enable turbo mode (ultra-fast)
  --fragment            Fragment IP packets (-f)
  --source-port PORT    Spoof source port
  --spoof-mac MAC       Spoof MAC address
  --decoys IP1,IP2,...  Comma-separated decoy IPs
  --ttl VALUE           Set IP time-to-live
  --auth-check          Attempt basic auth checks
  --auto-save           Auto-save report in reports/ folder
  --deep-inspect        Enable deep active inspection (default: on)
  --no-deep-inspect     Disable deep inspection
  --skip-ping           Do NOT add -Pn (let Nmap perform host discovery)
  --ipv6                Scan using IPv6
  --email ADDRESS       Send report via email (requires SMTP config)
  --slack URL           Slack webhook URL
  --config FILE         YAML/JSON config file
  --interactive         Force interactive menu
```

---

## 8. Interactive Menu

Running `cli.py` without arguments opens the new categorised menu:

### Main Menu
```
[1] Network Discovery & Port Scanning
[2] Vulnerability Assessment & Exploit Detection
[3] Full Attack Surface Analysis (Network + Vulns)
[4] About
[5] Update & Maintenance
[0] Exit
```

### Network Discovery Sub‑menu
Quick / Full / Turbo / Stealth / IPv6 / Custom port scans – no vulnerability checks.

### Vulnerability Assessment Sub‑menu
- Quick security scan (common ports + NSE scripts)
- Common security scan (top 1000 ports, version + NSE)
- Deep vulnerability scan (online NVD/Vulners, deep inspection)
- Web application security scan (HTTP headers, TLS)
- Active Directory / Kerberos focused scan
- Custom vulnerability scan

### Full Attack Surface Analysis Sub‑menu
Combines network scanning and vulnerability detection:
- Standard full scan
- Aggressive full scan (with online lookups)
- Stealth full scan
- Turbo combo (critical ports + vulns)

After selecting a preset, you can enable auto‑save and choose the report format.

---

## 9. Output & Reporting

Reports are generated in four formats:

- **Console:** Coloured summary with severity‑aware output (Critical=Red, High=Light Red, Medium=Yellow, Low=Blue).
- **JSON:** Full machine‑readable data (includes CVSS, severity, exploit links).
- **CSV:** Spreadsheet with columns: Proto/Port, Service, Product, Version, CVE, Severity, CVSS, Description, Exploit Links.
- **HTML:** Styled page with colour‑coded severity rows, clickable exploit links.

Use `--format all` to generate all three file formats.

---

## 10. Auto‑Save Feature

When `--auto-save` is used, reports are saved in the `reports/` folder with filename:

```
reports/<target>_<timestamp>.<ext>
```

Example: `reports/192.168.1.10_20260729_143015.json`.

This feature is ideal for automated and recurring scans.

---

## 11. Attack Surface Modules

Open ports are automatically mapped to attack modules:

| Module                | Ports                          | Proto | Example Attacks                       |
|-----------------------|--------------------------------|-------|---------------------------------------|
| DHCP Attacker         | 67, 68                         | UDP   | DHCP spoofing, starvation             |
| DNS Attacker          | 53                             | TCP   | Cache poisoning, tunnelling           |
| AD Attacker           | 88,135,139,389,464,636,3268,3269 | TCP   | Kerberoasting, DCSync, LDAP injection |
| SMB Attacker          | 139, 445                       | TCP   | EternalBlue, SMBGhost, Pass‑the‑hash  |
| SNMP Sniffinger       | 161, 162                       | UDP   | Default communities, info disclosure  |
| DoS Amplification     | 19,123,520,1900,11211           | UDP   | NTP amp, SSDP amp, memcached amp      |
| Install & Update      | 80,443,3389,5985,5986,8530,8531 | TCP  | WSUS hijack, WinRM abuse, RDP brute   |
| Print Spooler         | 515, 9100                      | TCP   | PrintNightmare                       |
| LDAP Signing          | 389, 636                       | TCP   | LDAP without signing / channel binding|
| MSSQL Attacker        | 1433                           | TCP   | SQL injection, RCE                     |
| Kerberos Attacker     | 88                             | TCP   | Kerberoasting                         |
| WinRM Attacker        | 5985, 5986                     | TCP   | Remote command execution               |
| RDP Attacker          | 3389                           | TCP   | BlueKeep, password spraying            |
| FTP / SSH Brute       | 21, 22                         | TCP   | Bruteforce, weak credentials          |
| HTTP(S) Exploitation  | 80,443,8080,8443               | TCP   | Web app attacks, path traversal       |

---

## 12. Vulnerability Detection

The scanner uses multiple layers:

1. **Static Database** – built‑in signatures for well‑known vulnerabilities (can be extended via `static_vulns.json`). Examples: MS17-010, BlueKeep, SMBGhost, SigRed.

2. **NSE Scripts** – when `--vuln-check` is active, a comprehensive set of NSE scripts are executed (`vulners`, `vuln`, `smb-vuln-*`, `rdp-vuln-*`, `http-vuln-*`, `ssl-*`). Their output is parsed into the vulnerability list.

3. **Live NVD Lookup** – service name, product, and version are sent to the NVD API (requires `--vuln-check`). Each result includes **CVE ID, description, CVSS score, and severity** (Critical, High, Medium, Low, Unknown). Caching prevents repeated API calls.

4. **Vulners Exploit Search** – when a Vulners API key is supplied, the scanner searches for public exploits for each CVE. Results are displayed with direct links.

5. **Exploit‑DB** – automatically generates a search link for every CVE.

All vulnerabilities are enriched with:
- Severity colour coding in console and HTML reports
- Exploit maturity flag (whether public exploits are known)
- CVSS score for risk assessment

---

## 13. Deep Inspection

With **deep inspection** enabled (default), the scanner performs active, non‑destructive checks directly against services:

- **FTP:** attempts anonymous login (`anonymous/anonymous`)
- **HTTP/HTTPS:** checks for missing security headers (HSTS, X-Frame-Options, CSP, etc.)
- **TLS/SSL:** tests for weak protocols (TLSv1.0/1.1), expired certificates, and self‑signed certificates

These findings are reported as vulnerabilities with appropriate severity and appear alongside CVE results.

Disable deep inspection with `--no-deep-inspect` if you prefer passive scanning only.

---

## 14. Evasion & Advanced Options

- **Stealth Mode** (`--stealth`): T2 timing, 500ms delays, random host order, reduced threads.
- **Aggressive Mode** (`--aggressive`): T5, 2000 pps min, short timeouts.
- **Fragment packets** (`--fragment`), **spoof source port** (`--source-port`), **spoof MAC** (`--spoof-mac`), **decoys** (`--decoys`), **custom TTL** (`--ttl`).
- **Host discovery control**: by default `-Pn` is used (skip ping). Use `--skip-ping` to let Nmap perform ping sweep before scanning.
- **IPv6 scanning**: activate with `--ipv6`.

---

## 15. Configuration File

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

Usage: `sudo python3 cli.py 192.168.1.0/24 --config config.yaml`

---

## 16. Examples

**Quick network scan (no vulns)**
```bash
sudo python3 cli.py 192.168.1.10 -m quick
```

**Common security scan with auto‑save**
```bash
sudo python3 cli.py 192.168.1.0/24 -m common --vuln-check --auto-save --format html
```

**Deep vulnerability scan with online lookups**
```bash
sudo python3 cli.py 10.0.0.1 -m common --vuln-check --nvd-key YOUR_KEY --vulners-key YOUR_KEY --deep-inspect --auto-save
```

**Turbo scan with vulns (fastest security assessment)**
```bash
sudo python3 cli.py target.com --turbo --vuln-check --auto-save
```

**IPv6 scan**
```bash
sudo python3 cli.py fe80::1 --ipv6 -m quick
```

**Stealth scan with custom decoys, no deep inspection**
```bash
sudo python3 cli.py 10.0.0.0/24 --stealth --decoys 10.0.0.1,10.0.0.2 --no-deep-inspect --vuln-check
```

**Custom Nmap arguments**
```bash
sudo python3 cli.py 192.168.1.1 -m custom --nmap-args "-p 80,443 --script http-enum" --deep-inspect
```

---

## 17. FAQ

**Q: Do I need root?**  
A: Yes, for SYN scan, UDP scan, and OS detection.

**Q: How long does a full scan take?**  
A: For a single host, a full 65535‑port scan may take 1–4 hours. Turbo mode finishes in <30 seconds.

**Q: Is the scanner OS‑agnostic?**  
A: Yes. Works on Windows, Linux, macOS, and most devices.

**Q: What if I don't have an API key?**  
A: CVE lookups still work but are rate‑limited. Exploit search requires a Vulners key.

**Q: Can I extend the static vulnerability database?**  
A: Yes, create a `static_vulns.json` file in the scanner's directory with the desired entries.

**Q: Where are reports saved?**  
A: In the `reports/` subfolder next to `cli.py`.

---

## 18. Legal Disclaimer

**⚠️ WARNING**  
This tool is intended for **authorised security testing only**.  
You must have **explicit written permission** from the system owner before scanning any network or host.

Unauthorised scanning is illegal under applicable laws (CFAA, Computer Misuse Act, etc.).  
The author assumes **no liability** for misuse or damage caused by this tool.

**Use at your own risk.**