```markdown
# Nemesis Scanner – Shadow Edition v3.1.0

**Author:** Erfan Nahidi  
**License:** For authorised security testing only.  
**Repository:** *(wherever you host it)*

---

## 📖 Table of Contents

1. [Introduction](#introduction)
2. [System Requirements](#system-requirements)
3. [Installation](#installation)
4. [Quick Start](#quick-start)
5. [Scan Modes](#scan-modes)
6. [Command-Line Reference](#command-line-reference)
7. [Interactive Menu](#interactive-menu)
8. [Output & Reporting](#output--reporting)
9. [Auto-Save Feature](#auto-save-feature)
10. [Attack Surface Modules](#attack-surface-modules)
11. [Vulnerability Detection](#vulnerability-detection)
12. [Evasion & Advanced Options](#evasion--advanced-options)
13. [Configuration File](#configuration-file)
14. [Examples](#examples)
15. [FAQ](#faq)
16. [Legal Disclaimer](#legal-disclaimer)

---

## 1. Introduction

**Nemesis Scanner** is an advanced, cross‑platform network reconnaissance and vulnerability scanner.  
It uses Nmap as its core scanning engine and enriches the results with:

- Service version detection
- OS fingerprinting
- Attack surface mapping to known attack modules
- Static vulnerability database (well‑known Windows/Linux/Network CVEs)
- **Live CVE lookup** via NIST NVD and Vulners API
- **Exploit search** links (Exploit‑DB and Vulners)
- Multi‑format reporting (console, JSON, CSV, HTML)
- Slack / Email notifications
- **Turbo mode** for ultra‑fast scanning of critical ports

The tool is designed for penetration testers, red teamers, and security auditors who need a fast, thorough, and portable scanner that works on **any operating system** (Windows, Linux, macOS, routers, IoT devices, etc.).

---

## 2. System Requirements

- **Operating System:** Linux, macOS, Windows (with Nmap installed)
- **Python:** 3.8 or higher
- **Nmap:** 7.80+ (must be in PATH; root/sudo required for SYN scan, UDP scan, OS detection)
- **RAM:** 2 GB minimum (more for large subnets)
- **Network:** Internet connection for live CVE/exploit lookup (optional)

---

## 3. Installation

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
tqdm
colorama
pyyaml
jinja2
```

Or manually:
```bash
pip install python-nmap requests tqdm colorama pyyaml jinja2
```

### 3. Download the scanner

Copy `core.py` and `cli.py` into the same directory.

### 4. (Optional) Get API keys for extended features

- **NVD API key:** https://nvd.nist.gov/developers/request-an-api-key  
  (increases rate limit from 5 to 50 requests per 30 seconds)
- **Vulners API key:** https://vulners.com/ (free registration)  
  (required for exploit search)

---

## 4. Quick Start

**Command line (direct):**
```bash
sudo python3 cli.py 192.168.1.10 -m quick
```

**Interactive menu:**
```bash
sudo python3 cli.py
```
Then choose `[1] Quick Scan (presets)` → `[1] Quick scan`.

---

## 5. Scan Modes

| Mode       | TCP Ports               | UDP Ports       | Version / OS | Scripts / Vuln Check | Speed  |
|------------|--------------------------|-----------------|--------------|----------------------|--------|
| `quick`    | ~38 critical ports       | ~10 common UDP  | No           | No                   | Fast   |
| `common`   | Top 1000 TCP             | 20 common UDP   | Yes          | Optional (--vuln-check) | Medium |
| `full`     | All 65,535 TCP           | 20 common UDP   | Yes          | Optional             | Very Slow |
| `custom`   | Defined by `--nmap-args` | As per args     | As per args  | Optional             | Varies |
| `turbo`    | Top 15 critical TCP + UDP| Top 6 UDP       | Optional     | Optional             | Ultra‑Fast |
| Security   | `common` mode + `--vuln-check` | –           | Yes          | Yes                  | Medium |

**Turbo mode** uses:
- T5 timing, 10,000 packets/sec minimum rate
- No ping, no DNS resolution
- Max parallelism 256 probes
- 100ms RTT timeout, zero retries
- 30s host timeout
- Optional lightweight version detection (`-sV --version-intensity 2`) if `--vuln-check` is used.

---

## 6. Command‑Line Reference

```
usage: cli.py [targets] [options]

positional arguments:
  targets               Target IP(s) or CIDR (space or comma separated)

optional arguments:
  -m, --mode {quick,common,full,custom,turbo}
                        Scan mode (default: quick)
  --stealth             Enable stealth mode (T2, decoys, delays)
  --vuln-check          Enable live CVE lookup (NVD + scripts)
  --nvd-key KEY         NVD API key
  --vulners-key KEY     Vulners API key for exploit search
  --nmap-args ARGS      Additional Nmap arguments (use with custom mode)
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
  --auto-save           Auto-save report in `reports/` folder with IP+timestamp
  --email ADDRESS       Send report via email (requires SMTP config)
  --slack URL           Slack webhook URL for notification
  --config FILE         YAML/JSON config file with defaults
  --interactive         Force interactive menu even if arguments are given
```

---

## 7. Interactive Menu

Running `cli.py` without arguments opens a full‑screen menu:

### Main Menu
```
[1] Quick Scan (presets)
[2] Advanced Configuration (wizard)
[3] Enter raw scanner arguments
[0] Exit
```

### Quick Scan Presets
```
[1] Quick scan (common ports, fast)
[2] Common scan (top 1000 ports, version & scripts)
[3] Full scan (all 65535 ports, very slow)
[4] Security scan (common + vulnerability check)
[5] Turbo scan (ultra-fast, top critical ports)
[0] Back
```
After choosing a mode, you’ll be prompted for a target and whether to **auto‑save** the report.

### Advanced Configuration (Wizard)
Step‑by‑step setup for all options: scan mode, stealth, vulnerability checks, API keys, extra Nmap flags, threads, output format, auto‑save, evasion options, etc.  
At the end, a summary is shown and the scan is launched.

### Raw Arguments
Enter arguments as you would on the command line, e.g.:
```
192.168.0.0/24 -m common --auto-save --format html
```

---

## 8. Output & Reporting

Reports are generated in four formats:

- **Console:** Coloured, real‑time summary with services, attack modules, and vulnerabilities.
- **JSON:** Full structured data for further processing.
- **CSV:** Spreadsheet‑ready table (service, product, version, CVE, exploit links).
- **HTML:** Styled page with tables and clickable exploit links (requires Jinja2).

When `-o my_scan` is given, files are created as `my_scan.json`, `my_scan.csv`, etc.  
Use `--format all` to generate all three file formats.

---

## 9. Auto‑Save Feature

When `--auto-save` is used (or selected in the interactive menu), reports are saved in the **`reports/`** folder (created automatically) with the following naming scheme:

```
reports/<target>_<timestamp>.<ext>
```

Example:
```
reports/192.168.1.10_20260725_143015.json
```

The timestamp is in `YYYYMMDD_HHMMSS` format.  
You can specify the format via `--format` (default: json).  
This feature is ideal for automated scans and logging.

---

## 10. Attack Surface Modules

Detected services are automatically mapped to attack modules based on their port and protocol.  
These modules help identify potential attack vectors:

| Module                | Ports                          | Proto | Attack Examples                       |
|-----------------------|--------------------------------|-------|---------------------------------------|
| DHCP Attacker         | 67, 68                         | UDP   | DHCP spoofing, starvation             |
| DNS Attacker          | 53                             | TCP   | DNS cache poisoning, tunnelling       |
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

## 11. Vulnerability Detection

The scanner uses three layers:

1. **Static database** – built‑in signatures for well‑known vulnerabilities:
   - MS17-010 (EternalBlue), CVE-2020-0796 (SMBGhost), CVE-2019-0708 (BlueKeep), CVE-2020-1350 (SigRed), etc.
   - Also includes Apache and IIS specific CVEs.

2. **NSE Scripts** (when `--vuln-check` is active with common/full modes):
   - `vulners`, `vuln`, `smb-vuln-*`, `rdp-vuln-*`, `http-vuln-*`, `ssl-*` scripts are executed.
   - Their output is parsed and added to the vulnerability list.

3. **Live CVE lookup via NIST NVD** (requires `--vuln-check`):
   - Service name, product, and version are sent to the NVD API.
   - Up to 5 CVEs are returned per service.

Additionally, if a **Vulners API key** is provided, the scanner searches for **exploit entries** for each CVE, and provides **Exploit‑DB** search links.

All vulnerabilities appear in the console, JSON/CSV/HTML reports with:
- CVE ID
- Description
- Exploit links (clickable in HTML)

---

## 12. Evasion & Advanced Options

The scanner includes several advanced features to tailor scans and bypass detection:

### Turbo Mode (`--turbo`)
- Maximum speed: T5, 10k pps, no retries, no ping, no DNS, SYN scan.
- Ideal for initial wide‑range recon.

### Stealth Mode (`--stealth`)
- T2 timing, 500ms delays, random host order, decoy IPs, limited retries.
- Reduces the chance of triggering IDS/IPS.

### Aggressive Mode (`--aggressive`)
- T5, 2000 pps minimum rate, short timeouts.
- Faster than normal but still noisy.

### Evasion Techniques
- `--fragment` – fragment IP packets.
- `--source-port` – spoof source port (e.g., 53 for DNS).
- `--spoof-mac` – spoof MAC address.
- `--decoys` – comma‑separated decoy IPs.
- `--ttl` – set custom TTL value.

### Other Options
- `-t / --threads` – parallel scans for multiple targets (default 10, capped at 2 in stealth mode).
- `--auth-check` – attempt basic authentication checks on services (future expansion).

---

## 13. Configuration File

You can store default arguments and SMTP settings in a YAML or JSON file.

**Example YAML (`config.yaml`):**
```yaml
mode: common
vuln_check: true
nvd_key: "your-nvd-api-key"
vulners_key: "your-vulners-key"
threads: 5
auto_save: true
format: json
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
Command‑line arguments override the file.

---

## 14. Examples

### Basic quick scan of a single host
```bash
sudo python3 cli.py 192.168.1.10 -m quick
```

### Full subnet scan with vulnerability check and auto‑save
```bash
sudo python3 cli.py 192.168.1.0/24 -m common --vuln-check --auto-save --format html
```

### Turbo scan of a critical server and email notification
```bash
sudo python3 cli.py 10.0.0.1 --turbo --vuln-check --auto-save --email admin@domain.com --config mail_config.yaml
```

### Stealthy scan with decoys
```bash
sudo python3 cli.py target.com -m common --stealth --decoys 10.0.0.1,10.0.0.2
```

### Custom Nmap arguments
```bash
sudo python3 cli.py 192.168.1.1 -m custom --nmap-args "-p 80,443 --script http-enum"
```

### Interactive mode with auto‑save
```bash
sudo python3 cli.py --interactive
```

---

## 15. FAQ

**Q: Do I need to run as root?**  
A: Yes, for SYN scan, UDP scan, and OS detection, root/sudo is required.

**Q: How long does a full scan take?**  
A: For one host, a full 65535‑port scan can take 1–4 hours. Turbo mode finishes in under 30 seconds.

**Q: Can I scan non‑Windows targets?**  
A: Absolutely. The scanner is completely OS‑agnostic.

**Q: What if I don’t have an API key?**  
A: Without a key, CVE lookups are still possible but are rate‑limited (5 requests/30s). Exploit search requires a Vulners key.

**Q: Where are the reports saved when using `--auto-save`?**  
A: They are stored in the `reports/` subfolder next to the script.

---

## 16. Legal Disclaimer

**⚠️ WARNING**  
This tool is intended for **authorised security testing only**.  
You must have **explicit written permission** from the system owner before scanning any network or host.

Unauthorised scanning is illegal under computer misuse laws (e.g., CFAA in the USA, Computer Misuse Act in the UK, etc.).  
The author assumes **no liability** for misuse or damage caused by this tool.

**Use at your own risk.**
```