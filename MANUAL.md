# Nemesis Scanner v4.1.1 — Full Manual

[English README](README.md) · [راهنمای فارسی](README_FA.md)

## 1. Overview

Nemesis Scanner is a Python command-line interface around Nmap. It supports authorized network scans, service and version discovery, local vulnerability-signature matching, optional online NVD lookup, selected active service checks, and reports.

The application has two distinct uses:

- **Scan a target:** starts Nmap and creates a new result.
- **Review a saved result:** reads the latest JSON report for an IP and reviews it without starting Nmap.

Only scan systems covered by explicit authorization. Agree on the target scope, testing window, rate, and notification plan with the owner. Reports can include sensitive network and software-version data.

## 2. Installation

### 2.1 Prerequisites

- Python 3.8 or newer.
- Nmap 7.80 or newer available on `PATH`.
- Dependencies listed in `requirements.txt`.
- Internet access for online NVD/Vulners lookup and Git updates.

Some Nmap scan types and OS detection require elevated privileges. Run with the least privilege required by the selected scan and local policy.

### 2.2 Install Nmap

Debian/Ubuntu:

```bash
sudo apt update
sudo apt install nmap
```

macOS:

```bash
brew install nmap
```

Windows: install Nmap from [nmap.org](https://nmap.org/download.html) and add it to `PATH`.

### 2.3 Install Python requirements

From the project directory:

```bash
python -m pip install -r requirements.txt
```

The required runtime packages are `python-nmap`, `requests`, and `colorama`. `Jinja2` is optional and enables HTML reports; without it, JSON and CSV reports are still available.

### 2.4 Optional API keys

- **NVD:** request a key from [NVD](https://nvd.nist.gov/developers/request-an-api-key). It may improve rate limits for Online queries.
- **Vulners:** optional key from [Vulners](https://vulners.com); used only for exploit enrichment in supported flows.

Do not put secrets in public repositories, screenshots, or shared reports.

## 3. Launching the CLI

Interactive mode:

```bash
python cli.py
```

Direct mode:

```bash
python cli.py 192.0.2.10 -m quick
```

`192.0.2.10` is reserved for documentation. Replace it only with an authorized target.

Force the interactive menu:

```bash
python cli.py --interactive
```

The terminal UI uses the red Nemesis ASCII logo and compact numbered menus. Non-TTY output disables ANSI colors.

## 4. Main menu

The main menu offers:

1. **Network Discovery & Port Scanning:** choose a network scan preset.
2. **Vulnerability Assessment:** review a saved result by IP or open new vulnerability-scan presets.
3. **Full Attack Surface Analysis:** choose a combined scan preset.
4. **About:** project and version information.
5. **Update & Maintenance:** Git update and Python dependency actions.
0. **Exit.**

Menu input is numeric. Invalid choices are rejected and the menu remains available.

## 5. Network scan presets

| Preset | Behavior | Relative duration |
| --- | --- | --- |
| Quick TCP | Curated common TCP/UDP ports | Shortest general preset |
| Full TCP | TCP ports 1–65535 plus the configured UDP list | Longest preset |
| Turbo | Limited critical TCP/UDP list and aggressive Nmap timing | Fast, limited coverage |
| Stealth SYN | Uses slower Nmap timing; may require elevated privileges | Slower |
| IPv6 | Adds Nmap IPv6 mode | Depends on target/network |
| Custom | Passes user-provided extra Nmap arguments | Depends on arguments |

Port coverage and duration are approximate. Filtering, dropped packets, target response, privileges, and network quality can greatly change run time. Turbo deliberately checks fewer ports and can miss services.

After selecting a preset, the menu asks for the target. It then asks whether to save a report automatically. When enabled, choose JSON, CSV, or HTML. The destination is `./reports/`.

## 6. Vulnerability assessment

### 6.1 Review a saved result

Choose **Vulnerability Assessment → Review a previous result**, enter an IPv4 or IPv6 address, and select the review level. The tool finds the latest matching JSON report in `reports/` using report-file modification time. If no report exists for that IP, run an authorized scan and save its report first.

| Level | Inputs | Network activity |
| --- | --- | --- |
| Quick | Existing report findings | None |
| Medium | Existing findings plus local signatures in `core/static_vulns.json` | None |
| Deep | Medium findings plus fresh NVD lookups for up to six services | NVD HTTP requests only; no new Nmap scan |

Deep requests are limited to six services in the report to bound the number of online lookups. NVD can still rate-limit or delay requests. An optional NVD API key can help with rate limits.

If a fresh NVD request fails and a matching response is cached, the cached result is returned with `data_source=local_cache_fallback`; the UI indicates that it is not fresh data. Successful fresh responses are stored in the per-user data directory (`~/.local/share/nemesis-scanner/` on Linux/macOS or `%LOCALAPPDATA%\\nemesis-scanner\\` on Windows).

After review, the user may save the reviewed findings separately. The output is `reports/<target>_review.json`.

### 6.2 New vulnerability scan presets

The menu provides:

- **Quick:** essential port preset with vulnerability correlation enabled.
- **Medium:** common port range and version detection.
- **Deep:** common scan plus online options and deep inspection.
- **Web checks:** HTTP header/TLS inspection preset.
- **Directory services:** common scan with optional extra Nmap arguments.
- **Custom:** choose mode, Nmap vulnerability scripts, source, API keys, and deep inspection.

For supported presets, choose the CVE source:

- **Offline:** local signature matching; no NVD request.
- **Online:** fresh NVD query for discovered services. Successful responses populate the NVD cache.

The local signature file is `core/static_vulns.json`. It is manually maintained; the application does not automatically download or update this file. Online NVD results are separate from these local signatures.

## 7. Full Attack Surface Analysis presets

The combined menu offers Standard, Aggressive, Stealth, and Turbo. Each option starts a new scan with the corresponding Nmap and vulnerability settings. The menu asks whether to save the resulting report. Review later through the saved-result workflow by IP.

## 8. Scan mode details

| Mode | TCP selection | UDP selection | Notes |
| --- | --- | --- | --- |
| `quick` | Curated list of about 38 common ports | Curated common list | Shorter list; service detection depends on vulnerability settings. |
| `common` | 1–1000 | Configured common UDP list | Version detection enabled. |
| `full` | 1–65535 | Configured common UDP list | Can take a long time. |
| `turbo` | Curated critical list | Curated critical list | Uses T5, high packet rate, short timeouts, and limited port coverage. |
| `custom` | Nmap arguments | Nmap arguments | Use `--nmap-args` to supply extra Nmap flags. |

The Turbo arguments include `-Pn` by default, no DNS lookup, no retries, and a 30-second host timeout. These are configuration values, not a guarantee of total scan duration.

## 9. CLI argument reference

```text
usage: cli.py [targets ...] [options]

Targets:
  IP address, hostname, or CIDR

Options:
  -m, --mode MODE          quick|common|full|custom|turbo (default: quick)
  -t, --threads N          parallel target tasks (default: 10)
  -o, --output NAME        output base path, no extension
  --format FORMAT          json|csv|html|all (default: json)
  --vuln-check             enable vulnerability correlation / Nmap scripts
  --vuln-source SOURCE     offline|online (default: offline)
  --nvd-key KEY            NVD API key
  --vulners-key KEY        Vulners API key
  --nmap-args ARGS         additional Nmap arguments
  --stealth                slower stealth timing profile
  --aggressive             aggressive timing profile
  --turbo                  turbo port/timing profile
  --fragment               request Nmap IP fragmentation
  --source-port PORT       set source port
  --spoof-mac MAC          set MAC address option
  --decoys LIST            comma-separated Nmap decoy values
  --ttl VALUE              packet TTL
  --auth-check             reserved option; no current scan action
  --auto-save              save a timestamped report under reports/
  --deep-inspect           enable deep service checks (default enabled)
  --no-deep-inspect        disable deep service checks
  --skip-ping              allow Nmap host discovery instead of default -Pn
  --ipv6                   IPv6 scan mode
  --email ADDRESS          parsed; not currently sent by scan runner
  --slack URL              parsed; not currently sent by scan runner
  --config FILE            parsed; configuration loading is not implemented
  --interactive            force the interactive menu
```

### Examples

```bash
# Quick scan of an authorized host
python cli.py 192.0.2.10 -m quick

# Common scan, local vulnerability correlation, timestamped JSON report
python cli.py 192.0.2.10 -m common --vuln-check --vuln-source offline --auto-save

# Write JSON, CSV, and HTML using an explicit output base
python cli.py 192.0.2.10 -m common --vuln-check -o reports/assessment --format all

# Force interactive mode
python cli.py --interactive
```

`--format all` applies to the explicit `-o` output path and writes all three extensions. Auto-save writes one chosen format. In non-interactive mode, auto-save with `--format all` selects JSON.

## 10. Reports

### Formats

- **Console:** colored summary of target, OS, services, modules, and findings.
- **JSON:** complete structured result including raw service data.
- **CSV:** rows for services and associated vulnerability fields.
- **HTML:** styled report generated when Jinja2 is installed.

### Paths

- Scan: `reports/<sanitized-target>_<YYYYMMDD_HHMMSS>.<ext>`.
- Review: `reports/<target>_review.json`.

Reports may contain internal IPs, service banners, product versions, CVE findings, and timestamps. Store and share them according to your organization’s data-handling rules.

## 11. Vulnerability data and caching

### Local signatures

`core/static_vulns.json` contains manually maintained service/product-version signatures. Its JSON structure maps keys such as `"smb,1.0"` to a list of description strings. To add an entry, preserve valid JSON and the same key/list structure. The scanner does not automatically update this file.

### NVD cache

Online queries go to the NVD CVE API. Successful results are cached in the per-user data directory and can be reused by an Offline lookup for an exactly matching query term. Online requests are fresh; cache is only used for Offline lookup or as a labeled fallback if NVD is unavailable.

NVD keyword results are candidates, not confirmation that a CVE affects the device. Confirm the exact vendor, product, version, configuration, and advisory before making remediation decisions.

### Vulners and Exploit-DB

Vulners search requires a Vulners API key. Exploit-DB links are search URLs for manual reference; the tool does not execute exploits.

## 12. Service inspection and severity

When deep inspection is enabled, the scanner performs checks such as anonymous FTP login attempts, HTTP security-header checks, and TLS protocol/certificate checks. These are active requests to discovered services and must only be used within authorized scope.

Severity and CVSS availability depend on the source record. Local signature severity is inferred from simple description keywords; it is not a vendor-confirmed risk score. NVD CVSS information is more specific, but still requires validation against the actual installed product/version.

## 13. Dependency list

- `python-nmap`: Python interface to the Nmap executable.
- `requests`: online NVD and Vulners HTTP requests.
- `colorama`: colored console reports.
- `jinja2` (optional): HTML report generation.

`PyYAML` and `tqdm` are not currently required by the code. The `--config` option is accepted by the argument parser but config-file loading is not implemented.

## 14. Troubleshooting

**Nmap executable not found**

Install Nmap and make sure `nmap` is available on `PATH`.

**Permission denied or incomplete scan**

Some scan types require elevated privileges. Confirm authorization and use only the privilege level required for the selected scan.

**No saved report for the IP**

Run an authorized scan, enable auto-save, and verify a JSON report exists in `reports/` for the same IP.

**Deep review takes time or returns fewer results**

Deep performs up to six NVD requests. Network delays, NVD rate limiting, service/product keyword quality, and API availability affect the result.

**Cache fallback notice appears**

NVD was unavailable; the displayed cached entries are not fresh. Retry later if current data is required.

**HTML output is skipped**

Install Jinja2 in the Python environment used to run Nemesis Scanner.

**Python import errors**

Activate the intended environment and run `python -m pip install -r requirements.txt` using that same Python interpreter.

## 15. Legal notice

Nemesis Scanner is for authorized security assessment only. Obtain explicit permission, define the scope, and coordinate testing windows before scanning. The maintainers assume no responsibility for unauthorized use, service impact, or damages.
