# Nemesis Scanner v4.1.0

[فارسی](README_FA.md) · [Full Manual](MANUAL.md)

Nemesis Scanner is a Python command-line interface around Nmap. It can scan explicitly authorized targets, correlate discovered services with local vulnerability signatures, optionally query the NIST National Vulnerability Database (NVD), inspect selected services, and write reports.

> Use only on systems and networks that you own or are explicitly authorized to assess. Scanning can disrupt services and may require elevated privileges.

## What’s in v4.1

- Compact, red Nemesis-branded interactive menus with a persistent ASCII logo.
- Network scan presets: Quick, Full, Turbo, Stealth, IPv6, and Custom.
- Vulnerability scan presets with Offline or Online CVE sources.
- Saved-report review by device IP at Quick, Medium, and Deep levels.
- Deep saved-report review refreshes CVEs online for at most six services; it does not start a new scan.
- JSON, CSV, and HTML reports, plus optional automatic report saving.
- Local signatures in `core/static_vulns.json` and persistent NVD response cache in `core/nvd_cache.json`.

## Requirements

- Python 3.8 or later.
- Nmap 7.80 or later installed and available as `nmap` on `PATH`.
- Python dependencies from `requirements.txt`.
- Internet access only for Online NVD/Vulners lookups and project updates.

Some Nmap scan types and operating-system detection need administrator/root privileges. Follow your organization’s authorization and change-control requirements.

## Install

Install Nmap first.

```bash
# Debian / Ubuntu
sudo apt update
sudo apt install nmap

# macOS
brew install nmap
```

On Windows, install Nmap from [nmap.org](https://nmap.org/download.html) and add its installation directory to `PATH`.

Install Python dependencies from the project root:

```bash
python -m pip install -r requirements.txt
```

Jinja2 is optional and is only needed for HTML reports. If it is absent, JSON and CSV reports remain available.

## Start

Open the interactive menu:

```bash
python cli.py
```

Run a scan from the command line:

```bash
python cli.py 192.0.2.10 -m quick
```

`192.0.2.10` is a documentation-only example address. Replace it only with an authorized target.

The menu keeps two workflows distinct:

1. **New scan:** runs Nmap using a selected preset and can save the resulting report.
2. **Review a previous result:** reads the latest saved JSON report for an IP and reviews its findings without starting a network scan.

## Interactive menus

### Network Discovery & Port Scanning

- **Quick TCP scan:** common TCP and UDP port lists; shortest preset.
- **Full TCP scan:** TCP ports 1–65535 and the configured common UDP list; longest preset.
- **Turbo scan:** small critical-port list; optimized for speed and may miss services on other ports.
- **Stealth SYN scan:** slower Nmap timing profile. Use only with written authorization.
- **IPv6 scan:** adds Nmap IPv6 mode.
- **Custom scan:** accepts extra Nmap arguments.

The scan prompts whether to save a report automatically. If enabled, choose JSON, CSV, or HTML. Files are written under `reports/` with the target and timestamp in the filename.

### Vulnerability Assessment

Choose **Review a previous result** or **Start a new vulnerability scan**.

A saved-report review asks for the device IP and uses its latest matching JSON report in `reports/`:

| Level | Data source | Network activity |
| --- | --- | --- |
| Quick | Findings already in the saved report | None |
| Medium | Saved findings plus `core/static_vulns.json` signatures | None |
| Deep | Medium data plus fresh NVD requests for up to six reported services | NVD requests only; no new Nmap scan |

Deep can take longer and may be rate-limited by NVD. An optional NVD API key can improve the API rate limit. If a fresh request fails and a matching cache entry exists, the cached result is marked as a fallback. The review displays severity totals and can save a separate reviewed report under `reports/`.

New vulnerability scans offer Quick, Medium, Deep, Web checks, Directory services, and Custom presets. The available CVE source selection is Offline or Online NVD. Online NVD queries require internet access; Vulners enrichment requires its API key.

### Full Attack Surface Analysis

The Full menu provides Standard, Aggressive, Stealth, and Turbo presets. Each starts a new scan. Choose report auto-save after selecting a preset if a saved JSON/CSV/HTML file is needed for later IP-based review.

## Scan modes

| Mode | TCP ports | UDP ports | Notes |
| --- | --- | --- | --- |
| `quick` | Curated common list (about 38 ports) | Curated common list | Shorter preset; service/version checks depend on vulnerability options. |
| `common` | 1–1000 | Curated common UDP list | Version detection is enabled. |
| `full` | 1–65535 | Curated common UDP list | Most thorough and can take substantially longer. |
| `turbo` | Curated critical list | Curated critical list | Fast, limited coverage. |
| `custom` | As supplied in `--nmap-args` | As supplied in `--nmap-args` | Custom Nmap arguments are passed through. |

Actual duration depends on target reachability, filtering, network conditions, privileges, and Nmap behavior. No preset can guarantee a completion time.

## Command-line options

```text
usage: cli.py [targets ...] [options]

positional arguments:
  targets                    IP addresses, hostnames, or CIDR targets

options:
  -m, --mode MODE            quick, common, full, custom, or turbo (default: quick)
  -t, --threads N            parallel target tasks (default: 10)
  -o, --output NAME          output base path, without extension
  --format FORMAT            json, csv, html, or all (default: json)
  --vuln-check               enable vulnerability correlation / Nmap scripts
  --vuln-source SOURCE       offline or online (default: offline)
  --nvd-key KEY              NVD API key
  --vulners-key KEY          Vulners API key for exploit enrichment
  --nmap-args ARGS           extra Nmap arguments
  --stealth                  use the slower stealth timing profile
  --aggressive               use the aggressive timing profile
  --turbo                    use the turbo port/timing profile
  --fragment                 request IP packet fragmentation from Nmap
  --source-port PORT         set source port
  --spoof-mac MAC            set MAC address option
  --decoys LIST              comma-separated Nmap decoy values
  --ttl VALUE                set packet TTL
  --auth-check               reserved basic-auth option
  --auto-save                save a timestamped report under reports/
  --deep-inspect             enable deep service checks (default: enabled)
  --no-deep-inspect          disable deep service checks
  --skip-ping                allow Nmap host discovery instead of default -Pn
  --ipv6                     enable IPv6 mode
  --email ADDRESS            parsed notification option
  --slack URL                parsed notification option
  --config FILE              accepted for compatibility; config loading is not implemented
  --interactive              open the interactive menu
```

Examples:

```bash
# Scan an authorized host using the quick preset
python cli.py 192.0.2.10 -m quick

# Enable vulnerability correlation and save JSON automatically
python cli.py 192.0.2.10 -m common --vuln-check --vuln-source offline --auto-save

# Write all supported report types using an explicit output base
python cli.py 192.0.2.10 -m common --vuln-check -o reports/example --format all

# Open the menu even when other command-line arguments are present
python cli.py --interactive
```

`--config`, `--email`, and `--slack` are parsed but are not currently applied by the scan runner. `--format all` applies to explicit `-o` output. Auto-save writes one selected format; the interactive menu asks which one.

## CVE sources, local data, and cache

- `core/static_vulns.json` is the hand-maintained local signature list used by Offline/Medium review. Entries use keys such as `"smb,1.0"` and lists of descriptions.
- Online NVD lookups make fresh requests and store successful responses in `core/nvd_cache.json`.
- Offline NVD lookup can read previously cached NVD responses for matching query terms. The local signature file and NVD cache are separate.
- NVD results are keyword matches against service/product/version strings, not proof that a particular CVE applies. Verify product/version and vendor advisories before taking action.
- No automatic updater for `static_vulns.json` is included.

Get an NVD API key at [NVD API Key Request](https://nvd.nist.gov/developers/request-an-api-key). Vulners keys are optional and only needed for Vulners exploit enrichment.

## Reports and data locations

- Timestamped scan reports: `reports/<target>_<YYYYMMDD_HHMMSS>.<ext>`.
- Reviewed reports: `reports/<target>_review.json`.
- Local signatures: `core/static_vulns.json`.
- NVD response cache: `core/nvd_cache.json`.

Reports can contain IP addresses, discovered services, versions, vulnerability details, and timestamps. Treat them as sensitive assessment data.

## Troubleshooting

- **Nmap not found:** install Nmap and confirm it is on `PATH`.
- **Permission errors or incomplete scan:** some Nmap modes need elevated privileges. Use only in an authorized environment.
- **No saved report for an IP:** run an authorized scan and enable report saving first; review uses the latest report matching that IP.
- **Online review returns cached data:** the UI marks cache fallback when NVD is unavailable; it is not a fresh response.
- **NVD rate limiting:** reduce the number of online lookups or request/use an NVD API key.
- **HTML report skipped:** install Jinja2 with `python -m pip install jinja2`.
- **Missing Python module:** install required dependencies with `python -m pip install -r requirements.txt` in the same environment used to run the scanner.

## Authorization

Use this software only for systems you own or have explicit written authorization to assess. Confirm scope, timing, rate limits, and notification requirements with the system owner. The project authors are not responsible for unauthorized use or resulting damage.
