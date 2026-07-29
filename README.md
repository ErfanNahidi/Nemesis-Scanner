[🇮🇷 نسخهٔ فارسی](README_FA.md)

# Nemesis Scanner – Shadow Edition

[![Python 3.8+](https://img.shields.io/badge/python-3.8+-blue.svg)](https://www.python.org/downloads/)
[![License](https://img.shields.io/badge/license-Custom-red.svg)](LICENSE)
[![Version](https://img.shields.io/badge/version-2.1.0-green.svg)]()

An advanced, cross‑platform network reconnaissance and vulnerability scanner built on **Nmap**.  
Designed for penetration testers, red teams, and security auditors who need fast, thorough scans **on any operating system**.

## ✨ Features

- **Multiple scan modes** – Quick, Common, Full, Custom, and **Turbo** (ultra‑fast)
- **Service & OS detection** with Nmap NSE scripts
- **Vulnerability detection** – static database + live CVE lookup via NVD & Vulners
- **Exploit correlation** – links to Exploit‑DB and Vulners exploits
- **Attack surface mapping** – automatically maps open ports to known attack modules
- **Multi‑format reporting** – console, JSON, CSV, HTML
- **Auto‑save reports** with IP + timestamp in `reports/` folder
- **Notifications** – email and Slack webhooks
- **Evasion techniques** – stealth mode, decoys, fragmentation, MAC spoofing, etc.
- **Interactive menu** – no need to remember command‑line flags
- **Fully cross‑platform** – works on Windows, Linux, macOS, routers, IoT devices…

## 📦 Installation

### 1. Install Nmap
```bash
# Debian/Ubuntu/Kali
sudo apt install nmap

# macOS
brew install nmap
```

### 2. Install Python dependencies
```bash
pip install python-nmap requests tqdm colorama pyyaml jinja2
```

### 3. Clone the repo
```bash
git clone https://github.com/yourusername/nemesis-scanner.git
cd nemesis-scanner
```

## 🚀 Quick Start

**Command line:**
```bash
sudo python3 cli.py 192.168.1.10 -m quick
```

**Interactive menu:**
```bash
sudo python3 cli.py
```

## 📖 Documentation

For a complete guide (scan modes, command reference, advanced options, configuration files, FAQ), see the **[MANUAL.md](MANUAL.md)**.

## ⚠️ Legal Disclaimer

This tool is for **authorised security testing only**. You must have **explicit written permission** from the system owner before use.  
Unauthorised scanning is illegal. The author assumes no liability for misuse.

**Use at your own risk.**
