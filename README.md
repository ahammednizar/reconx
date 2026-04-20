<div align="center">

```
██████╗ ███████╗ ██████╗ ██████╗ ███╗   ██╗██╗  ██╗
██╔══██╗██╔════╝██╔════╝██╔═══██╗████╗  ██║╚██╗██╔╝
██████╔╝█████╗  ██║     ██║   ██║██╔██╗ ██║ ╚███╔╝
██╔══██╗██╔══╝  ██║     ██║   ██║██║╚██╗██║ ██╔██╗
██║  ██║███████╗╚██████╗╚██████╔╝██║ ╚████║██╔╝ ██╗
╚═╝  ╚═╝╚══════╝ ╚═════╝ ╚═════╝ ╚═╝  ╚═══╝╚═╝  ╚═╝
```

**Professional Reconnaissance Framework — Single-File Python Tool**

[![Python](https://img.shields.io/badge/Python-3.9%2B-3776ab?style=for-the-badge&logo=python&logoColor=white)](https://python.org)
[![Version](https://img.shields.io/badge/Version-1.0.0-00d4ff?style=for-the-badge)](https://github.com/ahammednizar/reconx/releases)
[![License](https://img.shields.io/badge/License-MIT-2ed573?style=for-the-badge)](LICENSE)
[![Authorized Only](https://img.shields.io/badge/⚠_USE-AUTHORIZED_ONLY-ff4757?style=for-the-badge)](#legal)

[![CI](https://github.com/ahammednizar/reconx/actions/workflows/ci.yml/badge.svg)](https://github.com/ahammednizar/reconx/actions/workflows/ci.yml)
[![Security](https://github.com/ahammednizar/reconx/actions/workflows/codeql.yml/badge.svg)](https://github.com/ahammednizar/reconx/security)
[![PRs Welcome](https://img.shields.io/badge/PRs-welcome-brightgreen.svg?style=flat-square)](CONTRIBUTING.md)

</div>

---

> ⚠️ **FOR AUTHORIZED PENETRATION TESTING ONLY.** Running ReconX against systems you do not own or lack **explicit written permission** to test is illegal. The authors bear no liability for unauthorized use.

---

## What Is ReconX?

ReconX is a **single-file** Python reconnaissance framework for penetration testers and security researchers. Drop one `.py` file anywhere, install five pip packages, and you have a full OSINT + active recon toolkit that outputs professional HTML reports with risk-severity labels.

```
python reconx.py -d target.com --full
```

---

## Features

### 🔍 Passive Reconnaissance
| Module | What It Does |
|--------|-------------|
| `whois` | Domain registration, registrant contacts, nameservers |
| `dns` | A/MX/NS/TXT/SOA/CAA records · SPF/DMARC/DKIM checks · Zone transfer test |
| `subdomains` | Certificate transparency (crt.sh) + 115-name DNS brute-force |
| `tech` | HTTP fingerprinting · 20+ tech signatures · SSL cert · robots.txt |
| `email` | Email harvesting from public pages + naming pattern inference |
| `dorks` | 12 Google dork templates auto-generated (admin panels, backups, API keys…) |

### ⚡ Active Reconnaissance
| Module | What It Does |
|--------|-------------|
| `ports` | 42-port TCP connect scan · service detection · banner grabbing · risk labeling |

### 📊 Reporting
- **Interactive HTML** — dark-theme report, click-to-expand findings, CRITICAL/HIGH auto-opened
- **JSON export** — machine-readable, pipeline-friendly
- **Audit log** — timestamped record of every action per session
- **5-tier risk labels** — CRITICAL · HIGH · MEDIUM · LOW · INFO

---

## Quick Start

```bash
# Clone
git clone https://github.com/ahammednizar/reconx.git
cd reconx

# Install deps (one-time)
pip install -r requirements.txt

# Run passive recon
python reconx.py -d example.com

# Full scan (passive + port scan)
python reconx.py -d example.com --full

# Specific modules
python reconx.py -d example.com -m whois,dns,subdomains,tech
```

---

## Installation

### Option 1 — Clone & Run (Recommended)
```bash
git clone https://github.com/ahammednizar/reconx.git
cd reconx
pip install -r requirements.txt
python reconx.py --help
```

### Option 2 — Virtual Environment
```bash
git clone https://github.com/ahammednizar/reconx.git
cd reconx
python -m venv venv
source venv/bin/activate        # Windows: venv\Scripts\activate
pip install -r requirements.txt
python reconx.py -d example.com
```

### Option 3 — Docker
```bash
docker build -t reconx .
docker run --rm -v $(pwd)/output:/app/reconx_output reconx \
  -d example.com --no-auth --full
```

### Dependencies
```
python-whois    WHOIS lookups
dnspython       DNS enumeration
requests        HTTP requests
beautifulsoup4  HTML parsing
colorama        Terminal colors (cross-platform)
jinja2          HTML report templating
```
All deps degrade gracefully if missing — the tool still runs with reduced functionality.

---

## Usage Reference

```
python reconx.py [-h] (-d DOMAIN | -i IP)
                 [--passive | --active | --full]
                 [-m MODULE1,MODULE2]
                 [--no-html] [--json-only] [--no-auth]
```

| Flag | Description |
|------|-------------|
| `-d DOMAIN` | Target domain name |
| `-i IP` | Target IP address |
| `--passive` | Passive recon only (default) |
| `--active` | Active recon only (port scan) |
| `--full` | Full passive + active scan |
| `-m mod1,mod2` | Run specific modules |
| `--no-html` | Skip HTML report generation |
| `--json-only` | JSON output only |
| `--no-auth` | Skip authorization prompt (CI/CD use) |

### Examples
```bash
# Standard passive OSINT
python reconx.py -d example.com

# Full recon with all modules
python reconx.py -d example.com --full

# Port scan an IP
python reconx.py -i 10.10.10.5 --active

# Only DNS + tech + ports
python reconx.py -d example.com -m dns,tech,ports

# CI pipeline (no prompt, JSON output)
python reconx.py -d example.com --passive --no-auth --json-only
```

---

## Output Structure

```
reconx_output/    ← JSON reports  (auto-created)
reconx_reports/   ← HTML reports  (auto-created)
reconx_logs/      ← Audit logs    (auto-created)
```

### Risk Severity Legend
| Level | Meaning | SLA |
|-------|---------|-----|
| 🔴 CRITICAL | Immediately exploitable | Fix in 24h |
| 🟠 HIGH | Significant exposure | Fix in 72h |
| 🟡 MEDIUM | Notable risk | Fix in 2 weeks |
| 🟢 LOW | Minor risk | Next cycle |
| 🔵 INFO | Informational | Track only |

---

## Project Structure

```
reconx/
├── reconx.py            ← The entire tool (single file, 1375 lines)
├── requirements.txt     ← Runtime dependencies
├── requirements-dev.txt ← Dev/test dependencies
├── Dockerfile           ← Container build
├── docker-compose.yml   ← Compose config
├── .gitignore
├── LICENSE
├── CONTRIBUTING.md
├── SECURITY.md
├── tests/
│   ├── test_models.py
│   ├── test_config.py
│   ├── test_modules.py
│   └── test_reports.py
└── .github/
    ├── workflows/
    │   ├── ci.yml       ← Test + lint + Docker build
    │   └── codeql.yml   ← Security analysis
    ├── ISSUE_TEMPLATE/
    │   ├── bug_report.md
    │   └── feature_request.md
    └── PULL_REQUEST_TEMPLATE.md
```

---

## Contributing

Contributions are welcome! See [CONTRIBUTING.md](CONTRIBUTING.md) for the full guide including how to write a new recon module.

```bash
git checkout -b feature/my-new-module
# make changes
pytest tests/ -v
# open PR
```

---

## Roadmap

- [ ] Shodan API integration
- [ ] CVE correlation for detected service versions
- [ ] PDF report export
- [ ] Async I/O for faster scanning
- [ ] Config file (YAML) support
- [ ] OS fingerprinting via nmap
- [ ] OSINT: LinkedIn + breach data lookup

---

## Legal Disclaimer <a name="legal"></a>

ReconX is designed for **lawful security assessments only**.

By using this tool you confirm:
1. You own the target, or have **explicit written authorization** to scan it
2. Your use complies with all applicable laws
3. You accept full personal responsibility for your actions

The authors are **not liable** for misuse, damage, or legal consequences arising from unauthorized scanning.

---

## License

[MIT License](LICENSE) — Copyright (c) 2024 ReconX Project Contributors

---

<div align="center">
  Built for the security community · Use responsibly · ⭐ Star if useful
</div>
