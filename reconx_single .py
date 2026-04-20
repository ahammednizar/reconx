#!/usr/bin/env python3
"""
╔══════════════════════════════════════════════════════════════════════════════╗
║                                                                              ║
║    ██████╗ ███████╗ ██████╗ ██████╗ ███╗   ██╗██╗  ██╗                     ║
║    ██╔══██╗██╔════╝██╔════╝██╔═══██╗████╗  ██║╚██╗██╔╝                     ║
║    ██████╔╝█████╗  ██║     ██║   ██║██╔██╗ ██║ ╚███╔╝                      ║
║    ██╔══██╗██╔══╝  ██║     ██║   ██║██║╚██╗██║ ██╔██╗                      ║
║    ██║  ██║███████╗╚██████╗╚██████╔╝██║ ╚████║██╔╝ ██╗                     ║
║    ╚═╝  ╚═╝╚══════╝ ╚═════╝ ╚═════╝ ╚═╝  ╚═══╝╚═╝  ╚═╝  v1.0.0           ║
║                                                                              ║
║    Professional Reconnaissance Framework for Ethical Hacking & Pen-Test     ║
║                                                                              ║
║    ⚠  FOR AUTHORIZED PENETRATION TESTING AND SECURITY RESEARCH ONLY  ⚠     ║
║                                                                              ║
╚══════════════════════════════════════════════════════════════════════════════╝

Usage:
  python reconx_single.py -d example.com                  # Passive recon (default)
  python reconx_single.py -d example.com --full           # Full passive + active
  python reconx_single.py -d example.com --active         # Active only (ports)
  python reconx_single.py -d example.com -m whois,dns,tech
  python reconx_single.py -i 192.168.1.1 --active
  python reconx_single.py -d example.com --no-auth        # Skip auth prompt

Install dependencies:
  pip install python-whois dnspython requests beautifulsoup4 colorama jinja2
"""

# ══════════════════════════════════════════════════════════════════════════════
# STDLIB IMPORTS
# ══════════════════════════════════════════════════════════════════════════════
import argparse
import json
import logging
import os
import re
import socket
import ssl
import sys
import threading
import time
from abc import ABC, abstractmethod
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Optional

# ══════════════════════════════════════════════════════════════════════════════
# THIRD-PARTY IMPORTS  (pip install python-whois dnspython requests
#                            beautifulsoup4 colorama jinja2)
# ══════════════════════════════════════════════════════════════════════════════
try:
    import whois
except ImportError:
    whois = None

try:
    import dns.resolver
    import dns.zone
    import dns.query
    import dns.exception
except ImportError:
    dns = None

try:
    import requests
    from bs4 import BeautifulSoup
    requests.packages.urllib3.disable_warnings()        # suppress InsecureRequestWarning
except ImportError:
    requests = None
    BeautifulSoup = None

try:
    from colorama import Fore, Style, init as colorama_init
    colorama_init(autoreset=True)
    _COLOR = True
except ImportError:
    _COLOR = False
    class Fore:
        CYAN = RED = GREEN = YELLOW = BLUE = MAGENTA = WHITE = ""
    class Style:
        BRIGHT = DIM = RESET_ALL = ""

try:
    from jinja2 import Template
    _JINJA = True
except ImportError:
    _JINJA = False


# ══════════════════════════════════════════════════════════════════════════════
# ─────────────────────────────  SECTION 1  ───────────────────────────────────
#                           CONFIGURATION & CONSTANTS
# ══════════════════════════════════════════════════════════════════════════════

TOOL_NAME    = "ReconX"
TOOL_VERSION = "1.0.0"

# ── Output directories (created automatically) ────────────────────────────────
BASE_DIR   = os.path.dirname(os.path.abspath(__file__))
OUTPUT_DIR = os.path.join(BASE_DIR, "reconx_output")
LOG_DIR    = os.path.join(BASE_DIR, "reconx_logs")
REPORT_DIR = os.path.join(BASE_DIR, "reconx_reports")
for _d in (OUTPUT_DIR, LOG_DIR, REPORT_DIR):
    os.makedirs(_d, exist_ok=True)

# ── Timeouts & rate limiting ──────────────────────────────────────────────────
HTTP_TIMEOUT      = 10
DNS_TIMEOUT       = 5
PORT_SCAN_TIMEOUT = 2
RATE_LIMIT_DELAY  = 0.5
MAX_THREADS       = 20

# ── Risk constants ────────────────────────────────────────────────────────────
RISK_CRITICAL = "CRITICAL"
RISK_HIGH     = "HIGH"
RISK_MEDIUM   = "MEDIUM"
RISK_LOW      = "LOW"
RISK_INFO     = "INFO"

# ── Common TCP ports ──────────────────────────────────────────────────────────
COMMON_PORTS = [
    21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143,
    443, 445, 465, 587, 631, 993, 995, 1433, 1521, 2049,
    3000, 3306, 3389, 4444, 5000, 5432, 5900, 6379, 6443,
    7001, 8000, 8080, 8081, 8443, 8888, 9090, 9200, 9300,
    27017, 27018, 28017,
]

# port → (service_label, risk_level)
PORT_META: dict[int, tuple[str, str]] = {
    21:    ("FTP",            RISK_HIGH),
    22:    ("SSH",            RISK_INFO),
    23:    ("Telnet",         RISK_CRITICAL),
    25:    ("SMTP",           RISK_MEDIUM),
    53:    ("DNS",            RISK_LOW),
    80:    ("HTTP",           RISK_INFO),
    110:   ("POP3",           RISK_MEDIUM),
    111:   ("RPCBind",        RISK_HIGH),
    135:   ("MSRPC",          RISK_HIGH),
    139:   ("NetBIOS",        RISK_HIGH),
    143:   ("IMAP",           RISK_MEDIUM),
    443:   ("HTTPS",          RISK_INFO),
    445:   ("SMB",            RISK_CRITICAL),
    465:   ("SMTPS",          RISK_LOW),
    587:   ("Submission",     RISK_LOW),
    1433:  ("MSSQL",          RISK_CRITICAL),
    1521:  ("Oracle DB",      RISK_CRITICAL),
    2049:  ("NFS",            RISK_HIGH),
    3000:  ("Dev Server",     RISK_MEDIUM),
    3306:  ("MySQL",          RISK_HIGH),
    3389:  ("RDP",            RISK_HIGH),
    4444:  ("Metasploit?",    RISK_CRITICAL),
    5000:  ("Dev/Flask",      RISK_MEDIUM),
    5432:  ("PostgreSQL",     RISK_HIGH),
    5900:  ("VNC",            RISK_HIGH),
    6379:  ("Redis",          RISK_CRITICAL),
    7001:  ("WebLogic",       RISK_HIGH),
    8080:  ("HTTP-Alt",       RISK_LOW),
    8443:  ("HTTPS-Alt",      RISK_LOW),
    8888:  ("Jupyter/Dev",    RISK_HIGH),
    9090:  ("Admin Panel?",   RISK_MEDIUM),
    9200:  ("Elasticsearch",  RISK_CRITICAL),
    27017: ("MongoDB",        RISK_CRITICAL),
    27018: ("MongoDB",        RISK_CRITICAL),
    28017: ("MongoDB HTTP",   RISK_CRITICAL),
}

CRITICALLY_RISKY_PORTS = {23, 445, 1433, 1521, 4444, 6379, 9200, 27017, 27018}

# ── Subdomain wordlist ────────────────────────────────────────────────────────
COMMON_SUBDOMAINS = [
    "www", "mail", "ftp", "smtp", "pop", "imap", "vpn", "remote",
    "dev", "staging", "test", "api", "cdn", "admin", "portal",
    "dashboard", "app", "apps", "beta", "alpha", "demo", "docs",
    "blog", "shop", "store", "m", "mobile", "static", "assets",
    "img", "images", "media", "upload", "uploads", "download",
    "ns1", "ns2", "mx", "mx1", "mx2", "webmail", "autodiscover",
    "autoconfig", "gateway", "proxy", "firewall", "git", "gitlab",
    "github", "jira", "confluence", "jenkins", "monitor", "status",
    "grafana", "kibana", "elastic", "db", "database", "sql",
    "mysql", "postgres", "redis", "mongo", "internal", "intranet",
    "corp", "corporate", "old", "new", "secure", "ssl", "help",
    "support", "wiki", "backup", "log", "logs", "prod", "production",
    "stage", "uat", "qa", "hr", "erp", "crm", "vpn2", "office",
    "cloud", "auth", "login", "sso", "id", "identity", "ws", "wss",
    "socket", "chat", "video", "meet", "calendar", "files", "share",
    "exchange", "owa", "remote", "rdp", "citrix", "console", "cp",
    "cpanel", "whm", "plesk", "phpmyadmin", "pma",
]

# ── Technology fingerprints ───────────────────────────────────────────────────
TECH_FINGERPRINTS = {
    "WordPress":    {"headers": [],                          "body": ["wp-content", "wp-includes", "WordPress"]},
    "Drupal":       {"headers": ["X-Generator: Drupal"],     "body": ["Drupal.settings", "/sites/default"]},
    "Joomla":       {"headers": [],                          "body": ["/components/com_", "Joomla!"]},
    "React":        {"headers": [],                          "body": ["__react", "data-reactroot", "react-dom"]},
    "Angular":      {"headers": [],                          "body": ["ng-version", "angular.min.js", "_nghost"]},
    "Vue.js":       {"headers": [],                          "body": ["__vue__", "data-v-", "vue.min.js"]},
    "jQuery":       {"headers": [],                          "body": ["jquery.min.js", "jQuery(", "jquery-"]},
    "Bootstrap":    {"headers": [],                          "body": ["bootstrap.min.css", "bootstrap.min.js"]},
    "Apache":       {"headers": ["Server: Apache"],          "body": []},
    "Nginx":        {"headers": ["Server: nginx"],           "body": []},
    "IIS":          {"headers": ["Server: Microsoft-IIS"],   "body": []},
    "PHP":          {"headers": ["X-Powered-By: PHP"],       "body": []},
    "ASP.NET":      {"headers": ["X-Powered-By: ASP.NET", "X-AspNet-Version"], "body": ["__VIEWSTATE"]},
    "Django":       {"headers": [],                          "body": ["csrfmiddlewaretoken", "django"]},
    "Flask":        {"headers": ["Server: Werkzeug"],        "body": []},
    "Laravel":      {"headers": [],                          "body": ["laravel_session", "XSRF-TOKEN"]},
    "Shopify":      {"headers": ["X-ShopId"],                "body": ["Shopify.shop", "myshopify.com"]},
    "Cloudflare":   {"headers": ["CF-RAY", "cf-cache-status"], "body": []},
    "AWS":          {"headers": ["x-amz-", "X-Amz-"],        "body": []},
    "Google Cloud": {"headers": ["x-goog-", "via: 1.1 google"], "body": []},
}

# ── Google dork templates ─────────────────────────────────────────────────────
GOOGLE_DORKS = {
    "Admin Panels":      'site:{domain} inurl:admin OR inurl:administrator OR inurl:login OR inurl:wp-admin',
    "Login Pages":       'site:{domain} inurl:login OR inurl:signin OR inurl:auth',
    "Config Files":      'site:{domain} ext:xml OR ext:conf OR ext:cnf OR ext:ini OR ext:env OR ext:log',
    "Database Files":    'site:{domain} ext:sql OR ext:dbf OR ext:mdb',
    "Backup Files":      'site:{domain} ext:bkf OR ext:bak OR ext:old OR ext:backup',
    "Exposed Passwords": 'site:{domain} intext:password OR intext:passwd OR intext:pwd filetype:log',
    "API Keys":          'site:{domain} intext:"api_key" OR intext:"api-key" OR intext:"apikey"',
    "Directory Listing": 'site:{domain} intitle:"index of" OR intitle:"directory listing"',
    "Error Messages":    'site:{domain} intext:"sql syntax" OR intext:"mysql_fetch" OR intext:"ORA-"',
    "Sensitive Docs":    'site:{domain} filetype:pdf OR filetype:doc OR filetype:xls confidential',
    "Git Exposed":       'site:{domain} inurl:".git" OR inurl:"/.git/config"',
    "Email Lists":       'site:{domain} filetype:xls OR filetype:csv intext:email',
}

HIGH_RISK_DORK_CATS = {"Config Files", "Database Files", "Backup Files", "Exposed Passwords", "API Keys"}

USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/121.0",
]

EMAIL_RE = re.compile(r"[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}")

RISK_COLORS_HTML = {
    RISK_CRITICAL: "#ff4757",
    RISK_HIGH:     "#ff6b35",
    RISK_MEDIUM:   "#ffa502",
    RISK_LOW:      "#2ed573",
    RISK_INFO:     "#1e90ff",
}


# ══════════════════════════════════════════════════════════════════════════════
# ─────────────────────────────  SECTION 2  ───────────────────────────────────
#                             LOGGER  (dark-mode CLI)
# ══════════════════════════════════════════════════════════════════════════════

C = {
    "banner":   Fore.CYAN + Style.BRIGHT,
    "info":     Fore.BLUE + Style.BRIGHT,
    "success":  Fore.GREEN + Style.BRIGHT,
    "warn":     Fore.YELLOW + Style.BRIGHT,
    "error":    Fore.RED + Style.BRIGHT,
    "critical": Fore.MAGENTA + Style.BRIGHT,
    "dim":      Style.DIM,
    "reset":    Style.RESET_ALL,
    "header":   Fore.CYAN,
    "value":    Fore.WHITE + Style.BRIGHT,
    "muted":    Fore.WHITE + Style.DIM,
    "cyan":     Fore.CYAN,
    "risk_c":   Fore.RED + Style.BRIGHT,
    "risk_h":   Fore.RED,
    "risk_m":   Fore.YELLOW,
    "risk_l":   Fore.GREEN,
    "risk_i":   Fore.CYAN,
}

ICONS = {
    "info":     "[*]",
    "success":  "[+]",
    "warn":     "[!]",
    "error":    "[-]",
    "critical": "[!!]",
    "scan":     "[~]",
    "find":     "[>]",
}


class ReconLogger:
    """Colored console output + plain audit-log file."""

    def __init__(self, session_id: str):
        self.session_id = session_id
        self._actions:  list[dict] = []
        log_path = os.path.join(LOG_DIR, f"reconx_{session_id}.log")
        self._flog = logging.getLogger(f"reconx_{session_id}")
        self._flog.setLevel(logging.DEBUG)
        fh = logging.FileHandler(log_path)
        fh.setFormatter(logging.Formatter("%(asctime)s [%(levelname)s] %(message)s"))
        self._flog.addHandler(fh)

    # ── Console printers ──────────────────────────────────────────────────────
    def info(self, m):     print(f"{C['info']}{ICONS['info']}{C['reset']} {m}");     self._w("INFO",     m)
    def success(self, m):  print(f"{C['success']}{ICONS['success']}{C['reset']} {m}"); self._w("SUCCESS",  m)
    def warn(self, m):     print(f"{C['warn']}{ICONS['warn']}{C['reset']} {m}");      self._w("WARN",     m)
    def error(self, m):    print(f"{C['error']}{ICONS['error']}{C['reset']} {m}");    self._w("ERROR",    m)
    def critical(self, m): print(f"{C['critical']}{ICONS['critical']}{C['reset']} {m}"); self._w("CRITICAL", m)
    def find(self, m):     print(f"{C['success']}{ICONS['find']}{C['reset']} {C['value']}{m}{C['reset']}"); self._w("FIND", m)
    def scan(self, m):     print(f"{C['muted']}{ICONS['scan']} {m}{C['reset']}");     self._w("SCAN",     m)

    def module(self, name: str):
        bar = "─" * max(0, 50 - len(name) - 2)
        print(f"\n{C['header']}┌─ {name} {bar}┐{C['reset']}")
        self._w("MODULE", f"Started: {name}")

    def module_end(self):
        print(f"{C['header']}└{'─' * 52}┘{C['reset']}")

    def key_value(self, key: str, value, indent: int = 2):
        pad = " " * indent
        print(f"{pad}{C['muted']}{key:<22}{C['reset']}{C['value']}{value}{C['reset']}")

    def log_action(self, action: str, target: str, details: str = ""):
        self._actions.append({
            "timestamp": datetime.now(timezone.utc).replace(tzinfo=None).isoformat(),
            "action":    action,
            "target":    target,
            "details":   details,
        })
        self._w("ACTION", f"{action} → {target}: {details}")

    def get_actions(self) -> list[dict]:
        return self._actions

    def _w(self, level: str, msg: str):
        self._flog.info(f"[{level}] {msg}")


# ══════════════════════════════════════════════════════════════════════════════
# ─────────────────────────────  SECTION 3  ───────────────────────────────────
#                             DATA MODELS
# ══════════════════════════════════════════════════════════════════════════════

@dataclass
class Finding:
    category:    str
    title:       str
    data:        Any
    risk:        str = RISK_INFO
    description: str = ""
    timestamp:   str = field(default_factory=lambda: datetime.now(timezone.utc).replace(tzinfo=None).isoformat())

    def to_dict(self) -> dict:
        return {
            "category":    self.category,
            "title":       self.title,
            "data":        self.data,
            "risk":        self.risk,
            "description": self.description,
            "timestamp":   self.timestamp,
        }


@dataclass
class ReconResult:
    target:     str
    scan_type:  str
    started_at: str = field(default_factory=lambda: datetime.now(timezone.utc).replace(tzinfo=None).isoformat())
    ended_at:   Optional[str] = None
    findings:   list[Finding] = field(default_factory=list)
    metadata:   dict = field(default_factory=dict)
    actions:    list[dict] = field(default_factory=list)

    def add(self, f: Finding):
        self.findings.append(f)

    def finish(self):
        self.ended_at = datetime.now(timezone.utc).replace(tzinfo=None).isoformat()

    def summary(self) -> dict:
        c = {RISK_CRITICAL: 0, RISK_HIGH: 0, RISK_MEDIUM: 0, RISK_LOW: 0, RISK_INFO: 0}
        for f in self.findings:
            c[f.risk] = c.get(f.risk, 0) + 1
        return c

    def by_category(self) -> dict[str, list[Finding]]:
        out: dict[str, list[Finding]] = {}
        for f in self.findings:
            out.setdefault(f.category, []).append(f)
        return out

    def to_dict(self) -> dict:
        return {
            "meta": {
                "tool":       f"{TOOL_NAME} {TOOL_VERSION}",
                "target":     self.target,
                "scan_type":  self.scan_type,
                "started_at": self.started_at,
                "ended_at":   self.ended_at,
                "summary":    self.summary(),
            },
            "findings":   [f.to_dict() for f in self.findings],
            "categories": {cat: [f.to_dict() for f in fs] for cat, fs in self.by_category().items()},
            "audit_log":  self.actions,
        }

    def to_json(self, indent: int = 2) -> str:
        return json.dumps(self.to_dict(), indent=indent, default=str)


# ══════════════════════════════════════════════════════════════════════════════
# ─────────────────────────────  SECTION 4  ───────────────────────────────────
#                           RECON MODULES
# ══════════════════════════════════════════════════════════════════════════════

# ── 4A  WHOIS ─────────────────────────────────────────────────────────────────

def run_whois(target: str, result: ReconResult, log: ReconLogger):
    log.module("WHOIS Lookup")
    log.log_action("WHOIS", target)

    if whois is None:
        log.error("python-whois not installed  →  pip install python-whois")
        log.module_end(); return

    try:
        w = whois.whois(target)

        reg = {
            "domain_name":      _clean(w.domain_name),
            "registrar":        _clean(w.registrar),
            "creation_date":    str(w.creation_date),
            "expiration_date":  str(w.expiration_date),
            "updated_date":     str(w.updated_date),
            "status":           _clean(w.status),
            "dnssec":           _clean(w.dnssec),
        }
        log.find(f"Registrar: {reg['registrar']}")
        log.find(f"Created:   {reg['creation_date']}")
        log.find(f"Expires:   {reg['expiration_date']}")
        result.add(Finding("Passive Reconnaissance", "WHOIS Registration Data",
                            reg, RISK_INFO, "Domain registration and ownership information"))

        contact = {k: _clean(v) for k, v in {
            "registrant_name": getattr(w, "name", None),
            "org":             getattr(w, "org", None),
            "address":         getattr(w, "address", None),
            "city":            getattr(w, "city", None),
            "country":         getattr(w, "country", None),
            "emails":          w.emails,
            "phone":           getattr(w, "phone", None),
        }.items()}
        contact = {k: v for k, v in contact.items() if v not in (None, "None", [])}

        if contact:
            risk = RISK_MEDIUM if contact.get("emails") else RISK_LOW
            desc = "Registrant contact info exposed in public WHOIS"
            if contact.get("emails"):
                desc += " (email addresses found – potential phishing targets)"
                log.warn(f"Registrant emails exposed: {contact['emails']}")
            result.add(Finding("Passive Reconnaissance", "WHOIS Registrant Contact",
                                contact, risk, desc))

        ns = _clean(w.name_servers)
        if ns:
            ns_list = sorted({n.lower() for n in (ns if isinstance(ns, list) else [ns])})
            log.find(f"Nameservers: {', '.join(ns_list)}")
            result.add(Finding("Passive Reconnaissance", "WHOIS Nameservers",
                                ns_list, RISK_INFO, "Authoritative nameservers"))

    except Exception as e:
        log.error(f"WHOIS failed: {e}")
        result.add(Finding("Passive Reconnaissance", "WHOIS Lookup Failed", str(e), RISK_INFO))

    log.module_end()


# ── 4B  DNS ───────────────────────────────────────────────────────────────────

DNS_RECORD_TYPES = ["A", "AAAA", "MX", "NS", "TXT", "CNAME", "SOA", "SRV", "CAA"]

def run_dns(target: str, result: ReconResult, log: ReconLogger):
    log.module("DNS Enumeration")
    log.log_action("DNS_ENUM", target)

    if dns is None:
        log.error("dnspython not installed  →  pip install dnspython")
        log.module_end(); return

    resolver = dns.resolver.Resolver()
    resolver.timeout = resolver.lifetime = DNS_TIMEOUT

    # ── Record enumeration
    records: dict[str, list] = {}
    for rtype in DNS_RECORD_TYPES:
        try:
            answers = resolver.resolve(target, rtype)
            recs = [str(r) for r in answers]
            if recs:
                records[rtype] = recs
                preview = ", ".join(recs[:3]) + ("…" if len(recs) > 3 else "")
                log.find(f"{rtype:<6} → {preview}")
        except Exception:
            pass

    if records:
        result.add(Finding("Passive Reconnaissance", "DNS Records",
                            records, RISK_INFO, "All resolvable DNS records"))

    # ── IP resolution
    try:
        ip = socket.gethostbyname(target)
        log.find(f"Resolved IP: {ip}")
        result.add(Finding("Passive Reconnaissance", "Resolved IP Address", ip, RISK_INFO))
        result.metadata["resolved_ip"] = ip
    except Exception:
        pass

    # ── Email security checks
    issues = []
    try:
        txt = records.get("TXT", [])
        spf = [r for r in txt if "v=spf1" in r.lower()]
        if not spf:
            issues.append("No SPF record – domain may be spoofed for email phishing")
            log.warn("No SPF record found!")
        elif "+all" in " ".join(spf):
            issues.append("SPF uses '+all' – any server can send as this domain (critical)")
            log.warn("SPF '+all' detected – severe misconfiguration!")
    except Exception:
        pass

    try:
        dmarc = [str(r) for r in resolver.resolve(f"_dmarc.{target}", "TXT")]
        rec = " ".join(dmarc)
        if "p=none" in rec:
            issues.append("DMARC policy is 'none' – spoofed emails not quarantined/rejected")
    except Exception:
        issues.append("No DMARC record – email spoofing protection absent")
        log.warn("No DMARC record found!")

    for sel in ["default", "google", "mail", "k1", "dkim", "selector1", "selector2"]:
        try:
            dkim = [str(r) for r in resolver.resolve(f"{sel}._domainkey.{target}", "TXT")]
            if dkim:
                log.find(f"DKIM selector: {sel}")
                result.add(Finding("Passive Reconnaissance", f"DKIM Selector: {sel}",
                                    dkim, RISK_INFO))
        except Exception:
            pass

    if issues:
        risk = RISK_HIGH if any("spoof" in i.lower() for i in issues) else RISK_MEDIUM
        result.add(Finding("Passive Reconnaissance", "Email Security Misconfigurations",
                            issues, risk, "Missing/weak SPF or DMARC enables email spoofing attacks"))

    # ── Zone transfer attempt
    ns_list = records.get("NS", [])
    if ns_list:
        log.scan("Testing DNS zone transfer (AXFR)…")
        vulnerable = []
        for ns in ns_list[:3]:
            ns_clean = ns.rstrip(".")
            try:
                dns.zone.from_xfr(dns.query.xfr(ns_clean, target, timeout=5))
                vulnerable.append(ns_clean)
                log.critical(f"Zone transfer SUCCESSFUL on {ns_clean}!")
            except Exception:
                log.scan(f"Zone transfer blocked on {ns_clean}")
        if vulnerable:
            result.add(Finding("Passive Reconnaissance", "DNS Zone Transfer Vulnerability",
                                {"vulnerable_nameservers": vulnerable}, RISK_CRITICAL,
                                "AXFR allowed – full DNS zone exposed to anyone"))
        else:
            result.add(Finding("Passive Reconnaissance", "DNS Zone Transfer",
                                "All nameservers blocked zone transfer (AXFR)", RISK_INFO))

    log.module_end()


# ── 4C  SUBDOMAIN DISCOVERY ───────────────────────────────────────────────────

def run_subdomains(target: str, result: ReconResult, log: ReconLogger):
    log.module("Subdomain Discovery")
    log.log_action("SUBDOMAIN_ENUM", target)

    discovered: dict[str, str] = {}

    # Certificate Transparency via crt.sh
    if requests:
        try:
            url  = f"https://crt.sh/?q=%.{target}&output=json"
            resp = requests.get(url, timeout=HTTP_TIMEOUT, headers={"User-Agent": USER_AGENTS[0]})
            if resp.status_code == 200:
                names: set[str] = set()
                for entry in resp.json():
                    for name in entry.get("name_value", "").splitlines():
                        name = name.strip().lower().lstrip("*.")
                        if name.endswith(target) and name != target:
                            names.add(name)
                for name in names:
                    ip = _resolve(name)
                    discovered[name] = ip or "unresolved"
                    log.find(f"[CT]  {name} → {discovered[name]}")
        except Exception as e:
            log.warn(f"crt.sh query failed: {e}")

    # DNS brute-force
    log.scan(f"Brute-forcing {len(COMMON_SUBDOMAINS)} common subdomains…")
    lock = threading.Lock()

    def check(sub: str):
        fqdn = f"{sub}.{target}"
        ip   = _resolve(fqdn)
        if ip and fqdn not in discovered:
            with lock:
                discovered[fqdn] = ip
                log.find(f"[BF]  {fqdn} → {ip}")
        time.sleep(RATE_LIMIT_DELAY)

    with ThreadPoolExecutor(max_workers=MAX_THREADS) as ex:
        list(as_completed({ex.submit(check, s): s for s in COMMON_SUBDOMAINS}))

    if discovered:
        log.success(f"Total subdomains: {len(discovered)}")
        risk = RISK_MEDIUM if len(discovered) > 10 else RISK_LOW
        result.add(Finding("Passive Reconnaissance", "Discovered Subdomains",
                            discovered, risk,
                            f"{len(discovered)} subdomains enumerated – review for exposed dev/admin surfaces"))

        sensitive_kw = {"admin", "dev", "staging", "test", "internal", "vpn",
                        "git", "jenkins", "db", "database", "backup", "old",
                        "portal", "dashboard", "phpmyadmin", "pma", "kibana",
                        "grafana", "elastic", "mongo", "redis"}
        sensitive = {k: v for k, v in discovered.items()
                     if any(kw in k for kw in sensitive_kw)}
        if sensitive:
            log.warn(f"Sensitive subdomains: {list(sensitive.keys())}")
            result.add(Finding("Passive Reconnaissance", "Sensitive Subdomain Exposure",
                                sensitive, RISK_HIGH,
                                "Subdomains suggest internal infra, dev/CI, or admin systems are internet-facing"))
    else:
        log.info("No subdomains discovered")

    log.module_end()


# ── 4D  TECHNOLOGY STACK ──────────────────────────────────────────────────────

def run_tech_stack(target: str, result: ReconResult, log: ReconLogger):
    log.module("Technology Stack Detection")

    if requests is None:
        log.error("requests not installed  →  pip install requests beautifulsoup4")
        log.module_end(); return

    resp = None
    for scheme in ("https", "http"):
        url = f"{scheme}://{target}"
        log.log_action("HTTP_FINGERPRINT", url)
        try:
            resp = requests.get(url, timeout=HTTP_TIMEOUT,
                                headers={"User-Agent": USER_AGENTS[0]},
                                verify=False, allow_redirects=True)
            break
        except Exception as e:
            log.warn(f"Could not reach {url}: {e}")

    if resp is None:
        log.error("No HTTP response received"); log.module_end(); return

    headers_lower = {k.lower(): v for k, v in resp.headers.items()}
    body          = resp.text or ""

    log.key_value("Status",       resp.status_code)
    log.key_value("Final URL",    resp.url)
    log.key_value("Server",       headers_lower.get("server", "hidden"))
    log.key_value("Content-Type", headers_lower.get("content-type", "—"))

    # ── Missing security headers
    SECURITY_HEADERS = [
        "strict-transport-security", "content-security-policy",
        "x-frame-options", "x-content-type-options",
        "referrer-policy", "permissions-policy",
    ]
    missing = [h for h in SECURITY_HEADERS if h not in headers_lower]
    if missing:
        log.warn(f"Missing security headers: {missing}")
        result.add(Finding("Passive Reconnaissance", "Missing Security Headers",
                            missing, RISK_MEDIUM,
                            "Missing HTTP security headers expose site to clickjacking, XSS, and data leakage"))

    # ── Information-leaking headers
    leaky = {h: headers_lower[h] for h in
             ["server", "x-powered-by", "x-generator", "x-aspnet-version",
              "x-aspnetmvc-version", "x-drupal-cache", "via"]
             if h in headers_lower}
    if leaky:
        log.warn(f"Info-disclosing headers: {leaky}")
        result.add(Finding("Passive Reconnaissance", "Information-Disclosing Headers",
                            leaky, RISK_LOW,
                            "Server headers reveal tech versions – aids targeted CVE research"))

    # ── Tech fingerprints
    detected: list[str] = []
    for tech, sigs in TECH_FINGERPRINTS.items():
        found = False
        for h_sig in sigs["headers"]:
            hname, _, hval = h_sig.partition(": ")
            if hname.lower() in headers_lower:
                if not hval or hval.lower() in headers_lower[hname.lower()].lower():
                    found = True; break
        if not found:
            for b_sig in sigs["body"]:
                if b_sig.lower() in body.lower():
                    found = True; break
        if found:
            detected.append(tech)
            log.find(f"Technology: {tech}")

    if detected:
        result.add(Finding("Passive Reconnaissance", "Detected Technologies",
                            detected, RISK_INFO, "Identified web technologies and frameworks"))

    # ── SSL info
    if resp.url.startswith("https"):
        try:
            host = resp.url.replace("https://", "").split("/")[0]
            ctx  = ssl.create_default_context()
            conn = ctx.wrap_socket(socket.socket(), server_hostname=host)
            conn.settimeout(5); conn.connect((host, 443))
            cert = conn.getpeercert(); conn.close()
            ssl_info = {
                "subject":    dict(x[0] for x in cert.get("subject", [])),
                "issuer":     dict(x[0] for x in cert.get("issuer", [])),
                "not_before": cert.get("notBefore"),
                "not_after":  cert.get("notAfter"),
                "san":        cert.get("subjectAltName", []),
            }
            result.add(Finding("Passive Reconnaissance", "SSL/TLS Certificate", ssl_info, RISK_INFO))
        except Exception:
            pass

    # ── robots.txt / sitemap
    for path in ("/robots.txt", "/sitemap.xml"):
        try:
            base = f"{resp.url.split('//', 1)[0]}//{resp.url.split('//', 1)[1].split('/')[0]}"
            r2   = requests.get(base + path, timeout=5,
                                headers={"User-Agent": USER_AGENTS[0]}, verify=False)
            if r2.status_code == 200 and len(r2.text) > 10:
                disallowed = [l for l in r2.text.splitlines() if "disallow" in l.lower()]
                log.find(f"{path} ({len(r2.text)} bytes, {len(disallowed)} disallowed paths)")
                result.add(Finding("Passive Reconnaissance", f"File: {path}",
                                    {"content": r2.text[:2000], "disallowed_paths": disallowed},
                                    RISK_LOW if disallowed else RISK_INFO,
                                    f"{path} may reveal hidden paths and directories"))
        except Exception:
            pass

    # ── Full header dump
    result.add(Finding("Passive Reconnaissance", "HTTP Response Headers",
                        dict(resp.headers), RISK_INFO, "All HTTP response headers"))

    log.module_end()


# ── 4E  EMAIL HARVESTING ──────────────────────────────────────────────────────

HARVEST_PATHS = ["", "/about", "/contact", "/team", "/staff", "/people", "/company"]

def run_email_harvest(target: str, result: ReconResult, log: ReconLogger):
    log.module("Email Harvesting")
    log.log_action("EMAIL_HARVEST", target)

    if requests is None:
        log.error("requests not installed"); log.module_end(); return

    found: set[str] = set()
    hdrs  = {"User-Agent": USER_AGENTS[0]}

    for scheme in ("https", "http"):
        for path in HARVEST_PATHS:
            url = f"{scheme}://{target}{path}"
            try:
                r = requests.get(url, timeout=HTTP_TIMEOUT, headers=hdrs,
                                 verify=False, allow_redirects=True)
                if r.status_code == 200:
                    for e in EMAIL_RE.findall(r.text):
                        e = e.lower()
                        if target.lower() in e and e not in found:
                            found.add(e)
                            log.find(f"Email: {e}  [{url}]")
            except Exception:
                pass
            time.sleep(RATE_LIMIT_DELAY)
        break   # only try first working scheme

    if found:
        email_list = sorted(found)
        log.success(f"Harvested {len(email_list)} email address(es)")
        result.add(Finding("Passive Reconnaissance", "Harvested Email Addresses",
                            email_list, RISK_MEDIUM,
                            f"{len(email_list)} email(s) found – potential phishing / password spraying targets"))

        # Email naming pattern guess
        patterns: dict[str, str] = {}
        domains = {e.split("@")[1] for e in email_list}
        for d in domains:
            samples = [e.split("@")[0] for e in email_list if e.endswith(f"@{d}")]
            if samples:
                sample = samples[0]
                if "." in sample:
                    pat = "firstname.lastname@domain"
                elif len(sample) <= 3:
                    pat = "initials@domain"
                else:
                    pat = "username@domain"
                patterns[d] = pat
        result.add(Finding("Passive Reconnaissance", "Email Format Patterns",
                            patterns, RISK_INFO, "Guessed email naming convention (aids username enumeration)"))
    else:
        log.info("No email addresses found")

    log.module_end()


# ── 4F  GOOGLE DORKS ──────────────────────────────────────────────────────────

def run_google_dorks(target: str, result: ReconResult, log: ReconLogger):
    log.module("Google Dork Generator")
    log.log_action("GOOGLE_DORKS", target)

    generated: dict[str, str] = {}
    high_priority: list[str]  = []

    for label, template in GOOGLE_DORKS.items():
        query = template.format(domain=target)
        url   = "https://www.google.com/search?q=" + query.replace(" ", "+")
        generated[label] = url
        log.find(f"{label:<25} {url[:80]}")
        if label in HIGH_RISK_DORK_CATS:
            high_priority.append(label)

    result.add(Finding("Passive Reconnaissance", "Google Dork Queries",
                        generated, RISK_MEDIUM,
                        "Pre-built Google dork queries. Open each URL to search for exposed data indexed by Google."))

    if high_priority:
        log.warn(f"High-priority dork categories: {high_priority}")
        result.add(Finding("Passive Reconnaissance", "High-Priority Dork Categories",
                            high_priority, RISK_HIGH,
                            "These categories most likely surface critical exposures"))

    # Shodan links
    result.add(Finding("Passive Reconnaissance", "Shodan Search Links", {
        "Hostname":  f"https://www.shodan.io/search?query=hostname:{target}",
        "SSL Cert":  f"https://www.shodan.io/search?query=ssl:{target}",
        "Net Range": f"https://www.shodan.io/search?query=net:{target}",
    }, RISK_INFO, "Shodan queries for internet-facing infrastructure discovery"))

    log.module_end()


# ── 4G  PORT SCANNING ─────────────────────────────────────────────────────────

PORT_RISK_DESCRIPTIONS: dict[int, str] = {
    23:    "Telnet transmits credentials in plaintext – replace with SSH immediately",
    445:   "SMB exposed – risk of EternalBlue / WannaCry exploitation",
    1433:  "MSSQL exposed – restrict to internal network only",
    1521:  "Oracle DB exposed – restrict to trusted IPs only",
    4444:  "Port 4444 is the Metasploit default listener – investigate immediately",
    6379:  "Redis exposed without authentication – full cache read/write access",
    9200:  "Elasticsearch exposed – unauthenticated data access possible",
    27017: "MongoDB exposed without authentication – full database access",
}

def run_port_scan(target: str, result: ReconResult, log: ReconLogger):
    log.module("Port Scanning & Service Detection")

    host = result.metadata.get("resolved_ip") or target
    log.scan(f"TCP connect scan → {host}  ({len(COMMON_PORTS)} ports, {MAX_THREADS} threads)…")
    log.log_action("PORT_SCAN", host, f"ports={len(COMMON_PORTS)}")

    open_ports: list[dict] = []
    lock = threading.Lock()

    def probe(port: int):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(PORT_SCAN_TIMEOUT)
            if sock.connect_ex((host, port)) == 0:
                banner = ""
                try:
                    if port in (80, 8080, 8000, 8888):
                        sock.send(b"HEAD / HTTP/1.0\r\n\r\n")
                    elif port == 443:
                        banner = "SSL/TLS"
                    if not banner:
                        sock.settimeout(2)
                        banner = sock.recv(1024).decode("utf-8", errors="ignore").strip()[:200]
                except Exception:
                    pass
                sock.close()
                svc, _ = PORT_META.get(port, ("Unknown", RISK_INFO))
                with lock:
                    open_ports.append({"port": port, "state": "open",
                                       "service": svc, "banner": banner})
                    log.find(f"Port {port:>5}/tcp  OPEN  {svc:<18}  {banner[:50]}")
            else:
                sock.close()
        except Exception:
            pass

    with ThreadPoolExecutor(max_workers=MAX_THREADS) as ex:
        list(as_completed({ex.submit(probe, p): p for p in COMMON_PORTS}))

    open_ports.sort(key=lambda x: x["port"])

    if open_ports:
        log.success(f"{len(open_ports)} open port(s) found")
        result.add(Finding("Active Reconnaissance", "Open Ports", open_ports, RISK_INFO,
                            f"{len(open_ports)} TCP ports open"))

        for p in open_ports:
            port = p["port"]
            svc, risk = PORT_META.get(port, ("Unknown", RISK_LOW))
            if risk in (RISK_CRITICAL, RISK_HIGH):
                desc = PORT_RISK_DESCRIPTIONS.get(port, f"{svc} exposed – review firewall rules")
                lvl  = RISK_CRITICAL if port in CRITICALLY_RISKY_PORTS else RISK_HIGH
                if lvl == RISK_CRITICAL:
                    log.critical(f"Critical service exposed: {svc} on port {port}")
                else:
                    log.warn(f"High-risk service exposed: {svc} on port {port}")
                result.add(Finding("Active Reconnaissance",
                                    f"Exposed Service: {svc} (port {port})",
                                    p, lvl, desc))
    else:
        log.info("No open ports found on the common port list")

    log.module_end()


# ══════════════════════════════════════════════════════════════════════════════
# ─────────────────────────────  SECTION 5  ───────────────────────────────────
#                          HTML REPORT GENERATOR
# ══════════════════════════════════════════════════════════════════════════════

HTML_REPORT_TEMPLATE = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>ReconX Report &ndash; {{ target }}</title>
<style>
:root{--bg:#080d14;--sur:#111827;--card:#141e2d;--bor:#1e2d42;--text:#dce8f7;--mut:#4a6080;
--cy:#00d4ff;--gr:#2ed573;--re:#ff4757;--or:#ff6b35;--ye:#ffa502;--bl:#1e90ff;
--font:'Courier New',Courier,monospace;}
*{margin:0;padding:0;box-sizing:border-box;}
body{background:var(--bg);color:var(--text);font-family:var(--font);font-size:13px;line-height:1.6;}
/* ── Header ── */
header{background:linear-gradient(160deg,#060d18 0%,#0d1e35 50%,#060d18 100%);
border-bottom:2px solid var(--cy);padding:36px 48px;position:relative;overflow:hidden;}
header::before{content:'';position:absolute;inset:0;
background:repeating-linear-gradient(90deg,transparent,transparent 60px,rgba(0,212,255,.025) 60px,rgba(0,212,255,.025) 61px);}
.hi{position:relative;z-index:1;}
.logo{font-size:2.2rem;letter-spacing:8px;color:var(--cy);font-weight:900;text-shadow:0 0 24px rgba(0,212,255,.4);}
.sub{color:var(--mut);font-size:.72rem;letter-spacing:4px;margin-top:2px;}
.tbadge{display:inline-block;margin-top:14px;background:rgba(0,212,255,.08);
border:1px solid rgba(0,212,255,.3);padding:6px 20px;border-radius:3px;color:var(--cy);font-size:.9rem;}
.mrow{display:flex;gap:36px;margin-top:14px;flex-wrap:wrap;}
.mi{color:var(--mut);font-size:.72rem;} .mi span{color:var(--text);}
/* ── Container ── */
.wrap{max-width:1240px;margin:0 auto;padding:36px 24px;}
/* ── Warning ── */
.warn-bar{background:rgba(255,71,87,.08);border:1px solid rgba(255,71,87,.4);
border-radius:6px;padding:12px 20px;margin-bottom:32px;color:#ff8090;font-size:.78rem;text-align:center;}
/* ── Summary ── */
.sgrid{display:grid;grid-template-columns:repeat(auto-fit,minmax(130px,1fr));gap:14px;margin-bottom:40px;}
.sc{background:var(--card);border-radius:8px;padding:20px 12px;text-align:center;border-top:3px solid;}
.sc .n{font-size:2.4rem;font-weight:900;} .sc .l{color:var(--mut);font-size:.68rem;letter-spacing:2px;margin-top:4px;}
.cr{border-color:var(--re);} .cr .n{color:var(--re);}
.hi2{border-color:var(--or);} .hi2 .n{color:var(--or);}
.me{border-color:var(--ye);} .me .n{color:var(--ye);}
.lo{border-color:var(--gr);} .lo .n{color:var(--gr);}
.in{border-color:var(--bl);} .in .n{color:var(--bl);}
/* ── Sections ── */
.sec{margin-bottom:40px;}
.sec-t{font-size:.7rem;letter-spacing:4px;color:var(--cy);text-transform:uppercase;
border-bottom:1px solid var(--bor);padding-bottom:10px;margin-bottom:18px;}
/* ── Finding cards ── */
.fc{background:var(--card);border:1px solid var(--bor);border-radius:7px;margin-bottom:12px;overflow:hidden;
transition:border-color .2s;}
.fc:hover{border-color:rgba(0,212,255,.2);}
.fh{display:flex;align-items:center;gap:12px;padding:13px 18px;cursor:pointer;user-select:none;
border-bottom:1px solid transparent;}
.fh:hover{background:rgba(255,255,255,.02);}
.pill{font-size:.62rem;font-weight:700;letter-spacing:1.5px;padding:3px 10px;border-radius:10px;white-space:nowrap;}
.ft{flex:1;font-weight:600;}
.fts{color:var(--mut);font-size:.68rem;}
.fb{padding:16px 18px;display:none;}
.fb.open{display:block;}
.fdesc{color:var(--mut);margin-bottom:10px;font-style:italic;font-size:.8rem;}
pre{background:#050911;border:1px solid var(--bor);border-radius:5px;padding:12px;overflow-x:auto;
color:#7ecfea;font-size:.78rem;white-space:pre-wrap;word-break:break-all;line-height:1.7;}
/* ── Audit log ── */
.log-t{display:grid;grid-template-columns:190px 130px 1fr;gap:12px;
padding:7px 14px;border-bottom:1px solid var(--bor);font-size:.72rem;}
.log-t:nth-child(even){background:rgba(255,255,255,.015);}
.lt{color:var(--mut);} .la{color:var(--cy);} .ld{color:var(--text);}
footer{text-align:center;padding:28px;color:var(--mut);font-size:.7rem;border-top:1px solid var(--bor);}
</style>
</head>
<body>
<header>
<div class="hi">
  <div class="logo">RECONX</div>
  <div class="sub">PROFESSIONAL RECONNAISSANCE FRAMEWORK v{{ version }} &nbsp;&bull;&nbsp; AUTHORIZED USE ONLY</div>
  <div class="tbadge">&#x2295; TARGET &nbsp; {{ target }}</div>
  <div class="mrow">
    <div class="mi">TYPE <span>{{ scan_type }}</span></div>
    <div class="mi">STARTED <span>{{ started }}</span></div>
    <div class="mi">COMPLETED <span>{{ ended }}</span></div>
    <div class="mi">FINDINGS <span>{{ total }}</span></div>
  </div>
</div>
</header>

<div class="wrap">
<div class="warn-bar">&#9888; CONFIDENTIAL SECURITY ASSESSMENT &mdash;
Intended solely for authorized personnel. All activities conducted with explicit written authorization.</div>

<div class="sgrid">
  <div class="sc cr"><div class="n">{{ c.CRITICAL }}</div><div class="l">CRITICAL</div></div>
  <div class="sc hi2"><div class="n">{{ c.HIGH }}</div><div class="l">HIGH</div></div>
  <div class="sc me"><div class="n">{{ c.MEDIUM }}</div><div class="l">MEDIUM</div></div>
  <div class="sc lo"><div class="n">{{ c.LOW }}</div><div class="l">LOW</div></div>
  <div class="sc in"><div class="n">{{ c.INFO }}</div><div class="l">INFO</div></div>
</div>

{% for cat, fs in categories.items() %}
<div class="sec">
  <div class="sec-t">{{ cat }}</div>
  {% for f in fs %}
  <div class="fc">
    <div class="fh" onclick="tog(this)">
      <span class="pill" style="background:{{ rc[f.risk] }}22;color:{{ rc[f.risk] }};border:1px solid {{ rc[f.risk] }}55;">{{ f.risk }}</span>
      <span class="ft">{{ f.title }}</span>
      <span class="fts">{{ f.timestamp[:19] }}</span>
      <span style="color:var(--mut);margin-left:8px;">&#9660;</span>
    </div>
    <div class="fb">
      {% if f.description %}<div class="fdesc">{{ f.description }}</div>{% endif %}
      <pre>{{ f.data_json }}</pre>
    </div>
  </div>
  {% endfor %}
</div>
{% endfor %}

{% if audit_log %}
<div class="sec">
  <div class="sec-t">Audit Log</div>
  <div style="background:var(--card);border:1px solid var(--bor);border-radius:7px;overflow:hidden;">
    {% for e in audit_log %}
    <div class="log-t">
      <span class="lt">{{ e.timestamp[:19] }}</span>
      <span class="la">{{ e.action }}</span>
      <span class="ld">{{ e.target }} {{ e.details }}</span>
    </div>
    {% endfor %}
  </div>
</div>
{% endif %}
</div>

<footer>Generated by ReconX {{ version }} &bull; {{ generated }} &bull;
For authorized penetration testing purposes only.</footer>

<script>
function tog(h){const b=h.nextElementSibling;b.classList.toggle('open');}
document.addEventListener('DOMContentLoaded',()=>{
  document.querySelectorAll('.pill').forEach(p=>{
    if(['CRITICAL','HIGH'].includes(p.textContent.trim()))
      p.closest('.fc').querySelector('.fb').classList.add('open');
  });
});
</script>
</body>
</html>"""


def generate_html_report(result: ReconResult, output_path: str) -> str:
    """Render the dark-theme HTML report. Returns the output path."""
    if not _JINJA:
        # Fallback: write minimal HTML if jinja2 not installed
        with open(output_path, "w") as f:
            f.write(f"<pre>{result.to_json()}</pre>")
        return output_path

    data = result.to_dict()
    summ = data["meta"]["summary"]

    # Prepare per-finding data_json strings (for the template)
    cats_rendered: dict[str, list[dict]] = {}
    for cat, findings in data["categories"].items():
        cats_rendered[cat] = []
        for f in findings:
            entry         = dict(f)
            entry["data_json"] = json.dumps(f["data"], indent=2, default=str)
            cats_rendered[cat].append(entry)

    tpl  = Template(HTML_REPORT_TEMPLATE)
    html = tpl.render(
        version    = TOOL_VERSION,
        target     = data["meta"]["target"],
        scan_type  = data["meta"]["scan_type"],
        started    = data["meta"]["started_at"][:19],
        ended      = (data["meta"]["ended_at"] or "")[:19],
        total      = len(data["findings"]),
        c          = summ,
        categories = cats_rendered,
        audit_log  = data["audit_log"],
        rc         = RISK_COLORS_HTML,
        generated  = datetime.now(timezone.utc).replace(tzinfo=None).strftime("%Y-%m-%d %H:%M UTC"),
    )

    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    with open(output_path, "w", encoding="utf-8") as f:
        f.write(html)
    return output_path


# ══════════════════════════════════════════════════════════════════════════════
# ─────────────────────────────  SECTION 6  ───────────────────────────────────
#                          HELPER UTILITIES
# ══════════════════════════════════════════════════════════════════════════════

def _clean(val):
    """Deduplicate & stringify WHOIS fields."""
    if val is None:
        return None
    if isinstance(val, list):
        seen, out = set(), []
        for v in val:
            s = str(v).strip()
            if s and s not in seen:
                seen.add(s); out.append(s)
        return out or None
    return str(val).strip() or None


def _resolve(fqdn: str) -> Optional[str]:
    try:
        return socket.gethostbyname(fqdn)
    except Exception:
        return None


def _progress(current: int, total: int, label: str = "", width: int = 40):
    pct    = current / total
    filled = int(width * pct)
    bar    = "█" * filled + "░" * (width - filled)
    print(f"\r  {C['cyan']}{bar}{C['reset']} {int(pct*100):3d}%  {C['muted']}{label:<30}{C['reset']}",
          end="", flush=True)
    if current == total:
        print()


# ══════════════════════════════════════════════════════════════════════════════
# ─────────────────────────────  SECTION 7  ───────────────────────────────────
#                          CLI  &  MAIN ENTRY POINT
# ══════════════════════════════════════════════════════════════════════════════

BANNER = f"""
{C['banner']}
  ██████╗ ███████╗ ██████╗ ██████╗ ███╗   ██╗██╗  ██╗
  ██╔══██╗██╔════╝██╔════╝██╔═══██╗████╗  ██║╚██╗██╔╝
  ██████╔╝█████╗  ██║     ██║   ██║██╔██╗ ██║ ╚███╔╝
  ██╔══██╗██╔══╝  ██║     ██║   ██║██║╚██╗██║ ██╔██╗
  ██║  ██║███████╗╚██████╗╚██████╔╝██║ ╚████║██╔╝ ██╗
  ╚═╝  ╚═╝╚══════╝ ╚═════╝ ╚═════╝ ╚═╝  ╚═══╝╚═╝  ╚═╝
{C['reset']}
  {C['muted']}Professional Reconnaissance Framework  v{TOOL_VERSION}{C['reset']}
  {C['muted']}─────────────────────────────────────────────────{C['reset']}
  {C['warn']}  ⚠  FOR AUTHORIZED PENETRATION TESTING ONLY  ⚠ {C['reset']}
  {C['muted']}─────────────────────────────────────────────────{C['reset']}
"""

# Module registry
PASSIVE_MODULES = ["whois", "dns", "subdomains", "tech", "email", "dorks"]
ACTIVE_MODULES  = ["ports"]
ALL_MODULES     = PASSIVE_MODULES + ACTIVE_MODULES

MODULE_RUNNERS = {
    "whois":      run_whois,
    "dns":        run_dns,
    "subdomains": run_subdomains,
    "tech":       run_tech_stack,
    "email":      run_email_harvest,
    "dorks":      run_google_dorks,
    "ports":      run_port_scan,
}

MODULE_LABELS = {
    "whois":      "WHOIS registration lookup",
    "dns":        "DNS enumeration & zone transfer",
    "subdomains": "Subdomain discovery (CT + brute-force)",
    "tech":       "Technology stack fingerprinting",
    "email":      "Email address harvesting",
    "dorks":      "Google dork query generation",
    "ports":      "TCP port scanning & banner grabbing",
}


def require_authorization(target: str) -> bool:
    print(f"\n{C['warn']}{'═'*62}{C['reset']}")
    print(f"{C['warn']}  LEGAL & ETHICAL USE NOTICE{C['reset']}")
    print(f"{C['warn']}{'═'*62}{C['reset']}")
    print(f"""
  {C['error']}This tool performs active and passive reconnaissance.
  Scanning systems without explicit written authorization
  is ILLEGAL and unethical under computer crime laws.{C['reset']}

  Target: {C['value']}{target}{C['reset']}

  By proceeding you confirm:
    {C['success']}[1]{C['reset']} You own or have explicit written authorization to test the target
    {C['success']}[2]{C['reset']} Your use complies with all applicable laws and regulations
    {C['success']}[3]{C['reset']} You accept full responsibility for your actions
""")
    ans = input(f"  {C['warn']}Type 'AUTHORIZED' to continue, or press ENTER to abort: {C['reset']}").strip()
    return ans == "AUTHORIZED"


def print_summary(result: ReconResult, saved: list[tuple[str, str]]):
    summary = result.summary()
    total   = sum(summary.values())
    rcol    = {RISK_CRITICAL: C["risk_c"], RISK_HIGH: C["risk_h"],
               RISK_MEDIUM:   C["risk_m"], RISK_LOW:  C["risk_l"], RISK_INFO: C["risk_i"]}

    print(f"\n{C['banner']}{'═'*64}{C['reset']}")
    print(f"{C['banner']}  SCAN SUMMARY  ·  {result.target}{C['reset']}")
    print(f"{C['banner']}{'═'*64}{C['reset']}\n")
    for lvl in [RISK_CRITICAL, RISK_HIGH, RISK_MEDIUM, RISK_LOW, RISK_INFO]:
        n   = summary[lvl]
        col = rcol[lvl]
        bar = "█" * min(n, 38)
        print(f"  {col}{lvl:<10}{C['reset']}  {col}{bar:<38}{C['reset']}  {n}")
    print(f"\n  Total findings: {C['value']}{total}{C['reset']}")
    if saved:
        print(f"\n{C['info']}  Reports:{C['reset']}")
        for fmt, path in saved:
            print(f"    {C['muted']}{fmt:<6}{C['reset']}  {path}")
    print()


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="reconx_single.py",
        description=f"ReconX {TOOL_VERSION} – Professional Reconnaissance Tool for Ethical Hacking",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=f"""
Examples:
  python reconx_single.py -d example.com                  # Passive recon (default)
  python reconx_single.py -d example.com --full           # Full passive + active
  python reconx_single.py -d example.com --active         # Active only (port scan)
  python reconx_single.py -d example.com -m whois,dns,tech
  python reconx_single.py -i 192.168.1.1 --active
  python reconx_single.py -d example.com --json-only
  python reconx_single.py -d example.com --no-auth        # Skip auth prompt

Available modules:
{"".join(f"  {k:<12} {v}{chr(10)}" for k, v in MODULE_LABELS.items())}""",
    )

    tgt = p.add_mutually_exclusive_group(required=True)
    tgt.add_argument("-d", "--domain", dest="target", metavar="DOMAIN", help="Target domain name")
    tgt.add_argument("-i", "--ip",     dest="target", metavar="IP",     help="Target IP address")

    mode = p.add_argument_group("Scan Mode").add_mutually_exclusive_group()
    mode.add_argument("--passive", action="store_true", default=True,  help="Passive recon only (default)")
    mode.add_argument("--active",  action="store_true", default=False, help="Active recon only (ports)")
    mode.add_argument("--full",    action="store_true", default=False, help="Full passive + active scan")

    p.add_argument("-m", "--modules",  metavar="MOD1,MOD2", help="Comma-separated module list")

    out = p.add_argument_group("Output")
    out.add_argument("--no-html",   action="store_true", help="Skip HTML report")
    out.add_argument("--json-only", action="store_true", help="JSON output only")

    p.add_argument("--no-auth", action="store_true",  help="Skip authorization prompt (CI use)")
    p.add_argument("--version", action="version",     version=f"%(prog)s {TOOL_VERSION}")
    return p


def main():
    print(BANNER)
    parser = build_parser()
    args   = parser.parse_args()

    if args.json_only:
        args.no_html = True

    if not args.no_auth:
        if not require_authorization(args.target):
            print(f"\n{C['error']}  Aborted. Always obtain written authorization before scanning.{C['reset']}\n")
            sys.exit(0)

    # ── Session setup
    session_id = datetime.now(timezone.utc).replace(tzinfo=None).strftime("%Y%m%d_%H%M%S")
    log        = ReconLogger(session_id)
    log.success(f"Session {session_id} started")
    log.info(f"Target: {args.target}")

    # ── Select modules
    if args.modules:
        selected = [m.strip() for m in args.modules.split(",")]
    elif args.full:
        selected = ALL_MODULES
    elif args.active:
        selected = ACTIVE_MODULES
    else:
        selected = PASSIVE_MODULES

    valid   = [m for m in selected if m in MODULE_RUNNERS]
    invalid = [m for m in selected if m not in MODULE_RUNNERS]
    if invalid:
        log.warn(f"Unknown modules ignored: {invalid}")
    if not valid:
        log.error("No valid modules selected."); sys.exit(1)

    print(f"\n  {C['info']}Modules:{C['reset']} {', '.join(valid)}")
    print(f"  {C['info']}Output: {C['reset']} {OUTPUT_DIR}\n")

    # ── Run scan
    result     = ReconResult(target=args.target, scan_type=(
        "Full Scan" if args.full else ("Active" if args.active else "Passive")))
    start_time = time.time()

    for idx, mod in enumerate(valid, 1):
        _progress(idx - 1, len(valid), mod)
        try:
            MODULE_RUNNERS[mod](args.target, result, log)
        except KeyboardInterrupt:
            log.warn("Interrupted by user"); break
        except Exception as exc:
            log.error(f"Module '{mod}' crashed: {exc}")
        time.sleep(0.05)

    _progress(len(valid), len(valid), "Done")
    result.finish()
    result.actions = log.get_actions()

    elapsed = time.time() - start_time
    print(f"\n{C['success']}  Scan completed in {elapsed:.1f}s{C['reset']}\n")

    # ── Save reports
    ts     = datetime.now(timezone.utc).replace(tzinfo=None).strftime("%Y%m%d_%H%M%S")
    target = args.target.replace(".", "_")
    saved: list[tuple[str, str]] = []

    json_path = os.path.join(OUTPUT_DIR, f"{target}_{ts}.json")
    with open(json_path, "w") as f:
        f.write(result.to_json())
    saved.append(("JSON", json_path))

    if not args.no_html:
        html_path = os.path.join(REPORT_DIR, f"{target}_{ts}.html")
        generate_html_report(result, html_path)
        saved.append(("HTML", html_path))

    print_summary(result, saved)


if __name__ == "__main__":
    main()
