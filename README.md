# SmartNmap — Multi-Phase Nmap Reconnaissance Framework

> **Developed by [Osama Hussien](https://github.com/iSpammer)**

A single-file Python wrapper that chains Nmap with 20+ recon tools into a 6-phase
pipeline and drops a ready-to-read `REPORT.md` with severity-rated vulnerabilities,
metasploit hints, and loot (creds, flags, shares, URLs).

Built for CTFs, HTB, and bug-bounty recon.

---

## Install

```bash
git clone https://github.com/iSpammer/snmap.git reconnmap
cd reconnmap
chmod +x install.sh
./install.sh          # auto-detects missing tools and apt/pip installs what it can
```

Minimum: `nmap`, `python3`. Recommended: `searchsploit`, `gobuster`, `nikto`,
`nuclei`, `whatweb`, `enum4linux-ng`, `smbmap`, `ldap-utils`, `impacket-scripts`,
`sslscan` or `testssl.sh`, `seclists` wordlists.

```bash
# Kali / Debian one-liner for the recommended set:
sudo apt install -y nmap gobuster nikto whatweb sslscan enum4linux-ng smbmap \
                    ldap-utils seclists exploitdb dnsutils
pip install --break-system-packages impacket
go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest

# Kill-chain extras (crawlers, injection, AD) — or just run ./install.sh --run:
sudo apt install -y sqlmap commix hydra medusa feroxbuster
pip install --break-system-packages arjun bloodhound
go install github.com/projectdiscovery/katana/cmd/katana@latest
go install github.com/lc/gau/v2/cmd/gau@latest
go install github.com/tomnomnom/waybackurls@latest
go install github.com/hahwul/dalfox/v2@latest
go install github.com/ropnop/kerbrute@latest
git clone https://github.com/swisskyrepo/SSRFmap   # symlink ssrfmap.py onto PATH
```

Optional AI (Gemini):

```bash
export GEMINI_API_KEY="your-key"
# or: echo '{"gemini_api_key":"..."}' > ~/.config/smartnmap/config.json
```

---

## Quick start

```bash
# Default quick scan (top 1000 TCP, service detection, NSE, vuln, searchsploit, report)
python3 smartnmap.py 10.10.10.10

# All TCP + UDP + deep NSE + markdown report
python3 smartnmap.py --full --udp --markdown 10.10.10.10

# Bug-bounty mode: no DoS/intrusive scripts
python3 smartnmap.py --bb example.com

# CIDR sweep (large nets do ping-first, small ones expand to individual scans)
python3 smartnmap.py 10.10.10.0/24

# With vhost brute-forcing and hostname enrichment
python3 smartnmap.py --vhosts --hostname target.htb 10.10.10.10

# Resume a previous scan (re-uses phase1/phase2 XMLs from latest/)
python3 smartnmap.py --resume 10.10.10.10
```

Output lands under `~/smartnmap_results/<target>/<timestamp>/` with a `latest`
symlink. The key files are:

| File | What's in it |
|------|--------------|
| `REPORT.md` | **Start here** — severity-sorted findings + MSF hints |
| `loot.md` | creds, keys, flags, shares, URLs, notable notes |
| `phase1_tcp.xml` / `phase1_udp.xml` | port discovery (parseable) |
| `phase2_services.xml` | service/version/default-script output |
| `phase3_<group>.xml` | targeted NSE per service family |
| `phase4_vuln.xml` | `--script vuln` + `vulners` |
| `phase5_*.txt` | gobuster / nikto / enum4linux / ldap / asrep / etc. |
| `searchsploit_results.md` | exploit-DB matches by product+version |
| `scan_meta.json` | full args, start time, target info (resume uses this) |

---

## Pipeline (6 phases)

1. **Port discovery** — top-1000 TCP by default (+ UDP top-50 with `--udp`),
   `masscan`/`rustscan` fallback if available, CIDR host-discovery.
2. **Service/version** — `-sV -sC -A` with per-host timeout caps.
3. **Targeted NSE** — per-service script bundles grouped by family
   (FTP, SSH, HTTP, SMB, RPC, LDAP, Kerberos, DNS, SNMP, RDP, DB, WinRM, …).
4. **Vuln scan** — `--script vuln` + `vulners` CVE lookup. NSE findings
   (MS17-010, MS08-067, Heartbleed, etc.) are parsed into structured
   entries with CVSS-aware severity.
5. **Supplementary tools** — gobuster/ffuf (with recursion into `/cgi-bin/`,
   `/admin/`, …), nikto, nuclei, wpscan, sslscan/testssl, enum4linux,
   smbclient/smbmap, showmount, ldapsearch, Kerberos AS-REP roast,
   built-in **shellshock PoC**, FTP anonymous check, SSL cert SAN harvest.
   Now also: **web crawling** (katana/hakrawler/gospider + gau/waybackurls +
   arjun) into a shared URL/parameter corpus that feeds **web foothold
   heuristics** (HTML-intel harvest of users/emails/tech, default-cred probe,
   LFI, IDOR), **injection testing** (sqlmap, dalfox, commix), **SSRF**
   (ssrfmap + interactsh OOB), **credential attacks** (hydra/medusa),
   **SMB/NFS share pull-and-mine** (download readable shares → scan for
   creds/keys/flags), and **Windows/AD/SMB** (netexec null/RID enum,
   username==password spray, kerbrute, Kerberoast, BloodHound).
   Everything intrusive is **safe-by-default**: crawlers and passive enum
   always run; injection/brute tools fire only with `--active` (or `--ctf`),
   and otherwise emit a ready-to-run command into the report.

   **Feedback loop (the kill-chain differentiator):** `LootTracker` is a
   credential *state machine*, not a logbook. Any credential discovered (brute,
   spray, share loot, `--creds`) triggers a **credential-reuse sweep** — it's
   tried against every other discovered service (SMB/SSH/WinRM/MSSQL/LDAP/FTP
   via netexec), and a validated cred auto-drives credentialed AD collection
   (Kerberoast/BloodHound). The report opens with a **Kill-Chain Narrative**
   that stitches loot into the ordered path and surfaces *chain enablers*
   (anon FTP, readable shares, leaked usernames, default-cred panels, valid
   creds) above raw CVSS.
6. **Analysis & report** — dedup by `(port, cve, desc)`, severity sort
   (`critical → info`), Markdown report, optional Gemini attack-path synthesis.

---

## Cyber kill-chain coverage

| Stage | What SmartNmap does | Tools |
|-------|---------------------|-------|
| **Recon** | port/service discovery, crawling, URL/param corpus, subdomains, cert SANs | nmap, masscan/rustscan, katana/hakrawler/gospider, gau/waybackurls, arjun, httpx, subfinder |
| **Enumeration** | targeted NSE, web dirs, SMB/LDAP/NFS/SNMP/FTP, AD users (netexec null/RID) | NSE, gobuster/ffuf, nikto, whatweb, enum4linux-ng, smbmap, netexec |
| **Vuln ID** | CVE lookup, nuclei, searchsploit, severity-rated findings | vulners NSE, nuclei, searchsploit |
| **Exploitation** *(active-gated)* | SQLi/XSS/cmd-injection, SSRF, credential brute, Kerberoast/AS-REP | sqlmap, dalfox, commix, ssrfmap, hydra/medusa, kerbrute, impacket |
| **Post-ex candidates** *(gated / detect-and-recommend)* | AD graph collection, WinRM/MSSQL access, secretsdump hints | bloodhound-python, evil-winrm, netexec |

Active/exploitation tools never run without `--active` (or `--ctf`). When gated
off, the report's **Loot → Recommend** section lists the exact command to run.

## Key CLI flags

```
TARGETS
  TARGET              IP / CIDR / hostname / IP,IP,IP

SCAN PROFILES
  --quick             top-1000 TCP only (default)
  --full              all 65k TCP
  --fast              masscan or rustscan first, then nmap -sV on opens
  --top-ports N       custom top-N
  -p 80,443,8080      explicit ports
  --udp               add UDP top-50 + service detection on found ports

TIMING / STEALTH
  --timing T0..T5     nmap timing (default T4)
  --stealth           -sS with decoys
  --no-retry          skip retries on filtered ports

MODES
  --ctf               CTF mode (default looting, hostname tricks; enables --active)
  --bb                bug-bounty mode (skips DoS/slowloris/nessus scripts)

OFFENSIVE / ACTIVE (safe-by-default; gated)
  --active            enable intrusive tools: sqlmap, dalfox, commix, ssrfmap,
                      hydra/kerbrute/netexec brute (also on in --ctf)
  --no-crawl          skip web crawling + the URL/param corpus
  --oob               use interactsh OOB canary for blind SSRF/RCE
  --creds USER:PASS   creds for authenticated AD collection (Kerberoast/BloodHound)
  --userlist FILE     username wordlist for brute/spray
  --passlist FILE     password wordlist for brute/spray
  --domain DOMAIN     AD/Kerberos domain (auto-detected from LDAP if omitted)

WEB
  --vhosts            vhost brute-force on discovered HTTP ports
  --hostname H        seed hostname (written to /etc/hosts with --update-hosts)
  --no-gobuster       disable dir brute-forcing
  --no-nuclei         disable nuclei

OUTPUT
  -o DIR              output directory (default ~/smartnmap_results/<target>/<ts>)
  --markdown          write REPORT.md (on by default in --ctf)
  --json              additional JSON summary
  --no-stream         don't tail nmap stdout live (quieter)

AI
  --ai                force AI advisor calls (Gemini / Puter)
  --api-key KEY       override env var / config

MANAGEMENT
  --resume            skip phase1/phase2 if XMLs exist in latest/
  --install-scripts   fetch vulners.nse and other community NSEs
  --no-vuln           skip phase 4
  --no-extra          skip phase 5
```

---

## Examples

**Classic HTB box (Lame / Legacy / Blue):**
```bash
python3 smartnmap.py --quick --ctf --markdown 10.129.x.y
# -> REPORT.md lists MS17-010, MS08-067, SambaCry, vsftpd backdoor, etc.
#    with exact metasploit module names.
```

**Web-heavy box (Shocker):**
```bash
python3 smartnmap.py --quick --ctf --markdown --udp target.htb
# -> gobuster recurses /cgi-bin/, built-in shellshock PoC fires,
#    critical CVE-2014-6271 entry with ready curl command.
```

**AD box (Sauna / Forest):**
```bash
python3 smartnmap.py --quick --ctf --markdown target.htb
# -> extracts DC=... from LDAP, enumerates users, runs GetNPUsers.py
#    for AS-REP roastable accounts, hands you a hashcat -m 18200 command.
```

**Bug-bounty scope:**
```bash
python3 smartnmap.py --bb --vhosts --hostname acme.com acme.com
# -> no intrusive scripts, vhost brute, TLS SAN harvest, nuclei medium+.
```

---

## Running the tests

```bash
python3 tests/test_parsing.py
# 62 tests covering CIDR expansion, target validation, vuln-DB regexes,
# severity heuristics, CVE/CVSS extraction, NSE mapping, and LootTracker.
```

---

## Notes / gotchas

- **snap nmap**: if your `nmap` is from snap, it can't write outside
  `$HOME/tmp`. SmartNmap detects this and relocates the output dir
  automatically.
- **AS-REP roast** needs `GetNPUsers.py` on `PATH`
  (`pip install --break-system-packages impacket` or `pipx install impacket`).
- **Anon LDAP enum** needs `ldap-utils` (`apt install ldap-utils`). Without
  it, the domain is still extracted from Nmap's `ldap-rootdse` output.
- **Nuclei** adds ~1–3 min per HTTP port. Use `--no-nuclei` in CTF speedruns.
- SmartNmap never exploits root-privilege-required things without you asking —
  it maps the attack surface, you run the exploit.

---

## Project layout

```
reconnmap/
├── smartnmap.py        # the whole tool (~3900 LOC)
├── install.sh          # tool installer
├── tests/
│   └── test_parsing.py # unit tests
└── README.md           # this file
```
