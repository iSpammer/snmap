# SmartNmap vs. Real-Attacker Methodology — Kill-Chain Review

**Reviewer:** senior offensive-security engineering pass
**Tool under review:** `/home/ispam/snmap/smartnmap.py` (≈4,834 LOC at time of review; the file was
being actively extended *during* this review — it grew ~470 lines mid-session as the
crawler/injection/SSRF/cred/AD runners landed, so line numbers below are approximate and I
cite by **function name** wherever possible).
**Learning corpus (this section):** `/home/ispam/TryHackMe-Walkthroughs/` — 142 rooms under `Room/`.
**Note:** Two further corpora (`/home/ispam/CaptureTheFlag-walkthroughs/`, `/home/ispam/HackTheBox/`)
are analyzed and folded into the unified kill-chain map in **Section E** (added after deep-reading
those repos). Sections A–D below are grounded in the TryHackMe repo.

Every workflow claim is cited to a specific room (file under `Room/<name>/`). Every tool claim is
cited to a `smartnmap.py` function. Where I am uncertain I say so explicitly.

---

## A. The workflow model extracted from the walkthroughs

The TryHackMe repo itself states the methodology explicitly. `Room/Pentesting Fundamentals/readme.md`
enumerates the stages: **Reconnaissance → Enumeration/Scanning → Exploitation → Privilege
Escalation → Post-exploitation** ("The steps a penetration tester takes during an engagement is known
as the methodology… Enumeration/Scanning: discovering applications and services… Exploitation:
leveraging vulnerabilities… Privilege Escalation: expand your access… horizontally… vertically").
`Room/Red Team Fundamentals/readme.md` and `Room/Putting it all together/Readme.md` frame the same
loop against the cyber kill chain. Mapped onto the kill chain, the *actual* behaviour in the machine
writeups is below. The single most important observation is stated up front and then evidenced
per-stage:

> **The dominant pattern is inter-stage data flow / credential reuse.** A finding in one stage is the
> *input* to the next: files → wordlists → brute-force → creds → **reuse on another service** →
> foothold → loot more creds → privesc. Almost no room is "one CVE and done"; the win comes from
> *chaining*. This is the property SmartNmap most needs and most lacks (see Section B/C).

### Stage 1 — Reconnaissance / Port discovery (Kill chain: Recon)

- **Universal first move: nmap.** 64 of 142 rooms reference `nmap` directly. The recurring invocations:
  `nmap -sV -Pn` (`Room/Kenobi/readme.md`, `Room/Bounty-Hacker/readme.md`), `nmap 10.x -sV -p- -A -sS -T4`
  (`Room/Basic-Pentesting/readme.md`), `nmap -sC -sV` (`Room/Silver-Platter/readme.md`,
  `Room/Soupedecode 01/readme.md`), `nmap -sC -Cv` / follow-up `-p-` (`Room/Simple-CTF/readme.md`).
- **Decision signal — fingerprint the host role from the port set.** `Room/Soupedecode 01/readme.md`:
  "The scan revealed multiple services commonly associated with a Windows Domain Controller"
  (53/88/135/139/389/445/464/593/3268/3269/3389 → DC). `Room/Blue/readme.md` &
  `Room/Steel Mountain/readme.md`: 135/139/445/3389 → Windows. This role classification steers the
  entire rest of the engagement.
- **Data to next stage:** the open-port + service list.

### Stage 2 — Service enumeration (Kill chain: Recon/Weaponization) — the decision-heavy core

Per service, the writeups apply a consistent "if you see X → do Y" playbook:

- **FTP (21): try anonymous first.** `Room/Bounty-Hacker/readme.md` (anon → `get locks.txt`/`task.txt`),
  `Room/Startup/readme.md` (anon FTP, `ftp-anon` NSE flagged writeable dir), `Room/Anonforce/readme.md`.
  Signal: files retrieved become **wordlists/usernames** for Stage 3. Also grab the **version** →
  `searchsploit` (`Room/Kenobi/readme.md`: `searchsploit ProFTPD 1.3.5`; vsftpd 2.3.4 backdoor recurs).
- **SMB (139/445): null/guest session → enumerate shares → read files.** `Room/Kenobi/readme.md`
  (`smb-enum-shares` NSE → anonymous share → `log.txt`), `Room/Basic-Pentesting/readme.md`
  (`smbclient -L` → `Anonymous` share → `staff.txt` leaks users **jan/kay** + "weak creds"),
  `Room/Soupedecode 01/readme.md` (`crackmapexec smb -u guest -p '' --shares` → non-standard `backup`
  share stands out). Signal: readable share → download → grep for creds/usernames/hints.
- **NFS (111/2049): showmount → mount → loot.** `Room/Kenobi/readme.md`: `nfs-showmount` NSE → `/var`
  mount → copy `id_rsa` out (chained with a ProFTPD `SITE CPFR/CPTO` file-copy to stage the key first).
- **HTTP (80/8080/…): directory brute + read the page.** Nearly every web room runs `dirsearch`/
  `gobuster`/`dirb` (`Room/Basic-Pentesting`, `Room/Bounty-Hacker`, `Room/Startup`, `Room/Silver-Platter`).
  Two critical signals beyond dir-brute:
  - **Leaked identifiers in page content.** `Room/Silver-Platter/readme.md`: `/contact` leaks username
    `scr1ptkiddy` **and** the string "Silverpeas" (the CMS). The tester manually notes both and pivots.
  - **CMS/product name → version → CVE.** `Room/Simple-CTF/readme.md` ("CMS Made Simple 2.2.8" →
    CVE-2019-9053 SQLi exploit.py), `Room/Silver-Platter/readme.md` (Silverpeas version on login page →
    CVE-2024-36042 auth bypass), `Room/Steel Mountain/readme.md` (HFS 2.3 → CVE-2014-6287),
    `Room/Mr-Robot-CTF` / `Room/Wekor` / `Room/Smol` (WordPress → `wpscan`).
- **Version → searchsploit/CVE → exploit** is the universal weaponization loop (Kenobi, Simple-CTF,
  Steel Mountain, `Room/Ice/readme.md` Icecast, `Room/Blue/readme.md` MS17-010).

### Stage 3 — Weaponization/Delivery + Exploitation (foothold)

The concrete "if-this-then-that" foothold heuristics:

- **Vulnerable version → metasploit/searchsploit module.** `Room/Blue` (`smb-vuln-ms17-010` NSE →
  `exploit/windows/smb/ms17_010_eternalblue`), `Room/Ice` (Icecast → `exploit/windows/http/icecast_header`),
  `Room/Steel Mountain` (HFS 2.3 → `rejetto_hfs_exec`).
- **Found wordlist/username → hydra the exposed auth service.** `Room/Basic-Pentesting/readme.md`
  (SMB `staff.txt` names → `hydra -l jan -P rockyou.txt ssh://…` → `armando`),
  `Room/Bounty-Hacker/readme.md` (FTP `locks.txt` as the password list, `task.txt` gives user `lin` →
  `hydra -l lin -P locks.txt ssh://…`). hydra appears in 12 rooms.
- **Writable web dir / upload → webshell → trigger → nc.** `Room/Startup/readme.md` is the archetype:
  FTP-writeable `ftp/` dir maps to web `/files/ftp/` → upload `shell.php` → `curl` it → `nc -lnvp 1234`.
  File-upload-to-webshell is the foothold in ~30 rooms (grep of "file upload/upload…shell/.php").
- **Admin panel → default creds → built-in code exec.** `Room/Alfred/readme.md` (Jenkins on 8080 →
  `admin:admin` → **Script Console** groovy `cmd.execute()` → Nishang `Invoke-PowerShellTcp`).
- **Found SSH private key → ssh2john → crack passphrase → ssh.** `Room/Basic-Pentesting/readme.md`
  (`id_rsa` from kay's `.ssh` → `ssh2john` → `john … rockyou` → `beeswax` → `ssh -i`).
- **CMS CVE → PoC.** `Room/Simple-CTF` (SQLi exploit.py `--crack`), `Room/Silver-Platter` (Burp: strip
  password param for auth bypass).
- **Always upgrade the shell:** `python3 -c 'import pty;pty.spawn("/bin/bash")'` (`Room/Startup`).

### Stage 4 — Privilege escalation (Kill chain: Actions on objectives / vertical movement)

Recurring, in rough order of what testers check first:

- **`sudo -l` first → GTFOBins.** 23 rooms reference `sudo -l`. `Room/Bounty-Hacker` (`sudo tar` →
  GTFOBins checkpoint-action → root), `Room/Simple-CTF` (`sudo vim -c ':!/bin/sh'`). 6 rooms cite
  gtfobins by name (Bounty-Hacker, Cheese-CTF, Chocolate_Factory, Lian_Yu, Lookup, Rootme).
- **SUID hunt:** `find / -perm -u=s -type f 2>/dev/null` (`Room/Kenobi` → `/usr/bin/menu` → PATH hijack
  by planting `curl`; 8 rooms).
- **Capabilities:** `getcap -r /` (`Room/Kiba`, `Room/Linux Shells`, `Room/The-Server-From-Hell`; 7 rooms).
- **Writable cron / scripts:** `Room/Startup` (`planner.sh` / `/etc/print.sh`), 7 rooms cite cron.
- **Creds in files / history / captures:** `Room/Startup` (pcap → `wireshark` follow-TCP-stream →
  sudo password `c4ntg3t3n0ughsp1c3` → `su lennie` = **credential reuse** into privesc).
- **Container escape:** docker/lxd group (7 rooms: ContainMe, Publisher, Silver-Platter, The-Great-Escape…).
- **Windows privesc:** `whoami /priv` → SeImpersonate → potato/incognito (`Room/Alfred`: `load incognito`
  → `impersonate_token "BUILTIN\\Administrators"`); `local_exploit_suggester` → `bypassuac_*`
  (`Room/Blue`, `Room/Ice`); unquoted service path (`Room/Steel Mountain`); winPEAS/powershell enum.

### Stage 5 — Lateral movement / Active Directory

Concentrated in `Room/Soupedecode 01`, `Room/Directory`, `Room/VulnNet-Active`, `Room/Silver-Platter`.
The canonical AD chain (`Room/Soupedecode 01/readme.md`, verbatim order):

1. DC recognized from ports → `crackmapexec smb -u guest -p '' --shares` (non-standard `backup` share).
2. LDAP enum fails (DNS) → **RID brute:** `crackmapexec smb -u guest -p '' --rid-brute` →
   `awk` usernames → `users.txt`.
3. **Password spray, username==password:** `crackmapexec smb -u users.txt -p users.txt --no-bruteforce
   --continue-on-success` → `ybob317:ybob317`.
4. Creds → readable `Users` share → user flag (impacket `smbclient.py`).
5. **Kerberoast:** `GetUserSPNs.py … -request` → `hashcat -m 13100` → `file_svc:Password123!!`.
6. **Credential reuse:** `file_svc` reads `backup` share → `backup_extract.txt` = NTLM hash dump.
7. **Pass-the-hash spray:** `crackmapexec smb -u users_hashes -H hashes --no-bruteforce` →
   `FileServer$ (Pwn3d!)`.
8. **PtH → SYSTEM:** `impacket psexec.py … -hashes …` → root flag.

`Room/Directory/readme.md` (a pcap-forensics room) additionally shows **AS-REP roasting**
(`$krb5asrep$23$` → `hashcat -m 18200`) and Kerberos PREAUTH signals. `Room/Silver-Platter` shows
**IDOR** (iterate message `id=0..6` → SSH creds at id 6) then credential reuse to SSH; and the `adm`
group → read logs vector.

### The recurring "if-this-then-that" heuristics a truly automated tool should encode

| Signal observed | Attacker's next action | Rooms |
|---|---|---|
| FTP anonymous allowed | download everything, grep files for creds/usernames/keys | Bounty-Hacker, Startup, Anonforce |
| SMB null/guest + readable share | recursively pull share, read files for creds/hints | Kenobi, Basic-Pentesting, Soupedecode 01 |
| NFS export | mount, loot keys/creds | Kenobi |
| Service version matches known-vuln | searchsploit/metasploit module | Kenobi, Blue, Ice, Steel Mountain |
| CMS/product name in page | identify product → version → CVE → PoC | Simple-CTF, Silver-Platter, Mr-Robot |
| Username/e-mail leaked in page/file | seed it as the brute username / spray identity | Silver-Platter, Basic-Pentesting, Bounty-Hacker |
| Wordlist/creds found anywhere | hydra the exposed auth service **with the found list** | Bounty-Hacker, Basic-Pentesting |
| Writable dir served by web | upload webshell → trigger → nc | Startup (+~30) |
| Admin panel (Jenkins/Tomcat/…) | try default creds → built-in RCE | Alfred |
| Private key found | ssh2john → crack → ssh | Basic-Pentesting |
| **Any creds obtained** | **reuse on SSH/SMB/DB/su/other hosts** | Startup, Silver-Platter, Soupedecode 01 |
| Shell obtained | `sudo -l` → SUID → getcap → cron → GTFOBins | Bounty-Hacker, Kenobi, Simple-CTF, Startup |
| Windows shell | `whoami /priv` → SeImpersonate/potato; local_exploit_suggester | Alfred, Blue, Ice |
| DC detected | null SMB → RID brute → spray(user=pass) → kerberoast → PtH → psexec | Soupedecode 01 |

---

## B. Gap analysis — what the walkthroughs do that SmartNmap does NOT

I confirmed each gap by reading the code, not by assuming. Where SmartNmap *partially* does something,
I say so.

### B1. (ARCHITECTURAL, the big one) LootTracker is write-only — no finding is ever fed back

- **Walkthroughs:** every win is credential/loot reuse across stages (Startup FTP→web→`su`; Soupedecode
  RID→spray→kerberoast→PtH; Silver-Platter IDOR→SSH; Basic-Pentesting SMB-hint→SSH-brute→key-crack→`su`).
- **SmartNmap today:** `class LootTracker` (≈line 1737) has `creds/keys/flags/shares/urls/files/notes/
  recommend`. `LootTracker.scan_output()` and dozens of `loot.add(...)` calls populate them, but a grep
  for any *read* of `loot.creds`/`loot.keys`/`loot.shares` returns **nothing** except `loot.write()`
  (≈line 1794) dumping `loot.md` at the very end. The loot is never an input to any phase.
- **Concretely:** `run_credential_attacks()` finds valid creds via hydra and does `loot.add('creds', …)`,
  but nothing then *logs in* with them, reuses them on other services, or re-runs enumeration
  authenticated. Discovered creds die in `loot.md`.
- **Why it matters:** this is exactly the muscle every room relies on. Without a feedback loop the tool
  models "scan → report", not "scan → decide → act → re-scan". It can *find* the ProFTPD version but
  won't chain FTP-anon files → hydra; it can find an SMB share but won't pull it and grep for the next
  credential.

### B2. Discovered credentials never trigger credentialed AD collection

- **Walkthroughs:** Soupedecode's whole second half is *credentialed* (spray-found `ybob317` →
  kerberoast → reuse `file_svc` → PtH). The value is in what you do *after* the first cred.
- **SmartNmap today:** `run_ad_smb_suite()` (≈line 2975) reads `creds = getattr(args,'creds','') or
  context.get('creds','')`. But **nothing anywhere writes `context['creds']`** (grep confirms only
  `context['domain']` and `context['users']` are set). And `run_ad_smb_suite()` (called at ≈line 3695)
  runs **before** `run_credential_attacks()` (≈line 3700), so even hydra-found creds can't reach it.
  Net effect: Kerberoast/BloodHound/`secretsdump` only ever fire if the operator *manually* passes
  `--creds USER:PASS`. The tool has all the pieces (GetUserSPNs, bloodhound-python, GetNPUsers) but no
  wire from "cred discovered" → "collect with it".

### B3. No credential-spray, especially username==password

- **Walkthroughs:** `Room/Soupedecode 01` hinges on `--no-bruteforce --continue-on-success` with
  `-u users.txt -p users.txt` (username=password). Password spray (one password, many users) is the
  safe AD default.
- **SmartNmap today:** grep for `spray`/`no-bruteforce`/`continue-on-success` finds only help-text
  mentions in `parse_args()`. `run_credential_attacks()` does per-service hydra with *small default
  lists* (`_DEFAULT_USERLISTS`/`_DEFAULT_PASSLISTS`) — it does **not** do username==password, does not
  spray one password across the RID-brute `ad_users.txt`, and doesn't even consume `ad_users.txt`
  (it uses the generic lists). The exact technique that owns DCs in the corpus is absent.

### B4. SMB/NFS shares are listed but never pulled and mined

- **Walkthroughs:** the loot is *inside* the share/mount (`Room/Kenobi` `log.txt` + `/var` mount →
  `id_rsa`; `Room/Basic-Pentesting` `Anonymous`→`staff.txt`; `Room/Soupedecode` `backup`→hash dump).
- **SmartNmap today:** `run_ad_smb_suite()` and phase5 SMB block run `smbclient -L`, `smbmap`,
  `enum4linux`, `nxc --shares` and record READ/WRITE lines to `loot.shares`. But there is **no
  recursive download** (`smbclient -c 'recurse;ls;mget'` / `smbmap -R -A`) and **no NFS mount+scan**
  (phase3 runs `nfs-showmount`/`nfs-ls` NSE but never `mount` + walk). So it tells you a share is
  readable and stops — the walkthroughs' actual loot step is missing.

### B5. Web foothold heuristics not encoded (upload, default creds, LFI, log-poison)

- **Walkthroughs:** file-upload→webshell (~30 rooms), Jenkins/Tomcat default creds (`Room/Alfred`),
  LFI (12 rooms: Lookup, Cheese-CTF, ContainMe, Lo-Fi, Watcher…), log poisoning (`Room/Silver-Platter`).
- **SmartNmap today:** it crawls (`build_web_corpus`), dir-brutes (gobuster/ffuf w/ `/cgi-bin/` recursion),
  runs nuclei/nikto/whatweb/wpscan, and has a genuine **shellshock PoC** (`check_shellshock`, ≈2229) and
  a `VULN_DB` line that *mentions* Jenkins `/script` and Tomcat default creds (≈1134). But it never
  **attempts** default creds, never tests **LFI** on discovered `…=` params (the crawler's params feed
  sqlmap/dalfox/commix only — see `run_injection_suite`), and has no upload/log-poison logic. Uncertain
  point: LFI could arguably be "in scope for nuclei templates", but there is no dedicated LFI probe in
  the code.

### B6. Injection suite ignores the corpus's strongest web signals

- **SmartNmap today:** `run_injection_suite()` (≈2779) runs sqlmap/dalfox/commix on `web_corpus['params']`.
  Good. But the corpus's highest-yield web signals — **leaked username/CMS-name in page text**
  (`Room/Silver-Platter`), **IDOR by incrementing an `id=` param** (`Room/Silver-Platter`,
  `Room/IDOR`, `Room/Corridor`) — are not detected. `build_web_corpus` collects param URLs but never
  flags `id=`/numeric params as IDOR candidates, and no phase greps fetched HTML for emails/usernames/
  version strings to seed later stages.

### B7. searchsploit/VULN_DB find exploits but the tool never *runs* them (by design)

- **Walkthroughs:** they run the exploit (msfconsole module, PoC .py, `curl` one-liner).
- **SmartNmap today:** `VULN_DB` (≈1104) and `generate_suggestions()` (≈4141) produce excellent
  ready-to-run strings (e.g. `msfconsole -x 'use exploit/unix/ftp/proftpd_modcopy_exec…'`). It
  deliberately stops there (README: "it maps the attack surface, you run the exploit"). This is a
  *legitimate* safety stance, **but** even the safe, non-destructive checks the corpus relies on
  (FTP anon *and pull*, SMB null *and pull*, admin-panel default-cred *probe*, redis/mongo no-auth
  *connect*) are only emitted as `_recommend()` text rather than executed, so the tool discovers far
  less than a human doing the same "safe" steps. This is a **depth-of-enumeration** gap, distinct from
  the "don't auto-exploit" policy.

### B8. Linux privesc is completely out of scope (expected, but worth stating)

- SmartNmap is a remote-recon tool; it never has a shell, so `sudo -l`/SUID/getcap/cron/GTFOBins
  (the bulk of Stage 4 in the corpus) are out of reach. **Not a defect**, but it means the tool covers
  ~Stages 1–3 of a 5-stage kill chain. The report/loot could at least *hand off* to a privesc phase
  (e.g., emit a linpeas/pspy/GTFOBins checklist keyed to the discovered OS) — currently it does not.

### B9. Report prioritization is severity-only, not exploitability/chain-aware

- **SmartNmap today:** `guess_severity()` (≈3720) + `_builtin_attack_path()` (≈3770) sort by CVSS/
  keyword severity and print "Quick Wins by Service". Solid. But it has no notion of **chain proximity**
  ("this anonymous FTP is low-sev alone but it's your foothold because it exposes a wordlist") — the very
  reasoning the walkthroughs use to pick where to start. See Section D.

---

## C. Concrete improvement recommendations (prioritized, in-architecture)

All recommendations are expressed against the existing architecture: the 6 phases, `LootTracker`, the
`tools = check_tools()` detection dict, the `VULN_DB`/`SERVICE_SCRIPTS` tables, the `_recommend()`/
`active_enabled()` gating pattern, and the phase5 per-tool blocks. The emphasis (per the request) is
**decision-logic and inter-stage data flow**, not "add tool X" (the tool already has katana/gau/arjun/
sqlmap/dalfox/commix/ssrfmap/hydra/kerbrute/netexec/impacket/bloodhound wired in).

### P0 — Make LootTracker a *state machine*, not a logbook (fixes B1/B2)

**What:** promote `LootTracker` to shared engagement state that later phases *read*. Add typed, structured
records and a "consumed?" flag.
- Add `loot.add_cred(user, pw=None, nthash=None, source, scope='unknown')` storing dicts, not strings;
  keep `creds` list for the report but add `loot.valid_creds` (verified) and `loot.candidate_creds`.
- Add `loot.get_unused_creds()` / `loot.mark_used()`.
**Where:** `class LootTracker` (≈1737); populate from `run_credential_attacks`, LDAP block, kerberoast
crack, `scan_output` regexes.
**Decision-logic to encode:** after *any* phase that yields a credential, run a **credential-reuse
sweep**: for each `(user,pw|hash)` try it (read-only auth check) against every other discovered auth
service — `nxc smb/ssh/winrm/mssql/ldap/ftp`, `hydra -l user -p pass` single-shot, `mysql/psql/redis`
connect. This is the Startup/Basic-Pentesting/Soupedecode primitive.
**I/O:** in = `loot.valid_creds` + `services`; out = new `valid_creds` with wider `scope`, new
`vulns` entries ("credential reuse: user works on smb+ssh"), and — crucially — set
`context['creds']` so B2 unblocks.
**Priority justification:** credential reuse is the #1 recurring win in the corpus (Startup,
Basic-Pentesting, Silver-Platter, Soupedecode, and most CTF/HTB boxes in Section E). Without it the tool
cannot model how real attacks progress.

### P0 — Wire discovered creds → credentialed AD collection (fixes B2)

**What:** after the reuse sweep, if a domain is known and any cred validated over SMB/LDAP, auto-run the
credentialed collectors already present.
**Where:** reorder `_run_single_target`/`phase5_tools` so `run_credential_attacks()` (and the reuse
sweep) run **before** the credentialed branch of `run_ad_smb_suite()`; or split `run_ad_smb_suite` into
`ad_enum_unauth()` (early) and `ad_collect_authed(creds)` (late, fed by loot). Set `context['creds']`
from validated loot.
**Decision-logic:** `if domain and validated_smb_cred: GetUserSPNs(-request) → hashcat 13100 hint;
bloodhound-python -c All; nxc ldap --bloodhound; if admin-scope: secretsdump`.
**I/O:** in = validated cred + domain (already auto-detected via LDAP/`smb-os-discovery`, ≈3456–3510);
out = `kerberoast.hash`, BloodHound zip, `vulns`.
**Priority:** the corpus's AD boxes are unwinnable without this transition; the tool already ships every
required binary in `TOOL_LIST` (≈1354) — only the wire is missing.

### P0 — Add password spray, username==password, and consume `ad_users.txt` (fixes B3)

**What:** in `run_credential_attacks()`/`run_ad_smb_suite()`, add spray modes:
- username==password over the RID-brute `ad_users.txt`: `nxc smb TARGET -u ad_users.txt -p ad_users.txt
  --no-bruteforce --continue-on-success`.
- single-password spray: `nxc smb -u ad_users.txt -p '<season+year|found-pw>' --continue-on-success`.
**Where:** `run_credential_attacks` (≈2919) and the RID-brute block of `run_ad_smb_suite` (≈2990-3025)
— make the spray consume the `ad_users.txt` it already writes.
**Decision-logic:** `if ad_users.txt exists → spray user==pass first (cheap, high hit-rate), then spray
any password already in loot`. Feed hits into `loot.valid_creds` (→ P0 reuse/collection).
**Priority:** directly reproduces the Soupedecode foothold; today entirely absent.

### P1 — Actually pull & mine SMB shares and NFS mounts (fixes B4)

**What:** when a share is READ (or NFS export found), recursively download to `outdir/loot/` and run
`loot.scan_output()` over the files.
**Where:** phase5 SMB block (≈3400-3448) and a new NFS block next to the existing `nfs-showmount` NSE.
- SMB: `smbmap -R <share> -A '.*' -H TARGET` or `smbclient //T/share -N -c 'recurse ON; prompt OFF; mget *'`.
- NFS: `mount -t nfs T:/export /mnt/x -o nolock` (gate under `--active`; needs root) then walk for
  `id_rsa`, `*.kdbx`, `web.config`, `*.bak`, `.git`, `unattend.xml`, history files.
**Decision-logic:** `if READ share and not ADMIN$/C$ → pull; then scan_output → new creds/keys → P0 reuse`.
**I/O:** in = share list; out = files on disk + `loot.creds/keys`. **Priority P1** (huge in the corpus,
but gated because it writes/downloads).

### P1 — Encode the web foothold heuristics (fixes B5/B6)

**What (all gated by `active_enabled`, following the existing `_recommend`-when-off pattern):**
1. **Default-cred probe** for detected admin panels: Jenkins `/script`, Tomcat `/manager/html`,
   phpMyAdmin, GlassFish 4848, WildFly 9990, Grafana, SonarQube — try the small default-cred set the
   `VULN_DB` already documents, read-only (just detect 200/authenticated), record cred to loot.
2. **LFI probe:** for crawler params, test `?p=../../../../etc/passwd`, `php://filter/…`, and log-poison
   candidates; confirm on `root:x:0:0`.
3. **IDOR flag:** in `build_web_corpus`, tag URLs with numeric/`id=`/`uid=`/`msg=` params as IDOR
   candidates → `_recommend` an incrementing fetch (Silver-Platter pattern) or auto-diff a few IDs.
4. **HTML intelligence pass:** grep fetched pages/headers for emails, usernames, `Powered by <CMS>
   <ver>`, `X-Powered-By`, framework banners → seed `loot` + the CVE lookup + the brute username list.
**Where:** extend `build_web_corpus` (≈2700) to keep raw responses; add `run_web_foothold_suite()`
called right after crawl, before `run_injection_suite`.
**Decision-logic:** `product/version in page → cve_lookup_circl()+searchsploit → if default-cred product
→ probe; params with id-like names → IDOR; params echoed/file-like → LFI`.
**Priority P1:** file-upload/LFI/default-creds/IDOR are the majority of web footholds in the corpus.

### P1 — Chain-aware prioritization in the report (fixes B9)

**What:** in `_builtin_attack_path()`/`phase6_analysis`, compute a **foothold score** per finding that
boosts *chain enablers* regardless of CVSS: anonymous FTP/SMB with readable files, exposed wordlist,
leaked username, default-cred panel, private key, writable upload dir. Present a "**Primary attack path**"
that orders by *what unlocks the next step*, not just severity.
**Where:** `guess_severity` stays; add `chain_weight(finding, loot)` and a new "Attack Path (chained)"
section in `write_markdown_report` (≈4032).
**Priority P1:** the corpus explicitly reasons this way ("this low-sev anon FTP is where you start").

### P2 — Privesc hand-off checklist (fixes B8)

**What:** since the tool has no shell, emit an OS-aware privesc checklist into the report/loot: for
Linux → `sudo -l`, `find / -perm -u=s`, `getcap -r /`, `pspy`, writable cron/`/etc/passwd`, GTFOBins
lookup for any SUID/sudo binary; for Windows → `whoami /priv` (SeImpersonate→potato), winPEAS,
`local_exploit_suggester`, unquoted service paths. Key each item to the detected OS/services.
**Where:** new `emit_privesc_checklist(os_info, services)` called from `phase6_analysis`.
**Priority P2:** valuable and cheap, but strictly post-foothold (out of the tool's active reach).

### P2 — Feed found creds/keys into offline cracking hints

**What:** when `loot.keys` captures a private key or `kerberoast.hash`/AS-REP hash exists, emit the exact
`ssh2john`/`hashcat -m 13100|18200|1000` command and (gated) auto-run against `rockyou` if present.
**Where:** kerberoast/AS-REP blocks (≈3050, ≈3560) already emit hashcat hints — extend to SSH keys and
NTLM, and consume results back into `loot.valid_creds` (→ P0). **Priority P2.**

---

## D. Report / loot / prioritization improvements the corpus suggests

- **Track the *chain*, not just findings.** The writeups are narratives ("FTP anon → wordlist → hydra →
  ssh → sudo tar → root"). SmartNmap's `REPORT.md` is a severity-sorted *list*. Add a **"Kill-chain
  narrative"** block that stitches loot into the ordered path actually available (foothold candidate →
  cred source → reuse target → privesc lead). This is the single highest-value reporting change and it
  falls straight out of the P0 LootTracker-as-state-machine work.
- **Prioritize by foothold value, not CVSS alone** (B9/P1): anonymous FTP is "low" in CVSS but is the
  start of `Room/Bounty-Hacker`/`Room/Startup`. Surface chain-enablers at the top.
- **Loot categories the corpus proves valuable but the tool under-captures:** usernames/emails harvested
  from web pages and `staff.txt`-style files (seed brute lists); *contents* of readable shares/mounts;
  CMS name+version pairs (→ CVE); found wordlists (Bounty-Hacker's `locks.txt`). `LootTracker` has the
  buckets (`creds/keys/files/notes`) but nothing fills them from downloaded content because shares/mounts
  aren't pulled (B4).
- **"Recommend" is good but discovers nothing.** The `_recommend()` pattern (great for safety) currently
  substitutes for even non-destructive enumeration (FTP pull, SMB pull, default-cred probe, no-auth DB
  connect). Split "intrusive/exploit" (keep gated to `--active`) from "safe deep enumeration" (run by
  default) so default runs match what a human safely does — the corpus's Stage-2 depth.
- **Surface the AD transition explicitly.** When a DC is detected, the report should print the *ordered*
  AD playbook (null → RID → spray(user=pass) → kerberoast → crack → reuse → PtH → psexec) with the exact
  commands and mark which steps the tool already completed vs. which await a cred — mirroring
  `Room/Soupedecode 01`.

---

## E. Unified cyber kill-chain map (cross-corpus: TryHackMe + CaptureTheFlag + HackTheBox)

This section integrates deep reads of all three corpora:
- `/home/ispam/TryHackMe-Walkthroughs/` — 142 rooms (Sections A–D).
- `/home/ispam/HackTheBox/` — **all 16 boxes read in full** (Armageddon, Bashed, Beep, Explore, Knife,
  Lame, Mirai, Networked, Nibbles, OpenAdmin, ScriptKiddie, Sense, Shocker, Swagshop, Traverxec,
  Valentine).
- `/home/ispam/CaptureTheFlag-walkthroughs/` — 62 writeups; ~10 read in full (DC-4, Daily-Bugle,
  GoldenEye, Fowsniff, Overpass, symfonos 1, eLection, W34kn3ss-1, Poster, Mnemonic) plus
  whole-corpus command/technique frequency greps.

> **Method note (uncertainty, stated honestly):** I attempted to offload the two new repos to two
> Opus sub-agents, but both terminated on an Opus **session rate-limit (HTTP 429)**, so I read the
> repos directly instead. HTB coverage is complete (16/16 boxes). CaptureTheFlag coverage is a
> representative deep sample (~10/62 read line-by-line) plus grep-based frequency across all 62 —
> I flag this as a sample, not 62/62 line-by-line. Every claim below cites a file I actually opened.

### E1. Cross-corpus technique frequency (grounds "what matters most")

Whole-repo `grep -rliE` counts over `HackTheBox/` + `CaptureTheFlag-walkthroughs/` (80 files):
`nmap` 71 · command-injection/RCE 49 · dir-brute (gobuster/dirb/ffuf/feroxbuster/dirsearch) 41 ·
`sudo -l` 37 · reverse shell/`nc -l`/`/dev/tcp` 31 · docker/lxd 22 · python pty.spawn 23 ·
metasploit/msfvenom 20 · SQLi/`union select`/`' or` 19 · hash-cracking (hashcat/john/rockyou) 19 ·
hydra/medusa 17 · cron 15 · searchsploit 14 · default-creds/`admin:admin` 13 · steg/forensics
(steghide/exiftool/binwalk/strings) 12 · SSH key/`id_rsa` 11 · SUID/`find / -perm` 9 · gtfobins 9 ·
smb/enum4linux 8 · ssh2john 6 · credential-reuse (explicit) 6 · wordpress 5 · tar/wildcard 5 ·
burp 5 · nfs 4 · joomla 3 · shellshock 3 · heartbleed 2 · magento 1 · drupal 1.
Interpretation: the corpus is **overwhelmingly** foothold-by-web-or-service-CVE → shell →
`sudo -l`/SUID/cron privesc, and the connective tissue is **credential/loot reuse** (see E3).

### E2. The kill-chain map (stage → signals → tools → data-out → SmartNmap phase → gap)

| Kill-chain stage | What the attacker does | Decision signals ("if X → do Y") | Tools | Data produced (→ next stage) | SmartNmap phase | Gap (§B) |
|---|---|---|---|---|---|---|
| **1. Recon** (port/host) | full/aggressive nmap; classify host role | DC ports→AD path; Windows ports→SMB CVEs; few ports→web focus | nmap `-sC -sV -A -p-`, rustscan→nmap | open ports + service list | phase1/phase2 | — (strong) |
| **2. Weaponization** (version→vuln) | map versions to CVEs/exploits | version string→searchsploit/CVE; CMS name in page→product→CVE | searchsploit, `vulners`, whatweb, wpscan | candidate exploit set | phase2 `check_vulns`+`VULN_DB`, phase4 | B7 (finds, doesn't run) |
| **3a. Delivery/Enum — service** | anon FTP pull; null SMB pull; NFS mount; SMTP user-enum; DB no-auth | anon allowed→pull+grep; readable share→pull; SMTP VRFY→user list | ftp, smbclient/smbmap/enum4linux, showmount+mount, smtp-user-enum, redis-cli/psql | files, usernames, creds, keys | phase5 SMB/LDAP + `run_ad_smb_suite` | **B4** (lists, never pulls), B7 |
| **3b. Delivery/Enum — web** | dir-brute (+force-slash, +ext, +recurse); read page; find CMS/params | 403 dir→recurse; `/cgi-bin/`→shellshock; CMS→CVE; `?id=`→IDOR; params→SQLi/LFI; leaked user/email→seed | gobuster/ffuf/feroxbuster, katana/gau/arjun, nikto, nuclei, sqlmap | URLs, params, creds, CMS+ver, foothold | phase5 web + `build_web_corpus`+`run_injection_suite` | **B5/B6** (no default-cred/LFI/IDOR/HTML-intel), Shocker needs `-f` |
| **4. Exploitation** (foothold) | run exploit; upload webshell; default creds; auth bypass; brute w/ found list | vuln→msf/PoC; writable+web→upload; panel→default creds; found list→hydra | msfconsole, curl PoC, webshell, hydra | **shell (usually www-data)** | phase4/5 (emits commands) | B7 (safe checks only recommended) |
| **5. Foothold consolidation** | stabilize shell; run linpeas/pspy; read configs | always `python -c pty.spawn`; config files→DB creds | pty, linpeas, pspy | more creds/keys, users, hostnames | — (no shell) | **B8** (no privesc hand-off) |
| **6. Lateral / cred reuse** | reuse creds across users/services; crack found hashes/keys | any cred→try SSH/SMB/DB/su/other hosts; key→ssh2john; hash→hashcat | ssh/su/nxc, hashcat, ssh2john | new identities, wider access | — | **B1/B2/B3** (loot never reused) |
| **7. Privilege escalation** | `sudo -l`→GTFOBins; SUID/PATH; getcap; cron/writable script; kernel; docker/lxd | sudo binary→GTFOBins; SUID w/o abspath→PATH hijack; writable cron→inject; old kernel→DirtyCow | GTFOBins, pspy, linpeas, gcc | root | — (no shell) | B8 |
| **8. Actions/loot** | grab flags; dump hashes; persist | — | cat, mimikatz/secretsdump | flags, domain compromise | phase6 report | B9 (severity-only) |

### E3. Per-box kill-chain traces — HackTheBox (all 16, evidence = each box's `Readme.md`)

- **Lame** (`HackTheBox/Lame/Readme.md`): nmap `-sC -sV -A` → FTP vsftpd 2.3.4 (rabbit hole) →
  Samba 3.x → searchsploit → **usermap_script CVE-2007-2447**; anon SMB `logon "/=`nohup nc -e…`"`
  command injection → **direct root** (no privesc). *Maps to SmartNmap `VULN_DB` samba usermap entry.*
- **Shocker** (`.../Shocker/Readme.md`): nmap `-sV -sC -Pn` → gobuster **with `-f` (force trailing
  slash — default gobuster misses it here)** → `/cgi-bin/user.sh` → nmap shellshock NSE confirm →
  searchsploit PoC RCE → user → `sudo -l` = `perl` → GTFOBins → root. *SmartNmap has `check_shellshock`
  but its gobuster block does **not** use `-f`; it would miss the `/cgi-bin/` dir on this box (§B5).*
- **Nibbles** (`.../Nibbles/Readme.md`): nmap → gobuster → page source → Nibbleblog → README = v4.0.3 →
  **CVE-2015-6967**; guess admin creds → "My Image" plugin PHP upload → revshell → user → `sudo -l`
  world-writable `monitor.sh` run as root → append revshell → root.
- **Bashed** (`.../Bashed/Readme.md`): nmap → gobuster → `/dev/phpbash.php` web shell → www-data →
  pty → `sudo -l` → `sudo -u scriptmanager` → writable `cool.py` cron → root. *(privesc = writable
  cron script, same class as THM Startup.)*
- **Valentine** (`.../Valentine/Readme.md`): nmap + NSE `ssl-heartbleed`/`poodle` + **sslyze** →
  gobuster `/dev` → `hype_key` (hex→encrypted RSA key) + notes → **Heartbleed** (`heartbleed.py`,
  included in repo) leaks base64 passphrase → ssh with key → user → LinEnum → **tmux root socket** or
  **DirtyCow** → root. *SmartNmap runs `ssl-heartbleed`/sslscan (phase5), so it would flag this; the
  memory-leak→passphrase→key-decrypt chain is manual (§B8).*
- **Beep** (`.../Beep/Readme.md`): nmap (Elastix, Webmin 10000, many ports) → gobuster 443 →
  Elastix → searchsploit → **`graph.php` LFI** → read `/etc/passwd` + `amportal.conf` creds → grep
  creds → **hydra SSH → root** (force `-oKexAlgorithms=+diffie-hellman-group1-sha1`). *LFI→creds→SSH
  reuse = §B5+§B1.*
- **Mirai** (`.../Mirai/Readme.md`): rustscan → Pi-hole + Plex → **default creds `pi:raspberry`** →
  SSH → `sudo` ALL → root; deleted `root.txt` → `lsblk`+`strings` USB backup. *default-creds = §B5.*
- **Explore** (`.../Explore/Readme.md`, Android): nmap `-p-` → ES File Explorer 59777 →
  **CVE-2019-6447 arbitrary file read** (PoC `listPics`/`getFile`) → `creds.jpg` → SSH 2222 → user →
  **ADB port-forward 5555** → `adb root` → root.
- **Knife** (`.../Knife/Readme.md`): rustscan→nmap → gobuster → **Burp shows `PHP 8.1.0-dev`
  backdoor** → `User-Agentt: zerodium` RCE (Repeater) → revshell → user → `sudo -l` = `knife` →
  GTFOBins → root.
- **Armageddon** (`.../Armageddon/Readme.md`): rustscan→nmap (**default NSE even dumped
  `drupaluser`/DB password** + `http-generator: Drupal 7`) → gobuster → CHANGELOG.txt exact ver →
  **Drupalgeddon2 CVE-2018-7600** (GitHub PoC) → webshell → apache → read `settings.php` DB creds →
  `mysql` dump users → admin hash → **`hashcat -m 7900`** = `booboo` → **SSH reuse** brucetherealadmin
  → user → `sudo -l` = `snap install *` → **GTFOBins snap** (fpm malicious pkg) → root.
- **Swagshop** (`.../Swagshop/Readme.md`): rustscan→nmap → add vhost to `/etc/hosts` → gobuster
  `/index.php/` → Magento → default creds fail → searchsploit → **Shoplift SQLi auth-bypass** (add
  admin) → authenticated **PHP Object Injection RCE** (EDB 37811, needs install date from
  `app/etc/local.xml`) → www-data → user → `sudo -l` = `vi`+`/var/www/html/*` → **GTFOBins vi `:sh`** → root.
- **Sense** (`.../Sense/Readme.md`): rustscan→nmap → gobuster 443 → `system-users.txt` (username +
  default-pw hint) → **pfSense default creds** → authenticated → metasploit
  `pfsense_graph_injection_exec` → root.
- **OpenAdmin** (`.../OpenAdmin/Readme.md`): rustscan→nmap → gobuster → OpenNetAdmin 18.1.1 →
  searchsploit RCE (curl xajax) → www-data → **linpeas** → DB creds in `database_settings.inc.php`
  (`n1nj4W4rri0R!`) → **su jimmy (reuse)** → find jimmy hash in `index.php` → crackstation →
  `main.php` leaks joanna's `id_rsa` (via SSH-tunnelled internal port) → **ssh2john** → ssh joanna →
  `sudo -l` = `nano /opt/priv` → **GTFOBins nano `reset; sh 1>&0 2>&0`** → root. *(4-hop pivot:
  www-data→jimmy→joanna→root — pure §B1 credential/loot chaining.)*
- **Traverxec** (`.../Traverxec/Readme.md`): nmap → **nostromo 1.9.6** → searchsploit
  **CVE-2019-16278 RCE** → www-data → linpeas → nhttpd `.htpasswd` David MD5 → hashcat → find
  `backup-ssh-identity-files.tgz` → `wget http://david:pass@…` → encrypted `id_rsa` → **ssh2john** →
  ssh david → `sudo journalctl` (server-stats script) → **GTFOBins journalctl `!/bin/bash`** → root.
- **Networked** (`.../Networked/Readme.md`): nmap → gobuster finds `backup`/`uploads` → download
  `backup.tar` → **source-code review of `upload.php`** → MIME + **double-extension `.php.jpeg`
  bypass** → RCE → www-data → `crontab.guly` runs `check_attack.php` over filenames → **command
  injection via crafted filename `; nc … -c bash`** → guly → `sudo -l` `changename.sh` → ifcfg
  `NAME` field command injection → root.
- **ScriptKiddie** (`.../ScriptKiddie/Readme.md`): nmap → port 5000 Werkzeug/Flask "hacker tools" →
  **msfvenom APK template command injection (CVE-2020-7384)** → RCE as kid → find pwn's world-readable
  `scanlosers.sh` → **log-injection command injection** → pwn → `sudo -l` = msfconsole as root →
  **`irb` → `system("bash")`** → root.

### E4. Per-writeup kill-chain traces — CaptureTheFlag (deep-read sample)

- **DC-4** (`CaptureTheFlag-walkthroughs/DC-4 CTF Walkthrough.txt`): nmap `-A -p-` → nginx "System
  Tools" login → **Burp Intruder cluster-bomb** (admin + top-10M list) → `happy` → `command.php`
  `radio=` param = **command injection** (tamper predefined command in Burp) → `cat /etc/passwd`
  (users charles/jim/sam) → `cat /home/jim/backups/old-passwords.bak` = **password wordlist loot** →
  **`hydra -l jim -P passwords.txt ssh`** → jim → **`/var/mail/jim`** reveals charles's password →
  **su charles** → `sudo -l` = `teehee` NOPASSWD → **`echo "x::0:0:::/bin/bash" | sudo teehee -a
  /etc/passwd`** → root. *The purest credential-reuse chain in any corpus.*
- **Daily-Bugle** (`.../Daily-Bugle Tryhackme Write-up`): nmap → Joomla 3.7.0 → searchsploit →
  **`com_fields` SQLi (EDB 42033)** → sqlmap dump `#__users` admin hash → hashcat → `configuration.php`
  DB creds → **su jjameson (reuse)** → SSH → `sudo -l` = `/usr/bin/yum` NOPASSWD → **GTFOBins yum
  plugin** → root.
- **GoldenEye** (`.../GoldenEye Tryhackme GuidedCTF`): nmap (SMTP/POP3 on high ports) → source hint →
  **`hydra … pop3 -s 55007`** for `natalya`/`doak` → mail creds → Moodle admin → RCE → user →
  kernel/`nano` privesc → root.
- **Fowsniff** (`.../Fowsniff Walkthrough.txt`): POP3 → **leaked breach-dump hashes** → crack →
  POP3 login → mail = SSH creds → SSH → writable MOTD/`/opt` script run on login → root.
- **Overpass** (`.../Overpass Tryhackme Walkthrough.txt`): nmap → web login uses **client-side JS**
  (`Cookies.set("SessionToken", …)` regardless of server "Incorrect credentials") → **set cookie to
  bypass** → admin page leaks encrypted `id_rsa` → **ssh2john → john rockyou** → ssh james → **cron
  job `curl … | bash` with attacker-writable `/etc/hosts`** → root.
- **symfonos 1** (`.../symfonos 1 CTF Walkthrough.txt`): nmap (SMTP 25, SMB, HTTP) → enum4linux →
  smbclient anonymous → `attention.txt` (password-policy hint) → helios share → WordPress `/h3l105`
  → **Site Editor plugin LFI** (`ajax_path=/etc/passwd`) → **LFI read `/var/mail/helios`** →
  **LFI + `&cmd=id` = RCE** → nc revshell → helios → wp-config DB creds → SUID find → `/opt` binary
  calls `curl` w/o abspath → **PATH hijack** (`export PATH=/tmp:$PATH`) → root. *(Same SUID-PATH
  primitive as THM Kenobi.)*
- **eLection** (`.../eLection Vulnhub Writeup`): web creds → **`sqlmap -r cookie.request --os-shell`**
  → shell → crontab → compile **CVE-2019-12181 Serv-U** exploit → root.
- **W34kn3ss-1** (`.../W34kn3ss-1 Walkthrough.txt`): HTTPS → `searchsploit openssl 0.9.8c-1` =
  **Debian predictable-PRNG SSH keys (CVE-2008-0166)** → use precomputed key → ssh → `sudo -l` privesc.
- **Poster** (`.../Poster Tryhackme Write-up`): nmap → **postgresql 9.5** → metasploit
  `postgres_login` (default creds) → `postgres_readfile` / `postgres_payload` RCE. *SmartNmap has
  `pgsql-brute` NSE but no postgres exploitation path.*

### E5. Master heuristics (the same across all three corpora) and what SmartNmap must encode

1. **Enumerate → identify version/product → look up exploit → exploit** (universal; nmap 71,
   searchsploit 14). SmartNmap does the first three; §B7.
2. **Anonymous/null access → pull content → mine for the next credential** (Lame, Beep, symfonos,
   Kenobi, Basic-Pentesting, Soupedecode). SmartNmap lists access but never pulls; **§B4 = highest-ROI
   fix after B1**.
3. **Any credential/hash/key → reuse everywhere + crack offline** (DC-4, Armageddon, OpenAdmin,
   Traverxec, Daily-Bugle, Startup, Silver-Platter, Soupedecode). This is *the* connective tissue;
   **§B1/B2/B3 = the P0 fix.** Encode: after any cred, (a) `ssh2john`/`hashcat` it, (b) spray it across
   every discovered service and every known user, (c) if it validates on SMB/LDAP in a domain, run the
   credentialed AD collectors.
4. **Web: default creds → CMS-version→CVE → param-abuse (SQLi/LFI/cmd-inj/IDOR/upload)** (Nibbles,
   Swagshop, Armageddon, Daily-Bugle, symfonos, DC-4, Networked, Beep). SmartNmap crawls + runs
   sqlmap/dalfox/commix, but skips default-cred probing, LFI, IDOR, and HTML-intel harvesting (§B5/B6).
5. **Post-foothold is where boxes are won** — `sudo -l`→GTFOBins (Shocker, Knife, Swagshop, Armageddon,
   OpenAdmin, Bounty-Hacker, Daily-Bugle, Nibbles), SUID/PATH (Kenobi, symfonos), writable cron
   (Bashed, Networked, Startup, Overpass), kernel/DirtyCow (Valentine), docker/lxd (22 files). Out of a
   remote scanner's reach, but SmartNmap should at least **emit an OS-keyed privesc + GTFOBins hand-off**
   (§B8/P2) so the human continues the chain the report itself started.

### E6. Net conclusion for SmartNmap

Across **220+ machines/rooms in three corpora**, the winning methodology is identical: *recon →
version/CVE or web-param foothold → shell → **reuse the loot** → `sudo -l`/SUID/cron/GTFOBins → root*.
SmartNmap today executes a best-in-class **Stages 1–3 scanner** (its NSE map, `VULN_DB`, searchsploit
correlation, crawler, and now injection/AD runners are genuinely strong), but it stops at "here are
findings + ready-to-run commands." The corpus shows the value is in **Stages 4–7: chaining loot into
the next action.** The prioritized fixes in **Section C — P0: make `LootTracker` a state machine +
credential-reuse sweep + auto credentialed-AD collection + password spray; P1: pull-and-mine shares,
web foothold heuristics, chain-aware prioritization** — convert SmartNmap from a *reporter of an attack
surface* into an *executor of the early kill chain*, which is exactly the gap between the tool and the
way every writeup in these three repositories actually works.
