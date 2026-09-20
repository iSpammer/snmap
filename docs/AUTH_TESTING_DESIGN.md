# Broken-Authentication & Session Testing — Incorporation Design

Research + design for adding broken-auth / auth-logic / cookie & session manipulation
to SmartNmap. Grounded in OWASP WSTG (Authentication WSTG-ATHN-01..10, Session
Management WSTG-SESS-01..09), current automated-auth-testing research (AuthREST,
arXiv 2509.10320), and the bug-bounty hunt corpus (auth-bypass, session, MFA, OAuth,
CSRF). Gating follows SmartNmap's existing safe-by-default model.

## The honest constraint (why this needs a new primitive)

SmartNmap today is a **network-recon + crawl** tool: it discovers HTTP services, crawls
them into a URL/param corpus, curls paths, and captures response headers. It has **no
session state** — it never logs in, holds a cookie jar, parses a login form, or replays
an authenticated request. Most *deep* broken-auth testing (session fixation across
login, privilege escalation via cookie tampering, MFA step-skipping, OAuth flows) is
inherently **stateful and multi-step**, and much of it needs valid credentials or human
judgment of business logic.

So the work splits into three tiers by how well it fits an automated tool:

- **Tier 1 — passive analysis of data we already fetch** (safe, runs by default).
- **Tier 2 — active auth probes** needing a tiny HTTP-auth helper (gated `--active`).
- **Tier 3 — logic/creative flaws** that can't be reliably automated → **detect the
  surface + emit targeted recommend commands and an ordered checklist**.

No new heavy dependency is required: cookie parsing uses `http.cookies`, JWT decoding
uses stdlib base64/json (no PyJWT), and probes use the `curl`/`_run` pattern already in
the file. One new primitive: `AuthProbe` — a minimal curl-backed client that submits a
detected login form and diffs responses (status/length/location/timing), reused by the
lockout, username-enumeration, and default-cred checks.

---

## Tier 1 — Passive (run by default; pure analysis, zero extra requests where possible)

Populate new LootTracker signals + structured `vulns` + chain-enablers. All derive from
responses SmartNmap already captures (`http_headers_{port}.txt`, crawl corpus, page
bodies from the HTML-intel pass).

| Check | WSTG | What it does | Signal |
|-------|------|--------------|--------|
| **Cookie attribute audit** | SESS-02 | Parse every `Set-Cookie`; flag session cookies missing `HttpOnly`/`Secure`/`SameSite`, overly broad `Domain`/`Path`, `Secure` absent over HTTPS | medium |
| **Session-ID in URL** | SESS-04/09 | Grep corpus for `jsessionid=/phpsessid=/sid=/token=` in URLs (session/token leakage in referrers, logs) | medium |
| **JWT weakness decode** | (SESS-JWT) | Find JWTs in cookies/headers/params/bodies; base64-decode header+payload; flag `alg:none`, `alg:HS256` (alg-confusion candidate), missing/huge `exp`, sensitive claims, `kid` injection surface | high (alg:none) |
| **Cookie tamperability** | logic | Flag structured/guessable cookies: base64-JSON with `role/admin/is_admin/user/level`, plaintext `admin=0`, sequential/short ids, unsigned values → candidate privilege/session tamper | high |
| **Cleartext credential post** | ATHN-01 | Login `<form action>` posts to `http://` (not https) or Basic-Auth over HTTP (`WWW-Authenticate: Basic`) | high |
| **CSRF token presence** | SESS-05 | State-changing `<form>`/POST without an anti-CSRF token field/header | medium |
| **Auth-page caching** | ATHN-06 | Login/account pages missing `Cache-Control: no-store` | low |
| **Auth surface discovery** | — | Detect login/logout/register/reset/2FA/oauth/SSO endpoints + login forms (fields, csrf, action) → seed Tier 2/3 and the brute username list | info |

New LootTracker additions: `auth_findings` list + reuse of `usernames`/`notes`; each Tier-1
hit also becomes a chain-enabler (a tamperable role cookie or `alg:none` JWT is a foothold,
not just an "info").

---

## Tier 2 — Active auth probes (gated `--active`/`--ctf`; else `_recommend`)

Backed by the new `AuthProbe` helper. Intensity reduced in `--bb`.

| Check | WSTG | Method | Safety note |
|-------|------|--------|-------------|
| **Default creds on login form** | ATHN-02 | Submit a small default-cred list to the detected login form; success = redirect/session-cookie/absence-of-error | extend existing panel default-cred logic to generic forms |
| **Weak lockout / rate limit** | ATHN-03 | Send N (small, e.g. 6) bad logins **using a random throwaway username** and detect whether lockout/rate-limit/CAPTCHA ever appears; report its *absence* | **never brute a real account** — throwaway user only; hard-gated; skipped in `--bb` unless explicit |
| **Username enumeration** | ATHN-* | Diff login/reset responses (status/length/message/timing) for a known-bad vs candidate usernames from loot | low request count |
| **Auth-schema bypass** | ATHN-04 | Forced-browse known authed paths (reuse dir-brute); param tamper (`admin=true`,`role=admin`,`debug=1`); 401/403 header tricks (`X-Original-URL`, `X-Rewrite-URL`, `X-Forwarded-For`, verb swap) | mostly read-only GETs |
| **Session fixation** | SESS-03 | If creds available: capture pre-auth cookie, log in, verify the session id rotated | needs a cred (from reuse loop or `--creds`) |
| **Logout invalidation** | SESS-06 | If creds available: use session, logout, replay old cookie, expect 401 | needs a cred |

Feeds the credential state machine: any working login → `loot.add_cred(..., verified=True)`
→ the existing **credential-reuse sweep** and AD collection.

---

## Tier 3 — Logic / creative flaws (detect surface → recommend + checklist)

Not reliably automatable; encode the *decision-logic* as targeted recommendations keyed to
detected surface, mirroring the hunt corpus. Emitted into the report's Recommend section
and a new **"Auth Attack Playbook"** block.

- **MFA/2FA bypass** (if a 2FA step detected): step-skip via direct post-login URL, OTP
  reuse/replay, missing rate-limit on OTP (brute 000000–999999), backup-code dump via
  `/api/me`, factor downgrade.
- **OAuth/SSO** (if `/oauth`,`/authorize`,`client_id`,SAML detected): `redirect_uri`
  manipulation, missing `state` (CSRF), token/audience confusion, SAML signature stripping/XSW.
- **Password reset logic**: host-header poisoning of reset link, predictable/short token,
  reset without old password, token not invalidated after use.
- **Cookie/role tamper** (from Tier-1 tamperable cookie): flip `role`/`admin`, re-sign HS256
  JWT with alg-confusion, `none`-alg forge.
- **Business logic**: mass-assignment on register (`"role":"admin"`), response manipulation
  (`"success":false`→`true`), race conditions on login/OTP.

---

## Architecture (in-file, single-file preserved)

New phase-5 runners (same `which`-guard + try/except + timeout + loot + `_recommend`-when-gated pattern):

- `analyze_cookies(headers_text, url, is_https, loot)` — Tier 1 cookie audit (helper).
- `decode_and_flag_jwt(token, source, loot)` — Tier 1 JWT decode (helper, stdlib only).
- `detect_auth_surface(url, corpus, outdir, loot)` — find login/2FA/oauth/reset endpoints + forms.
- `run_auth_suite(url, port, corpus, outdir, args, tools, loot)` — orchestrates Tier 1 (always)
  + Tier 2 (gated) + Tier 3 (recommend); called per HTTP port right after `run_web_foothold_suite`.
- `class AuthProbe` — minimal curl-backed form login + response-diff (for lockout/user-enum/default-cred).

LootTracker: add `auth_findings` bucket (rendered in report + loot.md) and feed
`_chain_enablers` (tamperable cookie / alg:none JWT / default cred = top-of-report foothold).
New flag: none required (reuses `--active`, `--creds`, `--userlist`, `--passlist`); optionally
`--login-url URL` to point the auth suite at a specific login endpoint.

Tests (in `tests/test_parsing.py`, no network): cookie-attribute parser (missing flags →
finding), JWT decoder (`alg:none`/HS256 detection), tamperable-cookie heuristic, and the
safety gate (Tier-2 probes return nothing / only recommend when `--active` is off; lockout
probe never targets a real username).

---

## Prioritization

- **P0 (Tier 1):** cookie audit, JWT decode, session-in-URL, tamperable-cookie, cleartext-creds,
  auth-surface discovery. Highest value/effort ratio, fully safe, uses data already fetched.
- **P1 (Tier 2):** `AuthProbe` + default-cred-on-forms, lockout/rate-limit (throwaway user),
  username-enum, auth-schema bypass. Needs the probe primitive; account-lockout risk = strict gating.
- **P2 (Tier 3):** MFA/OAuth/reset/cookie-tamper/business-logic recommend playbook + report block.

## Sources
- OWASP WSTG Authentication Testing (WSTG-ATHN-01..10) and Session Management Testing (WSTG-SESS-01..09).
- OWASP WSTG "Testing for Cookies Attributes" (SESS-02).
- "Automated Testing of Broken Authentication Vulnerabilities in Web APIs with AuthREST" (arXiv 2509.10320).
- Bug-bounty hunt corpus: auth-bypass, session, MFA-bypass, OAuth, CSRF pattern sets.
