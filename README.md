# oscan — orel-cybersecurity-check

A manual, **authorized self-assessment** scanner for the sites, web apps, and
repos people increasingly build with AI. It catches the holes those builds ship
with — SQL injection, secrets in git history, weak cookies/tokens, an exposed
`.git`/`.env`, missing security headers, no rate-limiting — and it checks
**GDPR/privacy** basics too.

Detection is deterministic (in code); an optional Claude layer only rewrites
findings into plain language. The tool works fully offline without it.

> Companion to the [`orel_cybersecurity_check`](https://github.com/orelsv/claude-skills)
> Claude Code skill, which drives this scanner and adds secure-by-default build guidance.

## ⚠️ Authorization & ethics

Use this **only** on assets you own or are explicitly authorized to test. It is
for self-assessment, authorized pentesting, and learning.

- The default `passive` profile only observes (safe GET requests, no payloads).
- The intrusive `active` profile (injection markers, auth-lockout, a capped
  rate-limit burst) **requires** the `--i-am-authorized` flag, an interactive
  confirmation, and writes an audit log entry.
- There is **no DDoS flooder and no password cracker**. "DoS resilience" verifies
  rate-limiting/WAF *exists* (a hard-capped burst); "auth hardening" verifies
  account *lockout* exists (a few failed logins on your own account). The goal is
  to confirm defenses work, not to attack.
- All payloads are non-destructive detection markers — never `DROP`, never data
  exfiltration.

## Install

```bash
git clone https://github.com/orelsv/orel-cybersecurity-check.git
cd orel-cybersecurity-check
python3 -m venv .venv && source .venv/bin/activate
pip install -e .            # add ".[ai]" for the optional Claude layer
```

Optional external tools (auto-detected, graceful fallback if missing):
[`gitleaks`](https://github.com/gitleaks/gitleaks) for stronger secret scanning.

## Usage

```bash
# Passive scan of a live site (safe default)
oscan https://your-site.example

# Scan a local repo for secrets in the working tree AND git history
oscan --repo /path/to/your-repo

# Write machine + human reports
oscan https://your-site.example --json report.json --md report.md

# GDPR / privacy focus
oscan https://your-site.example --gdpr

# Active (intrusive, non-destructive) scan of YOUR OWN target
oscan https://your-site.example --profile active --i-am-authorized

# Verify login lockout exists (your own test account)
oscan https://your-site.example --profile active --i-am-authorized \
  --login-url https://your-site.example/login --login-user you@example.com
```

### Profiles

| Profile | What it does | Gate |
|---|---|---|
| `passive` (default) | TLS, headers, cookies/tokens, exposed `.git`/`.env`, secrets, GDPR | none |
| `standard` | + path enumeration, JWT analysis, WAF/rate-limit header check | none |
| `active` | + SQLi/XSS/traversal/open-redirect markers, admin-endpoint probe, login-lockout, DoS-resilience burst | `--i-am-authorized` + confirm |

### What it checks

- **Transport & TLS** — HTTPS, TLS version, cert validity, HTTP→HTTPS redirect, HSTS
- **Security headers** — CSP, X-Content-Type-Options, clickjacking protection, Referrer-Policy, version disclosure
- **Cookies & tokens** — Secure / HttpOnly / SameSite flags, JWT in cookies, tokens in URLs
- **Secrets & git** — working tree **and full git history** (committed-then-deleted secrets), `.gitignore` coverage
- **Exposed files** — `/.git`, `/.env`, config/backup files, source maps
- **Injection** *(active)* — SQLi (error/marker), reflected XSS, path traversal, open redirect
- **Auth hardening** *(active)* — JWT hygiene, unauthenticated admin/debug endpoints, login rate-limiting/lockout
- **DoS resilience** — WAF/CDN/rate-limit presence + a capped burst to confirm throttling
- **GDPR / privacy** — consent before tracking, third-party trackers, Google Fonts, privacy policy, PII over HTTP

### Output

Console summary with a **Risk Score (0–100)**, a letter grade, and an estimated
**time-to-compromise**, plus optional JSON (SIEM-friendly) and Markdown reports.

### Optional Claude enrichment

If the `anthropic` package is installed and `ANTHROPIC_API_KEY` is set, each
finding gets a one-sentence plain-language explanation. Detection is unchanged —
Claude is only a presentation layer. Disable with `--no-enrich`; pick a model
with `OSCAN_ENRICH_MODEL` (default `claude-haiku-4-5`).

## Development

```bash
pip install -e ".[dev]"
pytest                      # 42 tests, no network required
```

The test suite includes an end-to-end run against a deliberately vulnerable
local server and a git repo with a committed-then-deleted secret.

## License

MIT
