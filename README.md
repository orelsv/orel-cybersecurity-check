# oscan - orel-cybersecurity-check

[![CI](https://github.com/orelsv/orel-cybersecurity-check/actions/workflows/ci.yml/badge.svg)](https://github.com/orelsv/orel-cybersecurity-check/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Python](https://img.shields.io/badge/python-3.11%2B-blue.svg)](pyproject.toml)

A manual, **authorized self-assessment** scanner for the sites, web apps, and
repos people increasingly build with AI. It catches the holes those builds ship
with - SQL injection, secrets in git history, weak cookies/tokens, an exposed
`.git`/`.env`, missing security headers, no rate-limiting - and it checks
**GDPR/privacy** basics too.

Detection is deterministic (in code); an optional Claude layer only rewrites
findings into plain language. The tool works fully offline without it.

This repo ships **both** pieces:
- **`oscan`** - the scanner (this README).
- **`orel_cybersecurity_check`** - a [Claude Code](https://claude.com/claude-code)
  skill (in [`skill/`](skill/orel_cybersecurity_check/SKILL.md)) that drives `oscan`
  and adds secure-by-default build guidance. See [Claude Code skill](#claude-code-skill) below.

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
- All payloads are non-destructive detection markers - never `DROP`, never data
  exfiltration.

## Install

Run it once, with no permanent install (needs [uv](https://docs.astral.sh/uv/)):

```bash
uvx --from orel-cybersecurity-check oscan https://your-site.example
```

Install the `oscan` command for repeated use:

```bash
pipx install orel-cybersecurity-check     # isolated (recommended)
pip install orel-cybersecurity-check      # or plain pip
```

For the optional Claude enrichment layer, add the `ai` extra:
`pipx install "orel-cybersecurity-check[ai]"`.

From source, for development:

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

- **Transport & TLS** - HTTPS, TLS version, cert validity, HTTP→HTTPS redirect, HSTS
- **Security headers** - CSP, X-Content-Type-Options, clickjacking protection, Referrer-Policy, version disclosure
- **Cookies & tokens** - Secure / HttpOnly / SameSite flags, JWT in cookies, tokens in URLs
- **Secrets & git** - working tree **and full git history** (committed-then-deleted secrets), `.gitignore` coverage. Allowlist a known/fake secret with an inline `# gitleaks:allow` (or `# pragma: allowlist secret`) marker, or a repo `.gitleaksignore`.
- **Exposed files** - `/.git`, `/.env`, config/backup files, source maps
- **CORS** *(standard)* - arbitrary-origin reflection, wildcard-with-credentials
- **API security** *(standard)* - exposed OpenAPI/Swagger docs, GraphQL introspection, excessive data exposure (sensitive fields in JSON), verbose error/stack-trace disclosure
- **Injection** *(active)* - SQLi (error-based + **time-based blind**), **NoSQL** injection, reflected XSS, path traversal, open redirect, **SSRF** (cloud-metadata)
- **Auth hardening** *(active)* - JWT hygiene (`alg=none`, HMAC alg-confusion risk, empty signature, no-exp, sensitive claims), unauthenticated admin/debug endpoints, login rate-limiting/lockout
- **DoS resilience** - WAF/CDN/rate-limit presence + a capped burst to confirm throttling
- **GDPR / privacy** - consent before tracking, third-party trackers, Google Fonts, privacy policy, PII over HTTP

### Output

Console summary with a **Risk Score (0-100)**, a letter grade, and an estimated
**time-to-compromise**, plus optional JSON (SIEM-friendly) and Markdown reports.

### Optional Claude enrichment

If the `anthropic` package is installed and `ANTHROPIC_API_KEY` is set, each
finding gets a one-sentence plain-language explanation. Detection is unchanged -
Claude is only a presentation layer. Disable with `--no-enrich`; pick a model
with `OSCAN_ENRICH_MODEL` (default `claude-haiku-4-5`).

## Claude Code skill

The `orel_cybersecurity_check` skill lets [Claude Code](https://claude.com/claude-code)
build apps securely by default and drive `oscan` to audit existing ones. Install
it globally (one line):

```bash
mkdir -p ~/.claude/skills && curl -sL https://github.com/orelsv/orel-cybersecurity-check/archive/main.tar.gz | tar -xz --strip-components=2 -C ~/.claude/skills orel-cybersecurity-check-main/skill/orel_cybersecurity_check
```

Then restart your Claude Code session. The skill is at
[`skill/orel_cybersecurity_check/SKILL.md`](skill/orel_cybersecurity_check/SKILL.md).
For a project-local install instead of global, replace `~/.claude/skills` with
`.claude/skills` in your project root.

## Development

```bash
pip install -e ".[dev]"
ruff check . && ruff format --check .   # lint + formatting (CI gate)
pytest                                  # 51 tests, no network required
```

The test suite includes an end-to-end run against a deliberately vulnerable
local server and a git repo with a committed-then-deleted secret. CI runs the
same checks on Python 3.11-3.13. See [CONTRIBUTING.md](CONTRIBUTING.md).

## License

MIT
