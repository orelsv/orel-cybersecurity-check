---
name: orel_cybersecurity_check
description: Build apps securely from the start AND check already-built sites/apps for vulnerabilities + GDPR. Use when the user is creating an app with AI and wants it secure by default, or wants to audit an existing site/web app/repo (SQLi, secrets in git history, weak cookies/tokens, exposed .git/.env, missing headers, rate-limiting/lockout, GDPR). Drives the `oscan` scanner that ships in this same repo.
domain: cybersecurity
subdomain: web-application-security
tags:
- web-app-security
- dast
- secure-by-default
- gdpr
- privacy
- secrets-scanning
- authorized-testing
owasp:
- A01-broken-access-control
- A02-cryptographic-failures
- A03-injection
- A05-security-misconfiguration
- A07-identification-and-authentication-failures
nist_csf:
- ID.RA-01
- PR.DS-01
- PR.AA-01
- PR.PS-01
- DE.CM-01
mitre_attack:
- T1190
- T1552
- T1078
version: '0.1'
license: MIT
---

# Orel Cybersecurity Check

A lot of sites and apps are now generated with AI and ship with the same holes:
SQL injection, secrets committed to git history, missing security headers,
cookies without Secure/HttpOnly/SameSite, an exposed `.git` or `.env`, no
rate-limiting, and no GDPR basics. This skill has **two modes** - build it right
from the start, and check what already exists. It ships alongside the `oscan`
scanner in this repo (see the root `README.md` to install `oscan`).

> **Scope & ethics.** Only test assets the user owns or is explicitly authorized
> to test. Intrusive checks require an authorization flag (see the scanner's
> `--i-am-authorized`). This is self-assessment / authorized testing / learning,
> never offensive use against third parties. There is no DDoS flooder and no
> password cracker here - "DoS" means verifying rate-limiting exists, and
> "brute force" means verifying lockout exists.

This skill complements, not duplicates, a white-box source-reading review. Use a
code/IaC review skill for deep source audits; use this skill for (a) secure-by-default
build guidance and (b) driving the black-box `oscan` scanner + GDPR.

## Mode A - Build-time (secure by default)

When the user is creating a site/app/API with AI, bake these in from the start.
State which ones apply, then implement them - don't just list them.

**Injection & input**
- Parameterized queries / prepared statements ONLY - never build SQL by string
  concatenation. Same for shell commands and file paths (allowlist + canonicalize).
- Validate input at trust boundaries; context-encode all output (HTML-escape).

**Secrets**
- Secrets in environment variables or a secrets manager (e.g. Azure Key Vault),
  never in code or committed files. Add `.env`, `*.key`, `*.pem` to `.gitignore`
  **before the first commit**. No API keys in frontend bundles.

**Auth & sessions**
- Hash passwords with bcrypt/argon2; enforce a real password policy.
- Cookies: `Secure` + `HttpOnly` + `SameSite=Lax/Strict`. Short-lived tokens;
  never put tokens in URLs. JWTs: strong signing alg (reject `alg=none`), `exp` set,
  no secrets/PII in the payload.
- Rate-limiting + lockout/CAPTCHA on login; offer MFA.

**Transport & headers**
- HTTPS only, redirect HTTP→HTTPS, enable HSTS.
- Set: `Content-Security-Policy`, `X-Content-Type-Options: nosniff`,
  `X-Frame-Options: DENY` (or CSP `frame-ancestors`), `Referrer-Policy`.
  Hide version banners (`server_tokens off`, no `X-Powered-By`).

**Infra (Azure focus)**
- Managed identity over credentials; least-privilege RBAC; private endpoints for
  databases; a WAF/CDN in front (rate-limiting + OWASP CRS).

**GDPR / privacy (if any EU users or PII)**
- Cookie-consent banner BEFORE non-essential cookies/trackers.
- Linked privacy policy; data minimization; self-host fonts (don't load Google
  Fonts from Google - the German Schrems issue); PII only over HTTPS.
- Map the build to the GDPR articles that imply technical controls:

  | Article | What to build |
  |---|---|
  | Art. 5 | Data minimization, purpose limitation, storage limitation - collect/keep only what's needed, set retention/TTL. |
  | Art. 6 | A lawful basis per processing activity (consent, contract, legitimate interest); record which. |
  | Art. 25 | Data protection by design & by default - privacy-preserving defaults, least data exposed. |
  | Art. 30 | Records of Processing Activities (ROPA) - keep an inventory of what data you process and why. |
  | Art. 32 | Security of processing - encryption in transit & at rest, access control, the hardening in this skill. |
  | Art. 33/34 | Breach notification - be able to detect and report a breach to the authority within **72 hours**. |
  | Art. 35 | DPIA for high-risk processing (large-scale profiling, special-category data). |
  | Art. 15-22 | Data subject rights - build endpoints/processes for access (DSAR), rectification, erasure, portability. |

  Don't over-engineer for a hobby project; do apply Art. 5/6/25/32 (minimization,
  lawful basis, privacy-by-default, encryption) as the baseline for anything with real users.

## Mode B - Check-time (audit an existing target)

Drive the **`oscan`** scanner (in this repo), then interpret the results in
plain language and produce a prioritized fix list.

**Decide the profile (always start safe):**
- `passive` (default) - observation only (TLS, headers, cookies, exposed files,
  GDPR/privacy, and repo secrets/git history). Safe to run on any URL you own.
- `standard` - adds non-intrusive analysis: CORS, API docs/excessive-data/verbose
  errors, JWT hygiene, and rate-limit headers. Still GET-only observation.
- `active` - intrusive but non-destructive probes (injection markers for
  SQLi/NoSQLi/XSS/traversal/SSRF, admin-endpoint checks, login lockout, a capped
  DoS-resilience burst). Requires `--i-am-authorized` + confirmation. Only on the
  user's own/authorized targets.

**Typical invocations** (verify flags with `oscan --help` - see Rules):
```bash
oscan https://their-site.example                          # passive, safe default (GDPR/privacy included)
oscan https://their-site.example --md report.md           # passive + Markdown report
oscan --repo /path/to/their-repo                          # local secrets + git-history scan
oscan --repo https://github.com/owner/name.git            # clone a remote repo, scan, clean up
oscan https://their-site.example --profile standard       # + CORS, API, JWT, rate-limit headers
oscan https://their-site.example --profile active --i-am-authorized --json out.json
```

If `oscan` is not installed, point the user at the repo's `README.md` install
steps, or fall back to manual checks (curl for headers/cookies, `gitleaks` for
secrets, inspect `Set-Cookie` flags, request `/.git/HEAD` and `/.env`).

**What oscan checks (so you can explain coverage):** TLS/headers, cookie & token
hygiene, secrets in working tree **and git history**, exposed `.git`/`.env`/source
maps, SQLi/XSS/traversal/open-redirect (active), admin-endpoint exposure, JWT
hygiene, login rate-limiting/lockout (active), WAF/rate-limit presence + a capped
resilience burst (active), and GDPR/privacy (consent, trackers, fonts, privacy policy).

**Then:**
1. Summarize the Risk Score (0-100) and the worst issues in plain language -
   what an attacker could actually do, for a non-expert.
2. Give a prioritized remediation list: critical/high first, "quick wins" called out.
3. Tie each fix back to the Mode A guidance above.
4. Offer to write an Obsidian note documenting the audit.

## Rules
- **`oscan --help` is the source of truth** for the exact flags and `--profile`
  levels - they evolve between releases. Run it before building a command rather
  than trusting the examples above; if an example here disagrees with `--help`,
  `--help` wins (and fix this file).
- Never invent findings. If the scan is clean, say so and suggest defense-in-depth.
- Always explain WHY in plain language - the user is learning.
- Confirm authorization before any `active` scan; default to `passive`.
- For deep source-code review, hand off to a dedicated code-review skill; for
  documenting the result, hand off to a lab-writeup skill.
