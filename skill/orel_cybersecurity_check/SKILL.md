---
name: orel_cybersecurity_check
description: Build apps securely from the start AND check already-built sites/apps for vulnerabilities + GDPR. Use when the user is creating an app with AI and wants it secure by default, or wants to audit an existing site/web app/repo (SQLi, secrets in git history, weak cookies/tokens, exposed .git/.env, missing headers, rate-limiting/lockout, GDPR). Drives the `oscan` scanner that ships in this same repo.
---

# Orel Cybersecurity Check

A lot of sites and apps are now generated with AI and ship with the same holes:
SQL injection, secrets committed to git history, missing security headers,
cookies without Secure/HttpOnly/SameSite, an exposed `.git` or `.env`, no
rate-limiting, and no GDPR basics. This skill has **two modes** — build it right
from the start, and check what already exists. It ships alongside the `oscan`
scanner in this repo (see the root `README.md` to install `oscan`).

> **Scope & ethics.** Only test assets the user owns or is explicitly authorized
> to test. Intrusive checks require an authorization flag (see the scanner's
> `--i-am-authorized`). This is self-assessment / authorized testing / learning,
> never offensive use against third parties. There is no DDoS flooder and no
> password cracker here — "DoS" means verifying rate-limiting exists, and
> "brute force" means verifying lockout exists.

This skill complements, not duplicates, a white-box source-reading review. Use a
code/IaC review skill for deep source audits; use this skill for (a) secure-by-default
build guidance and (b) driving the black-box `oscan` scanner + GDPR.

## Mode A — Build-time (secure by default)

When the user is creating a site/app/API with AI, bake these in from the start.
State which ones apply, then implement them — don't just list them.

**Injection & input**
- Parameterized queries / prepared statements ONLY — never build SQL by string
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
  Fonts from Google — the German Schrems issue); PII only over HTTPS.

## Mode B — Check-time (audit an existing target)

Drive the **`oscan`** scanner (in this repo), then interpret the results in
plain language and produce a prioritized fix list.

**Decide the profile (always start safe):**
- `passive` (default) — observation only, safe to run on any URL you own.
- `standard` — adds path enumeration and JWT analysis.
- `active` — intrusive but non-destructive probes (SQLi/XSS markers, auth-lockout,
  DoS-resilience burst). Requires `--i-am-authorized` + confirmation. Only on the
  user's own/authorized targets.

**Typical invocations:**
```bash
oscan https://their-site.example                          # passive, safe default
oscan --repo /path/to/their-repo                          # secrets + git history scan
oscan https://their-site.example --gdpr --md report.md    # privacy-focused, Markdown report
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
1. Summarize the Risk Score (0–100) and the worst issues in plain language —
   what an attacker could actually do, for a non-expert.
2. Give a prioritized remediation list: critical/high first, "quick wins" called out.
3. Tie each fix back to the Mode A guidance above.
4. Offer to write an Obsidian note documenting the audit.

## Rules
- Never invent findings. If the scan is clean, say so and suggest defense-in-depth.
- Always explain WHY in plain language — the user is learning.
- Confirm authorization before any `active` scan; default to `passive`.
- For deep source-code review, hand off to a dedicated code-review skill; for
  documenting the result, hand off to a lab-writeup skill.
