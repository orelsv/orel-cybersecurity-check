# Changelog

All notable changes to this project are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project aims
to follow [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.1] - 2026-06-15

### Added
- Secret-scan allowlist: lines marked `# gitleaks:allow`, `# pragma: allowlist
  secret`, or `# oscan:allow` are skipped, and a scanned repo's own
  `.gitleaksignore` is now honored.
- `*.key` and `*.pem` to the project `.gitignore`.

### Fixed
- Repo scans no longer report a project's deliberately-fake test fixtures or
  documented example secrets as real leaks (the scanner was flagging its own).

## [0.1.0] - 2026-06-15

### Added
- Initial release of `oscan`: an authorized self-assessment scanner for sites,
  web apps, and repos.
- Checks for transport/TLS, security headers, cookie and token hygiene, secrets
  in the working tree and full git history, exposed `.git`/`.env`, CORS, API
  exposure (OpenAPI/Swagger, GraphQL introspection, excessive data, verbose
  errors), injection (SQLi incl. time-based blind, NoSQLi, XSS, path traversal,
  open redirect, SSRF), auth hardening (JWT hygiene, admin endpoints, login
  lockout), DoS resilience, and GDPR/privacy.
- Three profiles: `passive` (default, safe), `standard`, and a gated `active`
  profile requiring `--i-am-authorized` and confirmation.
- Risk score (0-100) with a letter grade, plus JSON and Markdown reports.
- Optional Claude layer that rephrases findings into plain language; detection
  stays deterministic and works fully offline.
- Bundled `orel_cybersecurity_check` Claude Code skill.
- MIT `LICENSE`, `SECURITY.md`, `CONTRIBUTING.md`, and this changelog.
- GitHub Actions CI (`pytest` on Python 3.11-3.13, `ruff` lint/format) and a
  PyPI release workflow using Trusted Publishing.

[0.1.1]: https://github.com/orelsv/orel-cybersecurity-check/releases/tag/v0.1.1
[0.1.0]: https://github.com/orelsv/orel-cybersecurity-check/releases/tag/v0.1.0
