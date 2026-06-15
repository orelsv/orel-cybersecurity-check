# Changelog

All notable changes to this project are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project aims
to follow [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- MIT `LICENSE` file so the project can be reused.
- `SECURITY.md` with a private vulnerability-reporting and responsible-use policy.
- GitHub Actions CI: `pytest` on Python 3.11, 3.12, and 3.13, plus `ruff` lint
  and format checks.
- `ruff` configuration and a `dev` dependency for it.
- `CONTRIBUTING.md`.
- PyPI packaging metadata (trove classifiers, project URLs, SPDX license) and a
  release workflow that publishes to PyPI via Trusted Publishing on a version tag.

### Changed
- Normalized punctuation to plain ASCII across source and docs.

## [0.1.0] - 2026-06-13

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

[Unreleased]: https://github.com/orelsv/orel-cybersecurity-check/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/orelsv/orel-cybersecurity-check/releases/tag/v0.1.0
