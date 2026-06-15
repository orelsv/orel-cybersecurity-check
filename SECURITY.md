# Security Policy

`oscan` is a security tool, so we hold it to its own standard.

## Reporting a vulnerability in oscan

If you find a security issue **in oscan itself** (not in a target you scanned),
please report it privately rather than opening a public issue:

- Open a [GitHub Security Advisory](https://github.com/orelsv/orel-cybersecurity-check/security/advisories/new) (preferred), or
- Email **orelsv21@gmail.com** with `[oscan security]` in the subject.

Please include steps to reproduce and the affected version. You can expect an
initial response within **7 days**. Once a fix is released, credit will be given
in the changelog unless you prefer to stay anonymous.

## Supported versions

This project is pre-1.0 and moves fast. Only the **latest release** receives
security fixes. Pin a version in production and upgrade deliberately.

| Version | Supported |
|---|---|
| latest `0.x` | ✅ |
| older `0.x`  | ❌ |

## Responsible use

`oscan` can send intrusive (but non-destructive) probes. **Only run it against
assets you own or are explicitly authorized to test.**

- The default `passive` profile only observes — safe GET requests, no payloads.
- The `active` profile (injection markers, auth-lockout, a capped rate-limit
  burst) is **gated**: it requires the `--i-am-authorized` flag, an interactive
  confirmation, and it writes an audit-log entry.
- There is **no DDoS flooder and no password cracker.** "DoS resilience" and
  "auth hardening" only confirm that rate-limiting and account lockout *exist*.
- All payloads are non-destructive detection markers — never `DROP`, never data
  exfiltration.

Scanning systems without authorization may be illegal in your jurisdiction. You
are responsible for how you use this tool.
