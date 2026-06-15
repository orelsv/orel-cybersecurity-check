# Contributing

Thanks for taking a look. This is a small, focused project, so the process is light.

## Development setup

```bash
git clone https://github.com/orelsv/orel-cybersecurity-check.git
cd orel-cybersecurity-check
python3 -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"
```

## Before you open a pull request

Run the same checks CI runs - they must all pass:

```bash
ruff check .            # lint
ruff format .           # auto-format (or `ruff format --check .` to verify)
pytest -q               # 51 tests, no network required
```

CI runs the test suite on Python 3.11, 3.12, and 3.13, so keep new code
compatible with all three.

## Adding a check

Each check lives in `oscan/checks/` and returns `Finding` objects (see
`oscan/core/finding.py`). A few rules of thumb:

- Detection must be **deterministic and in code**. The optional Claude layer in
  `oscan/report/enrich.py` only rephrases findings; it never decides them.
- Anything intrusive belongs in the `active` profile and must respect the
  authorization gate in `oscan/core/safety.py`. No destructive payloads, no
  DDoS, no password cracking - see [SECURITY.md](SECURITY.md).
- Add a test in `tests/`. The suite runs fully offline against a local
  vulnerable fixture, so no live target is needed.

## Style

Formatting and import order are handled by ruff (config in `pyproject.toml`);
don't hand-tune what the formatter owns. Keep comments explaining *why*, not
*what*.
