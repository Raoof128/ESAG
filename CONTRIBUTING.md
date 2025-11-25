# Contributing

Thank you for considering a contribution! This project welcomes improvements across code, documentation, tests, and automation.

## Getting started

1. Create a virtual environment and install dependencies:

   ```bash
   python -m venv .venv
   source .venv/bin/activate
   pip install -r requirements.txt
   ```

2. Install developer tooling:

   ```bash
   pip install black ruff pytest
   ```

3. Run checks locally:

   ```bash
   black .
   ruff check .
   python -m pytest
   ```

## Development guidelines

- Use type hints and docstrings that describe the meaning of SPF, DMARC, and DKIM tags where relevant.
- Avoid wrapping imports in try/except; fail fast when dependencies are missing.
- Keep CLI flags stable and documented in the README.
- Add or update tests for any behavior change.
- Favor clear logging over silent failures.

## Submitting changes

- Create a topic branch and keep commits focused.
- Include a clear description of the risk signals introduced or modified.
- Ensure CI (lint + tests) is green before submitting a pull request.
