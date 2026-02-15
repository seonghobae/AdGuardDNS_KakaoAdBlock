# CLAUDE Agent Guide

## Scope

Use this repository to maintain a precision Kakao and Daum
AdGuard DNS filter without breaking legitimate Kakao services.

## Quick Start

```bash
# Environment
uv venv
source .venv/bin/activate
uv pip install -e .
uv pip install -e ".[dev]"

# Validation
python -m pytest tests/test_dns_validator.py -v --tb=short
python scripts/dns_validator.py --test
```

## Operational Rules

- Prioritize precision over coverage.
- It is better to miss some ad domains than to over-block.
- Keep allowlist behavior intact in `scripts/collect_kakao_domains.py`.
- Keep edits focused; avoid unrelated refactors.
- Do not modify `.github/workflows/*` unless explicitly requested.
- Do not add secrets, private endpoints, credentials, or local machine data.

## Required Checks

- For script, filter, or test changes:
  - `python -m pytest tests/test_dns_validator.py -v --tb=short`
  - `python scripts/dns_validator.py --test`
- If domain collection logic changes:
  - `python scripts/collect_kakao_domains.py /tmp/kakao-test-filter.txt`

## Security Handling

- Treat all external source data as untrusted input.
- Keep source list changes explicit and reviewable in `scripts/sources.json`.
- Use private reporting flow in `SECURITY.md` for vulnerabilities.
