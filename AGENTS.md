# AGENTS Guide

## Purpose

This repository builds and validates a precision AdGuard DNS filter
for Kakao and Daum ad domains.

## Quick Commands

```bash
# Create virtual environment and install dependencies
uv venv
source .venv/bin/activate
uv pip install -e .
uv pip install -e ".[dev]"

# Run core tests
python -m pytest tests/test_dns_validator.py -v --tb=short

# Quick filter behavior check
python scripts/dns_validator.py --test

# Regenerate filter (writes output file)
python scripts/collect_kakao_domains.py kakao-adblock-filter.txt
```

## Guardrails

- Keep precision first behavior: avoid broad blocking rules
  that can break legitimate services.
- Preserve allowlist intent in `scripts/collect_kakao_domains.py`.
- Do not modify `.github/workflows/*` unless explicitly requested.
- Keep changes minimal and aligned with existing repository conventions.
- Never add secrets, tokens, credentials, or private infrastructure details.

## Validation Before Completion

- Run `python -m pytest tests/test_dns_validator.py -v --tb=short`
  for code or filter logic changes.
- Run `python scripts/dns_validator.py --test` to verify blocked and allowed behavior.
- If generation logic changes, run
  `python scripts/collect_kakao_domains.py /tmp/kakao-test-filter.txt`
  and confirm output is created.

## Security

- Use only public sources listed in `scripts/sources.json`
  unless maintainers request changes.
- Do not commit `.env` files, keys, tokens, or personal credentials.
- Route vulnerability reports through `SECURITY.md` process.
