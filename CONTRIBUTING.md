# Contributing Guide

Thank you for helping improve this precision Kakao and Daum DNS filter.

## 1. Branching Flow

- Base branches:
  - `develop`: active integration branch.
  - `main`: stable branch for broad consumption.
- Create topic branches from `develop`:
  - `feat/<short-topic>`
  - `fix/<short-topic>`
  - `docs/<short-topic>`
- Open pull requests to `develop` unless a maintainer requests a direct `main` fix.

## 2. Local Setup

```bash
uv venv
source .venv/bin/activate
uv pip install -e .
uv pip install -e ".[dev]"
```

## 3. Required Validation

Run these before opening a PR for code, script, or filter logic changes:

```bash
python -m pytest tests/test_dns_validator.py -v --tb=short
python scripts/dns_validator.py --test
```

If you changed filter generation logic, also run:

```bash
python scripts/collect_kakao_domains.py /tmp/kakao-test-filter.txt
```

## 4. Commit Style

Use short Conventional Commit style messages:

- `feat: add ...`
- `fix: correct ...`
- `docs: update ...`
- `test: add ...`
- `chore: ...`

Keep each commit focused on one logical change.

## 5. Link Issues in PRs

- Reference context with `Refs #123`.
- Close issues with `Closes #123` when the PR fully resolves them.
- For ad-domain reports, include test evidence or reproduction details.

## 6. PR Checklist

- [ ] Scope is minimal and does not include unrelated refactors.
- [ ] Precision-first behavior is preserved (no broad over-blocking).
- [ ] Allowlist intent in `scripts/collect_kakao_domains.py` is preserved.
- [ ] Required validation commands were run locally.
- [ ] PR description includes why the change is needed.
- [ ] Linked issue(s) are included (`Refs #...` or `Closes #...`).
- [ ] No secrets, credentials, private URLs, or `.env` files are included.

## 7. Guardrails

- Do not modify `.github/workflows/*` unless explicitly requested.
- Use only public upstream sources, or document and justify any source change.
- Prefer under-blocking over breaking legitimate Kakao services.
