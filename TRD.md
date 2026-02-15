# Technical Requirements Document (TRD)

## Overview
The project is a Python-based pipeline that collects candidate domains, validates them, and outputs DNS blocklist files. A static website in `docs/` provides distribution and guidance.

## Architecture
- Data sources: `scripts/sources.json`
- Collection: `scripts/collect_kakao_domains.py`
- Validation: `scripts/validate_domains.py` and `scripts/dns_validator.py`
- Outputs:
  - `kakao-adblock-filter.txt`
  - `kakao-adblock-production.txt`
- Website: `docs/` (static HTML, CSS, JS)

## Data Flow
1. Load domain sources from `scripts/sources.json`.
2. Collect candidate domains into a working file.
3. Validate domains:
   - DNS activity check
   - Allowlist conflict check
4. Write cleaned results to output files.

## Implementation Details
### Collection
- `collect_kakao_domains.py` merges domains from multiple sources.
- Output is a raw list suitable for validation.

### Validation
- `dns_validator.py` performs DNS lookups and status checks.
- `validate_domains.py` applies validation rules and produces cleaned output.

### Outputs
- `kakao-adblock-filter.txt` is the primary list.
- `kakao-adblock-production.txt` is the production-stable list.

## Testing
- Unit tests live under `tests/`.
- Use pytest configured in `pyproject.toml`.

## Tooling
- Python >= 3.9.
- Package management via `uv`.
- Linting style configured with ruff (see `pyproject.toml`).

## Local Development
1. Create a venv and install dependencies:
   - `uv venv`
   - `uv pip install -e ".[dev]"`
2. Run tests:
   - `uv run pytest`

## Validation Steps
- Run collection and validation scripts on a sample output file.
- Compare output diff to ensure only expected changes.
- Run pytest for regressions.

## Operational Considerations
- Avoid blocking essential Kakao services by maintaining allowlist rules.
- Document any source changes and validation logic updates.
