# Security Policy

## Supported Versions

Security fixes are provided for active branches in this repository.

| Branch | Supported | Notes |
| --- | --- | --- |
| `main` | Yes | Stable branch for broad use |
| `develop` | Yes | Active integration branch, best-effort rapid fixes |

## Reporting a Vulnerability

Please report vulnerabilities privately. Do not open a public issue first.

Preferred channels:

1. GitHub Security Advisories (private):
   `https://github.com/seonghobae/AdGuardDNS_KakaoAdBlock/security/advisories/new`
2. Maintainer email (fallback): `me@seonghobae.me`

Include:

- Affected file(s) and branch (`main` or `develop`)
- Reproduction steps or proof of concept
- Expected vs actual behavior
- Potential impact (availability, integrity, confidentiality)
- Suggested fix (optional)

## Disclosure Process

1. Acknowledgement target: within 72 hours.
2. Initial triage target: within 7 days.
3. Remediation plan: shared after triage if issue is confirmed.
4. Coordinated disclosure: public details are shared after fix or mitigation is available.

## Scope

In scope:

- Filter generation and validation scripts in `scripts/`
- DNS validation logic in `scripts/dns_validator.py`
- Test and automation logic that affects filter integrity
- Supply-chain risks from upstream source configuration (`scripts/sources.json`)

Out of scope:

- Upstream third-party list repository vulnerabilities outside this repository
- Generic DNS outages unrelated to this project code

## Handling Secrets and Sensitive Data

- Never commit secrets, tokens, private keys, `.env` files, or internal endpoints.
- Redact sensitive data from logs, screenshots, and issue comments.
