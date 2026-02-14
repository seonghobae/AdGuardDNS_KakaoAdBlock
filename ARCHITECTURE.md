# Architecture Overview

This document is a living architecture map for the AdGuard DNS
Kakao AdBlock repository.
It helps contributors and agents quickly locate the right files,
understand data flow, and make safe changes.

## 1. Project Structure

```text
[Project Root]/
|- scripts/                         # Filter generation, DNS validation,
|                                   # and maintenance scripts
|  |- collect_kakao_domains.py      # Main filter generator (sources,
|  |                                # patterns, allowlist, DNS validation)
|  |- validate_domains.py           # Batch DNS validation and report generator
|  |- dns_validator.py              # Local DNS validation server and test mode
|  |- sources.json                  # Public source list and matching patterns
|  `- update-domains.sh             # Helper script for manual domain maintenance
|- tests/
|  `- test_dns_validator.py         # Unit and integration style tests
|                                   # for DNS validator behavior
|- docs/                            # GitHub Pages static site assets
|- .github/
|  |- ISSUE_TEMPLATE/
|  `- workflows/                    # CI for tests, filter generation,
|                                   # and Pages deployment
|- kakao-adblock-filter.txt         # Main generated filter artifact (auto updated)
|- kakao-adblock-production.txt     # Additional filter artifact for manual use
|- README.md                        # User-facing project and usage documentation
|- CONTRIBUTING.md                  # Contributor process and quality gates
|- SECURITY.md                      # Vulnerability reporting policy
`- ARCHITECTURE.md                  # This document
```

## 2. High-Level System Diagram

```text
[Maintainer/Contributor]
        |
        v
[scripts/collect_kakao_domains.py] ---> [kakao-adblock-filter.txt]
        |                                      |
        | fetches public lists                 | consumed by DNS tools and users
        v                                      v
[scripts/sources.json + upstream sources]   [scripts/dns_validator.py --test]
        |
        v
[GitHub Actions: generate-filter.yml, test.yml]
        |
        v
[Repository + GitHub Pages docs]
```

## 3. Core Components

### 3.1. Frontend

Name: Documentation Site (`docs/`)

Description: Static GitHub Pages site with usage and project information.

Technologies: Static HTML, SVG, JSON manifest.

Deployment: GitHub Pages via `.github/workflows/pages.yml`.

### 3.2. Backend Services

#### 3.2.1. Filter Generation Pipeline

Name: Kakao Domain Collector

Description: Collects Kakao and Daum candidate domains from public
sources, applies precision ad-pattern matching and allowlist
protection, validates DNS existence, and writes AdGuard format output.

Technologies: Python 3.9+, standard library (`urllib`, `socket`, `concurrent.futures`).

Deployment: GitHub Actions scheduled and manual runs, plus local CLI execution.

#### 3.2.2. Domain Validation CLI

Name: Domain Validator

Description: Validates domains from a filter file against DNS records,
produces summary and optional cleaned outputs.

Technologies: Python, `dnspython`.

Deployment: Local CLI and CI command execution.

#### 3.2.3. DNS Validation Server

Name: DNS Validator Server

Description: Lightweight UDP DNS test server that returns blocked
or allowed responses based on the generated filter for behavior checks.

Technologies: Python socket server.

Deployment: Local testing utility and CI smoke checks.

## 4. Data Stores

### 4.1. Filter Artifact Store

Name: Repository Text Artifacts

Type: Versioned plain text files in Git.

Purpose: Stores generated blocklist artifacts (`kakao-adblock-filter.txt`, `kakao-adblock-production.txt`).

Key Schemas/Collections: AdGuard DNS rule lines (`||domain^`) and metadata comments.

### 4.2. Source Configuration Store

Name: Source and Pattern Configuration

Type: JSON (`scripts/sources.json`).

Purpose: Defines upstream list URLs, Kakao and Daum matching patterns,
and ad keyword rules.

## 5. External Integrations / APIs

Service Name 1: List-KR source lists

Purpose: Primary Korean filtering source data.

Integration Method: HTTPS raw text fetch.

Service Name 2: YousList source list

Purpose: Additional Korean ad and tracking domains.

Integration Method: HTTPS raw text fetch.

Service Name 3: Public DNS resolvers (Google, Cloudflare, OpenDNS)

Purpose: Domain existence and activity checks.

Integration Method: DNS queries via `dnspython` and socket resolution.

## 6. Deployment and Infrastructure

Cloud Provider: GitHub-hosted infrastructure.

Key Services Used: GitHub Actions, GitHub Pages, GitHub repository storage.

CI/CD Pipeline:
`.github/workflows/generate-filter.yml`,
`.github/workflows/test.yml`,
`.github/workflows/pages.yml`.

Monitoring and Logging: GitHub Actions job logs and script console output.

## 7. Security Considerations

Authentication: No runtime user auth; repository and workflow
permissions control writes.

Authorization: GitHub branch and repository permissions.

Data Encryption: HTTPS/TLS for upstream fetches and GitHub transport.

Key Security Tools/Practices: Public-source-only policy,
allowlist-first blocking logic, and private vulnerability reporting
path in `SECURITY.md`.

## 8. Development and Testing Environment

Local Setup Instructions: See `CONTRIBUTING.md` and quick commands in `AGENTS.md`.

Testing Frameworks: `pytest` (`tests/test_dns_validator.py`).

Code Quality Tools: `ruff` configuration in `pyproject.toml`.

Core Verification Commands:

- `python -m pytest tests/test_dns_validator.py -v --tb=short`
- `python scripts/dns_validator.py --test`

## 9. Future Considerations / Roadmap

- Add stronger policy checks for source allowlisting and unsafe pattern drift.
- Improve docs consistency across README, usage docs, and generated filter metadata.
- Expand deterministic tests around precision allowlist behavior.

## 10. Project Identification

Project Name: AdGuard DNS Kakao AdBlock Filter

Repository URL: `https://github.com/seonghobae/AdGuardDNS_KakaoAdBlock`

Primary Contact/Team: Repository maintainer (`SeongHo Bae`) and contributors.

Date of Last Update: 2026-02-14

## 11. Glossary / Acronyms

AdGuard DNS: DNS-level filtering format and platform used by this project.

NXDOMAIN: DNS response for non-existent domain names.

Allowlist-first: Design principle that protects legitimate service
domains before applying block rules.

Precision filtering: Blocking only high-confidence ad and tracking
domains to reduce service breakage.
