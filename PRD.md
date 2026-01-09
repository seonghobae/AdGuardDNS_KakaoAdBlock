# Product Requirements Document (PRD)

## Summary
This project provides a precision AdGuard DNS filter that blocks only verified Kakao/Daum ad and tracking domains while protecting essential services. It also ships a small static website for documentation and distribution.

## Goals
- Block confirmed ad and tracking domains for Kakao/Daum without breaking core services.
- Provide validated, up-to-date filter outputs for DNS blocklists.
- Offer clear, user-friendly documentation and distribution via GitHub Pages.

## Non-Goals
- General-purpose ad blocking beyond Kakao/Daum.
- Blocking by aggressive heuristics that risk false positives.
- Real-time, user-specific personalization or telemetry collection.

## Target Users
- Users of AdGuard Home, Pi-hole, and similar DNS-based blockers.
- Operators who want minimal overblocking risk for Kakao services.

## User Stories
- As a user, I want a DNS filter URL I can add to AdGuard Home so Kakao ads are blocked.
- As a user, I want core Kakao services to keep working even if ad blocking is enabled.
- As a maintainer, I want a repeatable process to collect and validate domains.

## Functional Requirements
1. Collect candidate Kakao/Daum ad domains from known public sources.
2. Validate domain activity and remove inactive or false-positive domains.
3. Maintain a protected allowlist of essential Kakao services.
4. Produce two output files:
   - A primary filter file for general use.
   - A production-stable filter file with stricter validation.
5. Publish the filter URL via the project README and GitHub Pages.
6. Provide documentation for common DNS products and usage patterns.

## Non-Functional Requirements
- Reliability: Avoid false positives that break login, payment, maps, or messaging.
- Maintainability: Scripts and sources are documented and easy to extend.
- Performance: Validation steps should complete on a typical laptop in minutes.
- Transparency: Document sources and validation rules.

## Data Requirements
- Input sources defined in a structured list (JSON).
- Validation should verify domain activity and allowlist conflicts.
- Output must be deterministic for the same input set.

## UX Requirements
- Documentation must be bilingual-ready and clearly explain usage steps.
- Filter URL must be easy to copy and stable.
- Website content should provide a quick overview and detailed usage.

## Integration Requirements
- Compatible with AdGuard Home, Pi-hole, and similar DNS blocklist systems.
- Raw GitHub URL distribution for auto-update support.

## Success Metrics
- Zero confirmed reports of essential Kakao services being blocked.
- Consistent update cadence aligned with source changes.
- Filter adoption and positive issue feedback.

## Risks and Mitigations
- Risk: False positives breaking services.
  - Mitigation: Strict allowlist and validation gates.
- Risk: Stale or inactive domains.
  - Mitigation: DNS validation during updates.

## Milestones
1. Document collection and validation process.
2. Publish PRD/TRD and align scripts with documented flow.
3. Validate outputs and update documentation links.
