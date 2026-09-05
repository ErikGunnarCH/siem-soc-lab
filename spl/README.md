# SPL

This directory documents reusable Splunk Search Processing Language (SPL) used throughout the SIEM/SOC lab.

Planned contents include:

- detection searches for DET-01 through DET-05
- investigation queries for INC-01 and INC-02
- triage queue and closed-case searches
- SLA calculations
- dashboard searches
- tuning validation queries

## Conventions

Detection SPL should preserve:

- rule ID
- rule name
- severity
- MITRE ATT&CK mapping
- correlation key
- analyst-relevant context fields

## Tuning note

Queries in this repository should reflect the final tuned logic where applicable. Historical baseline queries may be included separately when needed to demonstrate before/after analysis.
