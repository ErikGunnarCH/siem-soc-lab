# Configuration Notes

This directory is reserved for sanitized configuration documentation required to reproduce the lab.

## Known data sources

### Windows

- Splunk index: `soc_sysmon`
- Sysmon process creation telemetry
- Sysmon network connection telemetry
- registry-related telemetry used with CIM Change where available

### Linux

- Splunk index: `soc_linux`
- `linux_secure` SSH authentication telemetry
- `auditd` telemetry

## Alert scheduling

The implemented detection searches are scheduled on a recurring cadence and use correlation-key throttling to reduce duplicate alerting. Exact saved-search exports may be added later after sanitization.

## Case state

SOC triage state is stored in a lookup containing:

`case_id, rule_id, correlation_key, triage_status, triage_owner, triage_notes, created_at, last_update`

## Sanitization rules

Do not commit:

- passwords
- Splunk authentication tokens
- cookies
- SSH private keys
- API credentials
- session secrets

Configuration examples should replace secrets with placeholders.

## Reproducibility note

This document intentionally records logical configuration and data-flow requirements first. Exact installation paths, platform versions, and deployment-specific settings should be added only when verified from the lab and sanitized for publication.
