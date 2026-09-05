# SIEM SOC Lab

A hands-on SIEM and SOC engineering laboratory built with Splunk Enterprise, Sysmon, Windows, and Linux telemetry. The project covers log onboarding, detection engineering, alerting, SOC triage, incident investigation, playbooks, dashboards, and evidence-based detection tuning.

## Project status

- 5 implemented and validated detections
- 5 mapped MITRE ATT&CK techniques
- 3 SOC dashboards
- 3 operational investigation playbooks
- 2 fully documented incident investigations
- 2 detections tuned with measured before/after evidence

## Environment

| Component | Role |
| --- | --- |
| Splunk Enterprise | SIEM, search, alerting, dashboards, triage workflow |
| Windows endpoint | Sysmon process, registry, and network telemetry |
| Linux endpoint | SSH authentication and audit telemetry |
| `soc_sysmon` | Windows/Sysmon index |
| `soc_linux` | Linux security/audit index |

## Detection catalog

| ID | Detection | Severity | MITRE ATT&CK | Status |
| --- | --- | --- | --- | --- |
| DET-01 | Linux SSH Brute Force | Medium | T1110.001 Password Guessing | Validated + Tuned |
| DET-02 | Windows Suspicious PowerShell | High | T1059.001 PowerShell | Validated + Tuned |
| DET-03 | Windows Local Account Creation | Medium | T1136.001 Local Account | Validated |
| DET-04 | Windows Scheduled Task Creation | High | T1053.005 Scheduled Task | Validated |
| DET-05 | Windows Registry Run Key Persistence | High | T1547.001 Registry Run Keys / Startup Folder | Validated |

## SOC workflow

The lab implements an end-to-end workflow:

`Telemetry -> Detection -> Alert -> Triage Queue -> Investigation -> Classification -> Closure -> Tuning`

Cases are tracked through a Splunk lookup-backed triage workflow with case ID, rule ID, correlation key, status, owner, analyst notes, creation time, and last update.

## Investigation highlights

### INC-01 — Suspicious PowerShell
Five PowerShell `EncodedCommand` executions were investigated. The Base64 payloads decoded to authorized SIEM-lab test commands. No suspicious child processes, malicious persistence, or unauthorized activity were identified. Final classification: **Benign Positive / Authorized Security Test**.

### INC-02 — SSH Brute Force
Thirty failed SSH authentication attempts against an invalid user were investigated. No successful authentication or SSH session was observed. Final classification: **True Positive / Authorized Security Test — Unsuccessful SSH Brute Force**.

## Detection tuning highlights

### DET-01
A broad string match selected 81 events, including 3 unrelated `sudo/grep` events that merely contained `Failed password for`. The tuned rule restricts matching to real `sshd` / `sshd-session` failure messages.

- Before: 81 selected events
- After: 78 real SSH failures
- Noise removed: 3 events
- Detection windows preserved: 9 of 9
- Threshold retained: `>=5` failures in 5 minutes

### DET-02
All five historical detections were authorized lab `EncodedCommand` executions. A user-wide exclusion was rejected because it would also hide unknown payloads executed by the same analyst account. The tuned rule uses an exact-payload allowlist for the 3 validated lab payloads.

- Before: 5 known benign historical detections
- After: 0 of those known authorized executions alert
- Unknown `EncodedCommand` payloads remain detectable
- Other suspicious PowerShell behaviors remain detectable

## Dashboards

- `SOC - Executive Overview`
- `SOC - Triage Operations`
- `SOC - Detection Coverage`

## Repository map

- `docs/` — project overview and methodology
- `architecture/` — logical architecture and telemetry flow
- `detections/` — detection catalog and rule documentation
- `spl/` — SPL queries and detection logic
- `dashboards/` — dashboard documentation
- `playbooks/` — SOC investigation playbooks
- `incidents/` — completed incident reports
- `reports/` — tuning and assessment records
- `mitre/` — ATT&CK mapping and coverage
- `configuration/` — sanitized configuration notes
- `screenshots/` — sanitized evidence and dashboard images
- `lessons-learned/` — engineering and SOC lessons learned

## Security and sanitization

This repository is intended to contain only lab-safe, sanitized material. Passwords, API keys, session cookies, authentication tokens, SSH private keys, and other secrets must never be committed. See `SECURITY.md`.

## Scope note

This is a controlled laboratory project designed to demonstrate SIEM/SOC engineering methodology. Metrics and tuning conclusions are based on the observed lab dataset and should not be generalized to production environments without additional validation.
