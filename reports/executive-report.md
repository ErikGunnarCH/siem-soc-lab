# Executive Report — Splunk SIEM / SOC Lab

## Project purpose

This laboratory was built to demonstrate practical junior-level SOC / Blue Team capability using Splunk Enterprise. The project covers the complete defensive workflow from telemetry ingestion to detection engineering, alert triage, incident investigation, case closure, dashboards, and detection tuning.

## Environment

- Splunk Enterprise SIEM
- Windows endpoint with Sysmon telemetry
- Linux endpoint with SSH authentication and audit telemetry
- MITRE ATT&CK-aligned detections
- Lookup-backed SOC case workflow

## Security engineering delivered

Five detections were implemented and validated:

1. Linux SSH Brute Force — T1110.001
2. Windows Suspicious PowerShell — T1059.001
3. Windows Local Account Creation — T1136.001
4. Windows Scheduled Task Creation — T1053.005
5. Windows Registry Run Key Persistence — T1547.001

Three dashboards were created for executive visibility, SOC operations, and detection coverage.

## Incident outcomes

### INC-01 — Suspicious PowerShell

Five PowerShell `EncodedCommand` executions were investigated. Three Base64 payloads were decoded and confirmed as authorized SIEM-Lab test commands. No malicious child process or additional compromise evidence was identified.

**Classification:** Benign Positive / Authorized Security Test

### INC-02 — SSH brute force

Thirty failed SSH authentications from a single source against an invalid user were confirmed. The investigation found no successful authentication and no opened SSH session.

**Classification:** True Positive / Authorized Security Test — Unsuccessful SSH Brute Force

## Detection tuning outcomes

### DET-01

A broad text search initially selected 81 events. Three were unrelated `sudo/grep` events. Tuning restricted the rule to real `sshd` failure messages.

- 81 candidate events before
- 78 real SSH failures after filtering
- 3 irrelevant events removed
- 9 of 9 observed detection windows preserved

### DET-02

Five known authorized `EncodedCommand` executions initially generated detections. A broad user exclusion was rejected because it would suppress future unknown payloads. Exact-payload allowlisting was selected instead.

- 5 known benign historical detections suppressed
- 3 exact authorized payloads allowlisted
- unknown payload remained detectable in regression testing

## Measured project status

| Metric | Result |
| --- | ---: |
| Implemented detections | 5 |
| Validated detections | 5 |
| Formally tuned detections | 2 |
| Detailed investigations | 2 |
| Confirmed True Positive investigations | 1 |
| Confirmed Benign Positive investigations | 1 |
| Confirmed False Positives | 0 |
| Dashboards | 3 |
| Playbooks | 3 |

## Operational value demonstrated

The project demonstrates hands-on ability in:

- Splunk SPL and detection engineering;
- Windows Sysmon and Linux authentication analysis;
- MITRE ATT&CK mapping;
- alert triage and case ownership;
- process-tree and PowerShell payload analysis;
- SSH brute-force investigation;
- detection tuning with missed-event risk analysis;
- dashboarding and operational health monitoring;
- incident and playbook documentation.

## Key lesson

The lab intentionally avoided tuning by simply suppressing more alerts. Changes were accepted only when testing showed that known noise was reduced while observed malicious-behavior coverage was preserved.

## Scope note

All metrics are from an isolated authorized laboratory and should not be interpreted as enterprise production-performance claims.
