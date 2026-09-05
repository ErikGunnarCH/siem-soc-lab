# Project Overview

## Objective

Build a reproducible SIEM/SOC laboratory that demonstrates the complete defensive workflow from telemetry ingestion through detection engineering, triage, investigation, case closure, dashboards, and tuning.

## Core platform

- Splunk Enterprise as the SIEM platform
- Sysmon telemetry from a Windows endpoint
- Linux authentication and audit telemetry
- MITRE ATT&CK-aligned detection engineering
- lookup-backed SOC case workflow

## Implemented detections

1. DET-01 — Linux SSH Brute Force
2. DET-02 — Windows Suspicious PowerShell
3. DET-03 — Windows Local Account Creation
4. DET-04 — Windows Scheduled Task Creation
5. DET-05 — Windows Registry Run Key Persistence

All five detections were validated in the laboratory. DET-01 and DET-02 subsequently underwent formal before/after tuning.

## SOC case workflow

The triage process uses a case state lookup with the following fields:

`case_id, rule_id, correlation_key, triage_status, triage_owner, triage_notes, created_at, last_update`

Operational states include New, Investigating, and Closed. Active cases are excluded from the queue after closure and remain available in closed-case history.

## Incident investigations

### INC-01
DET-02 generated a high-priority suspicious PowerShell case. Five EncodedCommand executions were reviewed, their Base64 payloads decoded, parent/child lineage reconstructed, and related endpoint activity checked. The commands were authorized SIEM-lab tests. Classification: Benign Positive / Authorized Security Test.

### INC-02
DET-01 generated an SSH brute-force case. Thirty failed authentication events from a single source against an invalid account were confirmed. No accepted authentication or opened SSH session was observed. Classification: True Positive / Authorized Security Test — Unsuccessful SSH Brute Force.

## Dashboards

Three dashboards provide different operational views:

- Executive overview: case volume, priority, assets, MITRE coverage, trend, status, closure time
- SOC operations: queue, SLA, analyst workload, authentication failures, suspicious processes, log health, event volume, Splunk WARN/ERROR activity
- Detection coverage: detection catalog, ATT&CK coverage, data-source readiness, validation status, investigation depth, tuning status

## Tuning methodology

Tuning decisions were based on measured lab evidence rather than arbitrary suppression.

DET-01 retained its `>=5` failures / 5-minute threshold because increasing the threshold would remove observed detection windows. The improvement instead removed unrelated non-sshd events from the candidate event set.

DET-02 retained EncodedCommand as suspicious behavior. A broad user exclusion was rejected because it would hide unknown payloads. The approved tuning uses exact-payload allowlisting for three known authorized lab payloads.

## Portfolio principles

- preserve evidence and reproducibility
- distinguish True Positive, Benign Positive, and False Positive
- do not claim generalized production effectiveness from lab-only metrics
- document tuning risk, not just noise reduction
- keep secrets and sensitive authentication material out of version control
