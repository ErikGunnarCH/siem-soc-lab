# Test Register

This register records the controlled validation activities performed in the SIEM/SOC lab. It distinguishes what was simulated, what was detected, what was investigated, and what was formally tuned.

## Test summary

| Test ID | Detection / Area | Test purpose | Result | Evidence / outcome |
| --- | --- | --- | --- | --- |
| TST-01 | DET-01 | Validate repeated SSH failure detection | Passed | Brute-force windows detected and case created |
| TST-02 | DET-02 | Validate suspicious PowerShell `EncodedCommand` detection | Passed | 5 executions detected across 5 processes |
| TST-03 | DET-03 | Validate Windows local account creation detection | Passed | Detection technically validated |
| TST-04 | DET-04 | Validate scheduled-task creation detection | Passed | Detection technically validated |
| TST-05 | DET-05 | Validate Registry Run/RunOnce persistence detection | Passed | Detection technically validated |
| TST-06 | INC-01 | Decode and assess PowerShell payloads | Passed | 3 distinct payloads decoded as authorized lab commands |
| TST-07 | INC-01 | Reconstruct PowerShell parent/child process context | Passed | Parent PowerShell observed; no suspicious child processes found |
| TST-08 | INC-02 | Reconstruct SSH authentication activity | Passed | 30 failed authentications confirmed |
| TST-09 | INC-02 | Check for successful SSH authentication | Passed | 0 successful authentications found |
| TST-10 | INC-02 | Check for SSH session-open events | Passed | 0 sessions opened |
| TST-11 | DET-01 tuning | Identify extraction/noise problem | Passed | 81 candidates -> 78 real SSH failures; 3 sudo/grep noise events identified |
| TST-12 | DET-01 tuning | Compare thresholds `>=5`, `>=6`, `>=8` | Passed | `>=5` preserved 9 windows; higher thresholds introduced missed-event risk |
| TST-13 | DET-01 tuning | Validate final sshd-only filter | Passed | 78/78 real SSH failures extracted; 9/9 windows preserved |
| TST-14 | DET-02 tuning | Compare user exclusion vs exact payload allowlist | Passed | User exclusion shown to be overly broad |
| TST-15 | DET-02 tuning | Regression test unknown payload | Passed | Unknown payload remained `DETECT` under exact-payload allowlist logic |
| TST-16 | Dashboard health | Validate endpoint log-health logic | Passed | Historical last-seen timestamps surfaced; stale hosts correctly identified |

## Detection validation details

### DET-01 — Linux SSH Brute Force

Validation confirmed repeated SSH failure activity grouped by source IP and target user within 5-minute windows. The rule generated analyst-relevant correlation context and supported the INC-02 investigation.

### DET-02 — Windows Suspicious PowerShell

Validation confirmed 5 suspicious PowerShell `EncodedCommand` executions on `WIN-END-01`, all under `WIN-END-01\secadmin`. The investigation later determined the activity was authorized laboratory testing.

### DET-03 — Windows Local Account Creation

The CIM Change-based detection was technically validated for account object creation on `WIN-END-01`. This rule did not undergo a full incident investigation or formal before/after tuning cycle.

### DET-04 — Windows Scheduled Task Creation

The Sysmon process-based rule was validated against `schtasks /Create` and PowerShell scheduled-task creation patterns. The rule was scheduled and alert-enabled but did not undergo formal tuning.

### DET-05 — Windows Registry Run Key Persistence

The CIM Change-based rule was validated for `Run` / `RunOnce` persistence path modifications. The rule was scheduled and alert-enabled but did not undergo formal tuning.

## Investigation test details

### INC-01

Investigation activities verified:

- 5 suspicious PowerShell executions;
- 3 distinct Base64 payloads;
- successful Base64 decoding;
- authorized SIEM-Lab command content;
- PowerShell parent-process context;
- no suspicious child processes observed.

Final classification: **Benign Positive / Authorized Security Test**.

### INC-02

Investigation activities verified:

- 30 failed SSH authentications from `172.31.255.1`;
- repeated activity against `invaliduser`;
- related `Invalid user` / PAM failure context;
- no accepted authentication;
- no SSH session opened.

Final classification: **True Positive / Authorized Security Test — Unsuccessful SSH Brute Force**.

## Tuning test details

### DET-01 before / after

- Before: 81 text-matched candidate events.
- Noise identified: 3 `sudo/grep` events that contained the target phrase but were not authentication failures.
- After: 78 real SSH failure events.
- Extraction quality after filtering: 78/78.
- Detection windows before: 9.
- Detection windows after: 9.
- Threshold retained at `>=5` because higher thresholds removed observed windows.

### DET-02 before / after

- Before: 5 known authorized `EncodedCommand` detections.
- Candidate suppression A: exclude `secadmin` globally.
- Candidate suppression B: allowlist only exact known payloads.
- Regression result: broad user exclusion would suppress an unknown payload; exact payload allowlisting continued to detect it.
- After: 5 known benign historical detections suppressed while unknown payload behavior remained detectable.

## Test-status interpretation

`Passed` means the expected lab behavior was directly observed in the evidence collected during this project. It does not imply enterprise-scale validation, red-team coverage, or production readiness.

## Current validation state

- Implemented detections: 5
- Validated detections: 5
- Fully investigated detections: 2
- Formally tuned detections: 2
- Confirmed True Positive investigations: 1
- Confirmed Benign Positive investigations: 1
- Confirmed False Positives: 0

## Related evidence

- Detection documentation: [`../detections/`](../detections/)
- Final SPL: [`../spl/`](../spl/)
- Incident reports: [`../incidents/`](../incidents/)
- Tuning evidence: [`tuning-register.md`](tuning-register.md)
- Screenshots: [`../screenshots/`](../screenshots/)
