# Detection Catalog

This catalog summarizes the five detections implemented and validated in the lab. Each rule has a dedicated engineering note and a reproducible SPL file so the repository demonstrates both analyst workflow and hands-on detection development.

| Rule ID | Detection | Severity | MITRE ATT&CK | Primary data source | Validation | Tuning |
| --- | --- | --- | --- | --- | --- | --- |
| [DET-01](DET-01-Linux-SSH-Brute-Force.md) | Linux SSH Brute Force | Medium | T1110.001 — Password Guessing | Linux SSH authentication logs | Validated | **Tuned** |
| [DET-02](DET-02-Windows-Suspicious-PowerShell.md) | Windows Suspicious PowerShell | High | T1059.001 — PowerShell | Sysmon Process Creation | Validated | **Tuned** |
| [DET-03](DET-03-Windows-Local-Account-Creation.md) | Windows Local Account Creation | Medium | T1136.001 — Local Account | Windows Account Change / CIM Change | Validated | Not yet reviewed |
| [DET-04](DET-04-Windows-Scheduled-Task-Creation.md) | Windows Scheduled Task Creation | High | T1053.005 — Scheduled Task | Sysmon Process Creation | Validated | Not yet reviewed |
| [DET-05](DET-05-Windows-Registry-Run-Key-Persistence.md) | Windows Registry Run Key Persistence | High | T1547.001 — Registry Run Keys / Startup Folder | Registry Change / CIM Change | Validated | Not yet reviewed |

## Engineering maturity

### Fully investigated and tuned

**DET-01** and **DET-02** were taken through the full SOC lifecycle: detection, alerting, case creation, investigation, classification, closure, tuning hypothesis, controlled before/after validation and final saved-search update.

- DET-01 tuning removed 3 non-SSH `sudo/grep` events while preserving 78 real SSH failures and all 9 observed `>=5` correlation windows.
- DET-02 tuning suppressed 5 known authorized EncodedCommand executions using an exact-payload allowlist while preserving detection of an unknown payload in regression testing.

### Validated detections awaiting formal tuning review

DET-03 through DET-05 were technically validated and scheduled in Splunk, but the project deliberately does **not** label them as tuned because no formal before/after tuning exercise was performed for those rules.

## Saved-search schedule

All five detection searches are scheduled every 5 minutes in the lab (`*/5 * * * *`). Correlation keys and throttling are used to reduce duplicate alerting while preserving analyst context.

## Reproducible SPL

The final search logic is stored under [`../spl/`](../spl/):

- [`DET-01-Linux-SSH-Brute-Force.spl`](../spl/DET-01-Linux-SSH-Brute-Force.spl)
- [`DET-02-Windows-Suspicious-PowerShell.spl`](../spl/DET-02-Windows-Suspicious-PowerShell.spl)
- [`DET-03-Windows-Local-Account-Creation.spl`](../spl/DET-03-Windows-Local-Account-Creation.spl)
- [`DET-04-Windows-Scheduled-Task-Creation.spl`](../spl/DET-04-Windows-Scheduled-Task-Creation.spl)
- [`DET-05-Windows-Registry-Run-Key-Persistence.spl`](../spl/DET-05-Windows-Registry-Run-Key-Persistence.spl)

## What this demonstrates

This detection set is designed to show practical junior SOC / detection-engineering capability across:

- Windows and Linux telemetry
- Sysmon process analysis
- CIM / data-model searches
- MITRE ATT&CK mapping
- field extraction and correlation keys
- scheduled alerting and throttling
- investigation-driven tuning
- reproducible SPL documentation
