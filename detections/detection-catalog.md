# Detection Catalog

| Rule ID | Detection | Severity | MITRE ATT&CK | Primary data source | Validation | Tuning |
| --- | --- | --- | --- | --- | --- | --- |
| DET-01 | Linux SSH Brute Force | Medium | T1110.001 — Password Guessing | Linux SSH authentication logs | Validated | Tuned |
| DET-02 | Windows Suspicious PowerShell | High | T1059.001 — PowerShell | Sysmon Process Creation | Validated | Tuned |
| DET-03 | Windows Local Account Creation | Medium | T1136.001 — Local Account | Windows Account Change / CIM Change | Validated | Not yet reviewed |
| DET-04 | Windows Scheduled Task Creation | High | T1053.005 — Scheduled Task | Sysmon Process Creation | Validated | Not yet reviewed |
| DET-05 | Windows Registry Run Key Persistence | High | T1547.001 — Registry Run Keys / Startup Folder | Registry Change / CIM Change | Validated | Not yet reviewed |

## DET-01 — Linux SSH Brute Force

Detects repeated failed SSH password attempts from the same source IP against the same target user within a 5-minute window. Current threshold: `>=5` failures. The tuned rule restricts candidate events to real `sshd` / `sshd-session` failure messages so administrative commands that merely contain the text `Failed password for` do not enter correlation.

Correlation context: `host + src_ip + target_user`.

## DET-02 — Windows Suspicious PowerShell

Detects suspicious PowerShell / pwsh process creation patterns such as EncodedCommand, Base64 decoding, DownloadString, Invoke-WebRequest, Invoke-Expression, ExecutionPolicy Bypass, and hidden-window execution. The tuned rule uses an exact-payload allowlist for three validated SIEM-lab EncodedCommand payloads and deliberately does not exclude the analyst account globally.

MITRE: T1059.001.

## DET-03 — Windows Local Account Creation

Detects creation of local Windows user accounts through CIM Change data. Investigation context includes creator identity, privilege assignment, later account use, and related persistence behavior.

MITRE: T1136.001.

## DET-04 — Windows Scheduled Task Creation

Detects scheduled-task creation behavior through Sysmon process creation telemetry, including `schtasks /Create` and PowerShell scheduled-task cmdlets.

MITRE: T1053.005.

## DET-05 — Windows Registry Run Key Persistence

Detects changes to Windows Run / RunOnce persistence locations through registry change telemetry normalized with CIM Change.

MITRE: T1547.001.

## Validation status

All five rules were technically validated in the lab. DET-01 and DET-02 were investigated end-to-end and then tuned using measured before/after evidence. DET-03 through DET-05 remain validated but have not yet undergone formal tuning review.
