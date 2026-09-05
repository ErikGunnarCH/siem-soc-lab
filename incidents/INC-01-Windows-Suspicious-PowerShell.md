# INC-01 — Suspicious PowerShell EncodedCommand Execution

**Detection:** DET-02 — Windows Suspicious PowerShell  
**Severity:** High / P2  
**Status:** Closed  
**Analyst:** `socadmin`  
**Asset:** `WIN-END-01`  
**User:** `WIN-END-01\secadmin`  
**MITRE ATT&CK:** T1059.001 — PowerShell

## Initial hypothesis

Suspicious PowerShell execution using `EncodedCommand` may indicate obfuscated command execution, malware execution, defense evasion or post-exploitation activity.

## Summary

Five PowerShell `EncodedCommand` executions were identified on `WIN-END-01` under account `WIN-END-01\secadmin`.

## Investigation

The investigation established the following:

- 5 suspicious PowerShell executions were observed.
- 3 distinct Base64 payloads were extracted from the command line.
- The payloads were decoded as UTF-16LE / Unicode.
- Decoded content consisted only of authorized SIEM-Lab test commands.
- Sysmon EventCode 1 telemetry was used to reconstruct parent/child process relationships.
- PowerShell was identified as the parent process.
- No suspicious child-process execution was observed.
- No evidence of malicious persistence, unauthorized payload execution, lateral movement or other compromise indicators was identified.

### Decoded test commands

The observed encoded payloads decoded to laboratory-only commands equivalent to:

- `Write-Output 'SIEM-LAB-DET02'`
- `Write-Host "SIEM-Lab DET-02 Test"`
- `Write-Host "SIEM-Lab DET-02 Alert Test"`

## Evidence summary

| Artifact | Observation |
|---|---|
| Host | `WIN-END-01` |
| User | `WIN-END-01\secadmin` |
| Process | `powershell.exe` |
| Behavior | `EncodedCommand` |
| Executions | 5 |
| Distinct payloads | 3 |
| Suspicious child processes | 0 observed |
| Confirmed malicious persistence | None observed |

## Final classification

**Benign Positive / Authorized Security Test**

The detection was technically correct: suspicious PowerShell syntax was present. The incident was benign because the decoded commands and execution context were confirmed as authorized laboratory testing.

## Impact

No security impact identified.

## Containment

Not required.

## Eradication

Not required.

## Recovery

Not required.

## Detection engineering outcome

The investigation directly informed tuning of DET-02:

- a global exclusion for `secadmin` was rejected because it could hide future unknown malicious payloads;
- an exact-payload allowlist was selected for the 3 known authorized Base64 payloads;
- all 5 known benign executions were suppressed after tuning;
- a synthetic unknown payload remained detectable, demonstrating that coverage was preserved.

## Lessons learned

`EncodedCommand` alone is not sufficient to determine malicious intent. The payload, user context, process lineage, child processes and surrounding endpoint activity must be analyzed before classification.

## Closure reason

Authorized laboratory activity was validated through Sysmon telemetry, Base64 payload analysis and process-lineage review.
