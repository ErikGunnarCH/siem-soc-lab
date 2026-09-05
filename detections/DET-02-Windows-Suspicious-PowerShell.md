# DET-02 — Windows Suspicious PowerShell

**Status:** Validated, fully investigated and tuned  
**Severity:** High  
**MITRE ATT&CK:** T1059.001 — PowerShell  
**Primary data source:** Sysmon Process Creation (EventCode 1)  
**Schedule:** Every 5 minutes (`*/5 * * * *`)  
**Alert type:** Number of events

## Detection objective

Identify PowerShell or pwsh process creation with command-line patterns commonly associated with obfuscation, download/execution behavior, policy bypass or hidden execution.

## Suspicious behaviors covered

The rule classifies suspicious PowerShell activity including:

- `EncodedCommand` / `-enc`
- `FromBase64String`
- `DownloadString`
- `Invoke-WebRequest`
- `Invoke-Expression` / `IEX`
- `ExecutionPolicy Bypass`
- hidden-window execution

## Correlation context

The rule preserves analyst-relevant process context, including host, user, image, command line, parent image, parent command line and a correlation key based on host, user and suspicious reason.

## Investigation evidence

This detection drove **INC-01 — Suspicious PowerShell EncodedCommand Execution**. Five suspicious executions were identified on `WIN-END-01`, all under `WIN-END-01\secadmin`.

Investigation found:

- 5 executions / 5 unique processes
- 3 distinct Base64 payloads
- all observed suspicious events classified as `Encoded Command`
- decoded payloads contained authorized SIEM-Lab test commands only
- no suspicious child processes were observed
- no evidence of malicious persistence or compromise was found

The case was closed as **Benign Positive / Authorized Security Test**.

## Tuning analysis

Two suppression strategies were compared:

**Rejected:** exclude the user `secadmin` globally.  
This would suppress any future unknown malicious payload executed by that account.

**Selected:** exact-payload allowlist for the 3 Base64 payloads validated during INC-01.  
This suppresses known laboratory activity while preserving unknown `EncodedCommand` payloads and all other suspicious PowerShell behaviors.

A synthetic unknown payload test confirmed the difference: user-based exclusion returned `SUPPRESS`, while exact-payload allowlisting returned `DETECT`.

## Before / after

| Metric | Before | After |
| --- | ---: | ---: |
| Known authorized suspicious executions | 5 | 0 |
| Authorized payloads documented | 3 | 3 allowlisted |
| Global user exclusion | No | No |
| Unknown payload executed by `secadmin` | Detectable | Detectable |
| Other suspicious PowerShell behaviors | Preserved | Preserved |

## Reproducible SPL

See [`../spl/DET-02-Windows-Suspicious-PowerShell.spl`](../spl/DET-02-Windows-Suspicious-PowerShell.spl).

## Analyst follow-up

Decode payloads, reconstruct process lineage, review network activity, identify child processes and correlate with persistence or account activity. See [`../playbooks/PB-01-Windows-Suspicious-PowerShell.md`](../playbooks/PB-01-Windows-Suspicious-PowerShell.md).
