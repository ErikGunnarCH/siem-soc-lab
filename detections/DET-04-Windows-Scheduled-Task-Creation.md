# DET-04 — Windows Scheduled Task Creation

**Status:** Validated  
**Severity:** High  
**MITRE ATT&CK:** T1053.005 — Scheduled Task/Job: Scheduled Task  
**Primary data source:** Sysmon Process Creation (EventCode 1)  
**Schedule:** Every 5 minutes (`*/5 * * * *`)  
**Alert type:** Number of events

## Detection objective

Identify creation of Windows scheduled tasks through either `schtasks.exe /Create` or PowerShell scheduled-task cmdlets.

## Detection logic

The saved search monitors Sysmon EventCode 1 on `WIN-END-01` and detects either:

- `schtasks.exe` with `/Create`, or
- PowerShell / pwsh using `Register-ScheduledTask` or `New-ScheduledTask`.

The query normalizes the detection method, extracts the task name where possible, and builds a correlation key from `host|task_name`.

## Why this matters

Scheduled tasks are frequently used for legitimate administration, but they are also a common persistence and execution mechanism. A high-severity alert is appropriate in this lab because creation of a new task is an actionable endpoint change with strong investigation value.

## Analyst context preserved

The rule returns:

- host and user
- process image
- command line
- parent image and parent command line
- extracted task name
- detection method
- correlation key
- MITRE and severity metadata

## Validation status

The rule was technically validated in the lab. Formal tuning review has not yet been performed, so its catalog status remains **Validated / Not yet reviewed**.

## Reproducible SPL

See [`../spl/DET-04-Windows-Scheduled-Task-Creation.spl`](../spl/DET-04-Windows-Scheduled-Task-Creation.spl).

## Analyst follow-up

Review task name, task action, execution context, creator account, parent process, command line and whether the task is consistent with approved administration or software deployment.
