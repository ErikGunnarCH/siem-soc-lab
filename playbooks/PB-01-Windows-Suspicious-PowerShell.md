# PB-01 — Windows Suspicious PowerShell Investigation

**Associated detection:** DET-02 — Windows Suspicious PowerShell  
**MITRE ATT&CK:** T1059.001 — PowerShell

## Purpose

Provide a repeatable SOC investigation procedure for suspicious PowerShell execution detected on Windows endpoints. The playbook is designed to determine whether suspicious syntax represents malicious execution, authorized administration, automation, or security testing.

## Trigger

Triggered when DET-02 generates an alert for suspicious PowerShell behavior such as:

- `EncodedCommand` / `-enc`
- Base64 decoding
- `DownloadString`
- `Invoke-WebRequest`
- `Invoke-Expression` / `IEX`
- `ExecutionPolicy Bypass`
- hidden-window execution

## Required data

- Sysmon EventCode 1
- `host`
- `User`
- `Image`
- `CommandLine`
- `ParentImage`
- `ParentCommandLine`
- `ProcessId` / `ProcessGuid`
- `ParentProcessId` / `ParentProcessGuid`
- `suspicious_reason`
- `correlation_key`

## Initial triage

1. Identify the affected host.
2. Identify the executing user.
3. Review the complete PowerShell command line.
4. Identify the suspicious behavior that triggered the detection.
5. Record the `correlation_key`.
6. Determine the number and timing of executions.
7. Establish whether the activity is expected administrative, automated, laboratory, or unknown activity.

## Investigation procedure

### 1. Review the PowerShell execution

Confirm the timestamp, host, user, executable image, command line, parent process and detection reason.

```spl
index=soc_sysmon host="<HOST>" EventCode=1
(Image="*\\powershell.exe" OR Image="*\\pwsh.exe")
| table _time User Image CommandLine ParentImage ParentCommandLine ProcessId ProcessGuid ParentProcessId ParentProcessGuid
| sort _time
```

### 2. Extract and decode encoded payloads

If `EncodedCommand` or `-enc` is present, extract the Base64 payload and decode it as UTF-16LE / Unicode.

```spl
index=soc_sysmon host="<HOST>" EventCode=1
(Image="*\\powershell.exe" OR Image="*\\pwsh.exe")
(CommandLine="*-EncodedCommand*" OR CommandLine="*-enc *")
| rex field=CommandLine "(?i)(?:-EncodedCommand|-enc)\s+(?<encoded_payload>[A-Za-z0-9+/=]+)"
| table _time User CommandLine encoded_payload
```

Review decoded content for:

- downloads or remote URLs;
- additional payload execution;
- credential access;
- file creation;
- registry modification;
- persistence;
- defense evasion.

### 3. Reconstruct process lineage

Use Sysmon process telemetry to identify the parent process and execution chain.

Review:

- `ProcessId`
- `ProcessGuid`
- `ParentProcessId`
- `ParentProcessGuid`
- `ParentImage`
- `ParentCommandLine`

### 4. Search for child processes

Correlate `ProcessGuid` with `ParentProcessGuid` to determine whether the detected PowerShell instance launched additional processes.

```spl
index=soc_sysmon host="<HOST>" EventCode=1
[
  search index=soc_sysmon host="<HOST>" EventCode=1
  (Image="*\\powershell.exe" OR Image="*\\pwsh.exe")
  | fields ProcessGuid
  | rename ProcessGuid as ParentProcessGuid
]
| table _time User Image CommandLine ParentImage ProcessGuid ParentProcessGuid
| sort _time
```

Pay particular attention to `cmd.exe`, `rundll32.exe`, `regsvr32.exe`, `mshta.exe`, `certutil.exe`, `bitsadmin.exe`, script hosts and additional PowerShell instances.

The absence of child-process execution should also be documented.

### 5. Review related host activity

Search the affected endpoint and time window for:

- scheduled-task creation;
- Run/RunOnce registry modification;
- local-account creation;
- suspicious network communication;
- additional PowerShell execution;
- lateral-movement indicators.

## Classification guidance

### True Positive

Confirmed malicious or unauthorized PowerShell activity.

### Benign Positive

The detection correctly identified suspicious PowerShell behavior, but investigation confirmed legitimate or authorized activity.

### False Positive

The detection logic incorrectly classified normal activity as suspicious.

Do **not** classify an event as a false positive solely because it was benign. If the rule correctly detected suspicious syntax, prefer **Benign Positive / Authorized Activity**.

## Escalation criteria

Escalate when:

- decoded payload performs download or execution;
- suspicious child processes are created;
- persistence is observed;
- external network communication is identified;
- credential access or lateral movement is suspected;
- execution is associated with an unexpected account.

## Containment decision

Containment may be required when malicious payload execution, unauthorized remote activity, persistence, credential compromise or suspicious child execution is confirmed.

Possible actions include endpoint isolation, account disablement, process termination, malicious IP/domain blocking and evidence preservation.

## Closure requirements

Document:

- affected asset;
- executing user;
- complete PowerShell command;
- decoded payload when applicable;
- process lineage;
- child-process findings;
- related activity;
- final classification;
- containment decision;
- analyst notes.

## Required evidence

- alert result or screenshot;
- original Sysmon process event;
- complete `CommandLine`;
- decoded payload when applicable;
- parent/child process lineage;
- related network or persistence findings;
- analyst classification.

## Communication for escalation

Include incident/case ID, host, user, timestamp, detection reason, decoded command, relevant IoCs, analyst assessment and recommended containment.

## Metrics

Track alert count, investigated executions, True Positives, Benign Positives, False Positives, escalations, average investigation time and rule changes generated by investigations.

## Lesson from INC-01

`EncodedCommand` alone does not prove malicious activity. Payload contents, execution context, process lineage and related endpoint activity must be analyzed before determining intent.
