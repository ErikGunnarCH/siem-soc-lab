# PB-03 — Windows Local Account Creation Investigation

**Associated detection:** DET-03 — Windows Local Account Creation  
**MITRE ATT&CK:** T1136.001 — Create Account: Local Account

## Purpose

Provide a repeatable SOC investigation procedure for local Windows account creation. The playbook focuses on identifying who created the account, whether the action was authorized, whether privileges were assigned and whether the account was used for subsequent activity.

## Trigger

Triggered when DET-03 identifies successful creation of a local Windows account.

## Required data

- Windows Security account-management events
- CIM Change data
- Sysmon process telemetry where available
- `host`
- created account
- account creator
- timestamp
- action/status
- `correlation_key`

## Initial triage

1. Identify the affected Windows host.
2. Identify the new local account.
3. Identify the user/process responsible for creation.
4. Review the timestamp.
5. Record the `correlation_key`.
6. Determine whether the account name is expected.
7. Determine whether creation occurred during approved administration, automation or laboratory activity.

## Investigation procedure

### 1. Confirm account creation

Review the DET-03 result and verify that the event represents successful account creation.

```spl
| datamodel Change All_Changes search
| search host="<HOST>" All_Changes.action=created All_Changes.object_category=user
| table _time host All_Changes.user All_Changes.object All_Changes.action All_Changes.status All_Changes.vendor_product
| sort _time
```

### 2. Review Windows account-management telemetry

Where available, review Event ID 4720 and related account-management events.

```spl
index=soc_windows host="<HOST>" EventCode=4720
| table _time host SubjectUserName TargetUserName TargetSid _raw
| sort _time
```

Confirm account name, SID, creator, local/domain context, timestamp and originating management tool/process where available.

### 3. Determine who created the account

Identify whether the creator was an administrator, service account, SYSTEM, expected automation identity or an unexpected/possibly compromised user.

Review the creator's activity around the creation timestamp.

### 4. Review account naming and context

Look for:

- names resembling system accounts;
- administrator-like names;
- service or backup naming;
- random/unusual usernames;
- names resembling legitimate users;
- names associated with approved laboratory testing.

### 5. Search for privilege assignment

Determine whether the new account was added to groups such as:

- Administrators
- Remote Desktop Users
- Remote Management Users
- Backup Operators
- Power Users

Document whether elevated privileges were assigned.

### 6. Search for account usage

```spl
| datamodel Authentication Authentication search
| search Authentication.dest="<HOST>" Authentication.user="<NEW_ACCOUNT>"
| table _time Authentication.user Authentication.src Authentication.dest Authentication.action Authentication.app
| sort _time
```

Look for interactive logon, RDP, SMB, network logon, PowerShell, process creation, scheduled tasks or service creation.

### 7. Review related persistence activity

Search the same host/time window for:

- scheduled-task creation;
- Run/RunOnce registry modification;
- new services;
- startup-folder changes;
- PowerShell execution;
- additional local-account creation;
- local-group changes;
- remote-access configuration changes.

Account creation combined with another persistence mechanism should increase investigation priority.

### 8. Review process activity

Where process telemetry is available, look for account-management commands and tooling:

```spl
index=soc_sysmon host="<HOST>" EventCode=1
(CommandLine="*net user*" OR CommandLine="*New-LocalUser*")
| table _time User Image CommandLine ParentImage ParentCommandLine
| sort _time
```

Also review `net localgroup`, `Add-LocalGroupMember`, `cmd.exe`, `powershell.exe`, `pwsh.exe` and administrative scripts.

## Classification guidance

### True Positive — Unauthorized Account Creation

A local account was created without authorization or as part of malicious activity.

### True Positive — Persistence

The account was created as a persistence mechanism or used for continued access.

### Authorized Security Test

The account was created during an approved security exercise or laboratory simulation.

### Benign Positive

The detection correctly identified account creation, but the activity was legitimate administration or automation.

### False Positive

The detection incorrectly interpreted an event as account creation.

## Severity guidance

Increase severity when:

- the account is added to Administrators;
- the account is subsequently used;
- remote access is observed;
- suspicious PowerShell or command execution accompanies creation;
- additional persistence mechanisms are created;
- the initiating account is unexpected;
- multiple accounts are created;
- creation occurs outside an approved maintenance window.

## Escalation criteria

Escalate when account creation is unauthorized, privileged membership is assigned, the account is used, remote authentication occurs, suspicious process activity accompanies creation, other persistence is observed, or the creator may be compromised.

## Containment decision

Possible actions for unauthorized creation include disabling/removing the account, removing privileged membership, resetting the creator account if compromised, isolating the endpoint when additional malicious activity exists, preserving Windows/Sysmon telemetry and reviewing other hosts for the same account name.

For approved administrative or laboratory activity, containment may not be required.

## Closure requirements

Document:

- affected host;
- created account;
- creator identity;
- timestamp and status;
- privilege-assignment findings;
- account-usage findings;
- process/command responsible for creation;
- related persistence findings;
- final classification;
- containment decision;
- analyst notes.

## Investigation decision logic

A newly created account alone does not prove malicious persistence. Determine:

1. who created the account;
2. whether creation was authorized;
3. whether privileges were assigned;
4. whether the account was used;
5. whether additional persistence or suspicious activity occurred.

## Required evidence

- account-creation event;
- created username;
- creator identity;
- host and timestamp;
- privilege/group changes;
- subsequent authentication;
- process responsible for creation;
- related persistence findings;
- classification and analyst notes.

## Metrics

Track account-creation alerts, authorized/unauthorized creations, privileged-account creations, accounts subsequently used, escalations, false/benign positives and average investigation time.

## Lesson from DET-03 validation

Account creation is a high-value persistence indicator, but administrative and laboratory activity can legitimately trigger the same detection. Creator identity, privilege assignment, subsequent authentication and endpoint activity must be reviewed before determining malicious intent.
