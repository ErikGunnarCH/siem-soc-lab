# INC-02 — Unsuccessful SSH Brute Force Against Linux Host

**Detection:** DET-01 — Linux SSH Brute Force — Repeated Failed Passwords  
**Severity:** Medium / P3  
**Status:** Closed  
**Analyst:** `socadmin`  
**Asset:** `LNX-END-01`  
**Source IP:** `172.31.255.1`  
**Target user:** `invaliduser`  
**MITRE ATT&CK:** T1110.001 — Password Guessing

## Initial hypothesis

Repeated SSH authentication failures from the same source IP may indicate password guessing or brute-force activity against the Linux endpoint. The investigation must determine whether authentication eventually succeeded, whether an SSH session opened and whether subsequent suspicious activity occurred.

## Summary

Thirty failed SSH authentication attempts from `172.31.255.1` targeted the invalid user `invaliduser` on `LNX-END-01`. The activity was detected by DET-01 and generated repeated failed-authentication windows.

## Investigation

The investigation established the following:

- 30 failed-password events associated with `172.31.255.1` and `invaliduser` were identified.
- 20 `Invalid user` events were observed across 20 related SSH processes/sessions.
- Authentication activity was reviewed across the investigation time window.
- No `Accepted password` events associated with the source IP were identified.
- No `Accepted publickey` events associated with the source IP were identified.
- No successful SSH authentication was observed.
- No SSH session was opened as a result of the investigated activity.
- No evidence of unauthorized access or host compromise was identified.

## Evidence summary

| Artifact | Observation |
|---|---|
| Host | `LNX-END-01` |
| Source IP | `172.31.255.1` |
| Target user | `invaliduser` |
| Protocol | SSH |
| Failed authentication attempts | 30 |
| Invalid-user events | 20 |
| Successful authentication events | 0 |
| Opened SSH sessions | 0 |

## Final classification

**True Positive / Authorized Security Test — Unsuccessful SSH Brute Force**

The detection correctly identified brute-force/password-guessing behavior. The activity was authorized laboratory testing and did not result in successful access.

## Impact

No confirmed security impact. The authentication attempts were unsuccessful and no evidence of unauthorized access or host compromise was identified.

## Containment

No containment was required for the laboratory scenario because the activity was authorized and unsuccessful.

In a production environment, response options could include temporary blocking of the offending source IP and review of the targeted account and host.

## Eradication

Not required. No persistence, unauthorized account, malware or compromised session was identified.

## Recovery

Not required. The target Linux host remained operational and no evidence of compromise was discovered.

## Detection engineering outcome

The investigation and later tuning review directly improved DET-01:

- 3 non-sshd `sudo/grep` noise events containing the text `Failed password for` were removed from scope;
- 78 real SSH failure events were retained;
- all 9 observed detection windows were preserved;
- the threshold of `>=5` failures in 5 minutes was retained because increasing it would reduce observed coverage, including INC-02 windows.

## Lessons learned

Repeated authentication failures should not be evaluated only by count. Investigation must determine whether authentication succeeded, whether an SSH session opened and whether post-authentication activity occurred.

## Closure reason

Authorized laboratory brute-force simulation confirmed through Linux authentication telemetry. Thirty failed authentication attempts and twenty invalid-user events were observed, with no successful authentication or SSH session creation.
