# DET-01 — Linux SSH Brute Force

**Status:** Validated, fully investigated and tuned  
**Severity:** Medium  
**MITRE ATT&CK:** T1110.001 — Password Guessing  
**Primary data source:** Linux SSH authentication logs (`linux_secure`)  
**Schedule:** Every 5 minutes (`*/5 * * * *`)  
**Alert type:** Number of events

## Detection objective

Identify repeated failed SSH password attempts from the same source IP against the same target account within a 5-minute correlation window.

## Detection logic

The rule:

1. Searches `linux_secure` events containing `Failed password for`.
2. Restricts candidates to real `sshd` / `sshd-session` failure messages.
3. Extracts `target_user`, `src_ip` and `src_port` from the raw event.
4. Groups activity into 5-minute windows by `host + src_ip + target_user`.
5. Triggers when the window contains at least 5 failures.
6. Builds a correlation key from `host|src_ip|target_user`.

## Why this matters

Repeated authentication failures can indicate password guessing or brute-force activity. Correlating by source and target account reduces noise while preserving the context an analyst needs for triage.

## Validation evidence

The baseline dataset contained 81 text-matched events. Investigation showed that 3 were administrative `sudo grep` commands that merely contained the string `Failed password for`; 78 were real SSH authentication failures.

The tuned filter removed those 3 irrelevant events while preserving all 78 real failures and all 9 observed detection windows. The threshold remained `>=5` because testing showed that increasing it to 6 would lose one observed window and increasing it to 8 would miss every window associated with INC-02.

## Investigation linkage

This detection drove **INC-02 — Linux SSH Brute Force**. The investigated incident contained 30 failed authentications from `172.31.255.1` against `invaliduser`, with no successful authentication and no SSH session opened.

## Tuning decision

- Keep threshold at `>=5` failures.
- Keep 5-minute window.
- Keep correlation on `host + src_ip + target_user`.
- Filter non-`sshd` events before correlation.
- Retain the existing correlation-key throttle.

## Reproducible SPL

See [`../spl/DET-01-Linux-SSH-Brute-Force.spl`](../spl/DET-01-Linux-SSH-Brute-Force.spl).

## Analyst follow-up

During triage, validate source IP, target account, failure cadence, any successful authentication, session-open events and follow-on activity. See [`../playbooks/PB-02-Linux-SSH-Brute-Force.md`](../playbooks/PB-02-Linux-SSH-Brute-Force.md).
