# DET-03 — Windows Local Account Creation

**Status:** Validated  
**Severity:** Medium  
**MITRE ATT&CK:** T1136.001 — Local Account  
**Primary data source:** CIM Change / Windows account-change telemetry  
**Schedule:** Every 5 minutes (`*/5 * * * *`)  
**Alert type:** Number of events

## Detection objective

Identify creation of local Windows user accounts on `WIN-END-01` using normalized CIM Change data.

## Detection logic

The saved search uses the `Change` data model and filters for:

- `host=WIN-END-01`
- `All_Changes.action=created`
- `All_Changes.object_category=user`

The rule then adds normalized detection metadata and builds a correlation key from `host` and `All_Changes.object`.

## Why this matters

Unexpected local-account creation can support persistence, privilege abuse or preparation for lateral movement. Even when the event is legitimate, it is a high-value change for SOC review because it modifies the host's authentication surface.

## Analyst context preserved

The rule returns fields including:

- host
- initiating user
- changed object
- object path
- action and status
- vendor/product context
- correlation key
- rule metadata

## Validation status

The rule was technically validated in the lab and is present in the detection catalog. It has not yet undergone formal tuning review, so the repository deliberately labels it as **Validated / Not yet reviewed** rather than implying tuning work that was not performed.

## Reproducible SPL

See [`../spl/DET-03-Windows-Local-Account-Creation.spl`](../spl/DET-03-Windows-Local-Account-Creation.spl).

## Analyst follow-up

Validate whether the account creation was approved, identify the creator, review group membership and privileges, determine whether the new account was used, and correlate with scheduled tasks, services, Run/RunOnce persistence or remote logon activity. See [`../playbooks/PB-03-Windows-Local-Account-Creation.md`](../playbooks/PB-03-Windows-Local-Account-Creation.md).
