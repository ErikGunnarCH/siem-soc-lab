# DET-05 — Windows Registry Run Key Persistence

**Status:** Validated  
**Severity:** High  
**MITRE ATT&CK:** T1547.001 — Registry Run Keys / Startup Folder  
**Primary data source:** CIM Change / registry change telemetry  
**Schedule:** Every 5 minutes (`*/5 * * * *`)  
**Alert type:** Number of events

## Detection objective

Identify creation or modification of Windows Run / RunOnce registry persistence locations on `WIN-END-01`.

## Detection logic

The saved search uses the `Change` data model and filters for:

- `All_Changes.object_category=registry`
- action equal to `created` or `modified`
- object paths matching Windows `CurrentVersion\Run` or `CurrentVersion\RunOnce`

The correlation key combines `host` and the affected registry object path.

## Why this matters

Run and RunOnce keys are well-known persistence locations. Monitoring changes to these paths provides high-value endpoint visibility into startup persistence mechanisms that may otherwise blend into routine registry activity.

## Analyst context preserved

The rule returns:

- host
- initiating user
- action and change type
- registry object path
- object attributes and status
- vendor/product context
- correlation key
- severity and MITRE metadata

## Validation status

The rule was technically validated in the lab. It has not yet undergone formal tuning review, so its status remains **Validated / Not yet reviewed**.

## Reproducible SPL

See [`../spl/DET-05-Windows-Registry-Run-Key-Persistence.spl`](../spl/DET-05-Windows-Registry-Run-Key-Persistence.spl).

## Analyst follow-up

Review the affected value, referenced executable or script, initiating user, timing, process ancestry and whether the change corresponds to approved software installation or administration.
