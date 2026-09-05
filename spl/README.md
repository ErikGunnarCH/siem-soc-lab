# SPL Library

This directory contains the final, reproducible Splunk Search Processing Language (SPL) used for the lab's detection rules.

## Detection searches

| Rule | SPL | Status |
| --- | --- | --- |
| DET-01 — Linux SSH Brute Force | [`DET-01-Linux-SSH-Brute-Force.spl`](DET-01-Linux-SSH-Brute-Force.spl) | Validated + Tuned |
| DET-02 — Windows Suspicious PowerShell | [`DET-02-Windows-Suspicious-PowerShell.spl`](DET-02-Windows-Suspicious-PowerShell.spl) | Validated + Tuned |
| DET-03 — Windows Local Account Creation | [`DET-03-Windows-Local-Account-Creation.spl`](DET-03-Windows-Local-Account-Creation.spl) | Validated |
| DET-04 — Windows Scheduled Task Creation | [`DET-04-Windows-Scheduled-Task-Creation.spl`](DET-04-Windows-Scheduled-Task-Creation.spl) | Validated |
| DET-05 — Windows Registry Run Key Persistence | [`DET-05-Windows-Registry-Run-Key-Persistence.spl`](DET-05-Windows-Registry-Run-Key-Persistence.spl) | Validated |

## Design conventions

The detection SPL preserves the metadata and context needed for SOC workflows:

- rule ID and human-readable rule name
- severity
- MITRE ATT&CK mapping
- correlation key
- analyst-relevant host, user and process/change context
- deterministic fields suitable for throttling and triage

## Tuning philosophy

The repository reflects **final tuned logic where tuning was actually performed**.

- DET-01 uses an `sshd` / `sshd-session` filter to prevent unrelated administrative commands containing `Failed password for` from entering correlation.
- DET-02 uses an exact-payload allowlist for three authorized EncodedCommand payloads. It deliberately does not exclude the `secadmin` user globally.

The project avoids claiming that DET-03 through DET-05 are tuned because those rules were validated but did not receive the same measured before/after tuning exercise.

## Additional SPL used in the project

Beyond the five files in this folder, the lab also used SPL for:

- SOC triage queue and closed-case reporting
- SLA calculations
- incident investigation and process-tree reconstruction
- SSH authentication timeline reconstruction
- dashboard panels and telemetry-health checks
- tuning baselines and regression testing

Those searches are documented in the surrounding project documentation where they provide investigation or operational context.
