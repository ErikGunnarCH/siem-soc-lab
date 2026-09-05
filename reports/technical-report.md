# Technical Report — Splunk SIEM / SOC Lab

## 1. Executive technical summary

This project implements an end-to-end SIEM/SOC laboratory using Splunk Enterprise, Windows Sysmon telemetry, Linux authentication/audit telemetry, MITRE ATT&CK-aligned detections, scheduled alerting, lookup-backed case management, incident investigation, dashboards, and evidence-driven detection tuning.

The lab was built to demonstrate practical junior SOC / Blue Team capability rather than only product installation. The project therefore follows the operational chain from raw telemetry to analyst decision-making:

```text
Telemetry -> Ingestion -> Search / Normalization -> Detection -> Alert
-> Triage -> Investigation -> Classification -> Closure -> Tuning
```

Five detections were implemented and validated. Two detections were taken through the complete lifecycle, including incident investigation and controlled before/after tuning.

## 2. Scope and objectives

### Objectives

- ingest security telemetry from Windows and Linux endpoints;
- develop SPL searches that convert raw events into security-relevant detections;
- align detections to MITRE ATT&CK techniques;
- schedule and throttle alerts using analyst-meaningful correlation keys;
- implement a repeatable SOC triage and case-state workflow;
- investigate representative Windows and Linux alerts;
- classify incidents using evidence rather than alert syntax alone;
- build operational and executive dashboards;
- measure tuning trade-offs before changing detection logic;
- preserve reproducible SPL and analyst documentation in GitHub.

### Scope boundaries

This is an isolated, authorized laboratory. Results are lab-observed and are not presented as production detection-performance benchmarks.

## 3. Architecture

### Core components

- **Splunk Enterprise** — SIEM, search, alerting, dashboards, lookups, and analyst workflow.
- **WIN-END-01** — Windows endpoint providing Sysmon process and network telemetry.
- **LNX-END-01** — Linux endpoint providing SSH authentication and audit telemetry.
- **Detection layer** — five scheduled SPL searches aligned to MITRE ATT&CK.
- **SOC workflow** — lookup-backed case state, active queue, closure history, SLA views, and investigation notes.

See [`../architecture/architecture.md`](../architecture/architecture.md) for the full data-flow diagram and architecture rationale.

## 4. Data sources and indexes

### Windows

**Index:** `soc_sysmon`

Security-relevant telemetry used in the project includes:

- Sysmon EventCode 1 — process creation;
- Sysmon EventCode 3 — network connections;
- process image and command line;
- parent process image and command line;
- process GUID / PID relationships;
- registry/account change context through the Splunk Change data model where available.

### Linux

**Index:** `soc_linux`

Primary sources:

- `linux_secure` — SSH authentication telemetry;
- `auditd` — broader system/audit context.

The project also monitored source volume and endpoint last-seen status to surface collection-health issues.

## 5. Detection engineering

Five detections were implemented and validated:

| Rule | Detection | Severity | MITRE ATT&CK | Status |
| --- | --- | --- | --- | --- |
| DET-01 | Linux SSH Brute Force | Medium | T1110.001 — Password Guessing | Validated + Tuned |
| DET-02 | Windows Suspicious PowerShell | High | T1059.001 — PowerShell | Validated + Tuned |
| DET-03 | Windows Local Account Creation | Medium | T1136.001 — Local Account | Validated |
| DET-04 | Windows Scheduled Task Creation | High | T1053.005 — Scheduled Task | Validated |
| DET-05 | Windows Registry Run Key Persistence | High | T1547.001 — Registry Run Keys / Startup Folder | Validated |

All five searches are documented in [`../detections/`](../detections/) and the final SPL is stored in [`../spl/`](../spl/).

### Correlation design

The rules use contextual correlation rather than raw event counts alone. Examples include:

- DET-01: `host + src_ip + target_user`;
- DET-02: `host + user + suspicious_reason`;
- DET-03: `host + changed object`;
- DET-04: `host + task_name`;
- DET-05: `host + registry path`.

All five saved searches run on a recurring five-minute cadence in the lab. Correlation-key throttling is used where configured to reduce duplicate alerting.

## 6. SOC triage workflow

Case state is stored in `soc_triage_state.csv` with:

```text
case_id
rule_id
correlation_key
triage_status
triage_owner
triage_notes
created_at
last_update
```

The workflow supports:

- `New`;
- `Investigating`;
- `Closed`.

Closed cases are removed from the active queue and retained in closed-case history. Additional searches calculate case age, SLA remaining time, and closure duration.

This design separates alert generation from analyst state management and allows dashboard metrics to use a consistent case population.

## 7. Incident investigation — INC-01

### Detection

**DET-02 — Windows Suspicious PowerShell**

### Initial signal

Five PowerShell `EncodedCommand` executions were observed on `WIN-END-01` under `WIN-END-01\secadmin`.

### Investigation actions

- retrieved the five Sysmon process-creation events;
- extracted three distinct Base64 payloads;
- decoded the payloads as Unicode / UTF-16LE;
- reviewed decoded commands;
- reconstructed parent PowerShell processes;
- searched for child-process execution;
- reviewed surrounding endpoint activity for additional malicious behavior.

### Evidence

The three payloads decoded to authorized SIEM-Lab test commands. No suspicious child processes, malicious persistence, unauthorized download behavior, or other compromise evidence was identified.

### Classification

**Benign Positive / Authorized Security Test**

The detection itself was correct: `EncodedCommand` behavior occurred. The incident was benign because the payload content and execution context were authorized.

Full report: [`../incidents/INC-01-Windows-Suspicious-PowerShell.md`](../incidents/INC-01-Windows-Suspicious-PowerShell.md).

## 8. Incident investigation — INC-02

### Detection

**DET-01 — Linux SSH Brute Force**

### Initial signal

Repeated SSH password failures were observed from `172.31.255.1` against `invaliduser` on `LNX-END-01`.

### Investigation actions

- reconstructed individual SSH failure events;
- quantified failures by source, target user, and source port;
- correlated related `sshd-session` process IDs;
- checked for accepted password/public-key authentication;
- checked for SSH session-open events;
- reviewed surrounding authentication context.

### Evidence

The investigation confirmed:

- 30 failed SSH authentication events;
- 20 `Invalid user` events across related SSH processes;
- 0 successful authentication events;
- 0 opened SSH sessions.

### Classification

**True Positive / Authorized Security Test — Unsuccessful SSH Brute Force**

Full report: [`../incidents/INC-02-Linux-SSH-Brute-Force.md`](../incidents/INC-02-Linux-SSH-Brute-Force.md).

## 9. Detection tuning and evaluation

Two detections completed formal before/after tuning.

### DET-01 — SSH brute force

#### Baseline

The broad text search selected 81 events containing `Failed password for`.

Investigation showed:

- 78 were real SSH authentication failures;
- 3 were unrelated `sudo` commands executing `grep 'Failed password for' /var/log/secure`.

#### Threshold testing

Observed correlation windows were tested at multiple thresholds:

- `>=5` preserved 9 observed detection windows;
- `>=6` lost one observed five-attempt window;
- `>=8` would miss all four observed windows associated with INC-02.

#### Final tuning

The threshold remained `>=5` within 5 minutes. The improvement instead restricted candidate events to real `sshd` / `sshd-session` failure messages.

#### Result

- selected events before: 81;
- real SSH failures after filtering: 78;
- irrelevant events removed: 3;
- triggered windows before: 9;
- triggered windows after: 9;
- INC-02 windows preserved: 4 of 4.

### DET-02 — Suspicious PowerShell

#### Baseline

Five `EncodedCommand` executions generated detections. Investigation confirmed all five were authorized SIEM-Lab activity represented by three known Base64 payloads.

#### Candidate tuning strategies

1. exclude `secadmin` globally;
2. allowlist only the exact payloads already confirmed as authorized.

#### Regression test

A synthetic unknown-payload test demonstrated that a broad user exclusion would suppress a new payload executed by `secadmin`, while exact-payload allowlisting would continue to detect it.

#### Final tuning

- 3 exact authorized payloads allowlisted;
- 5 known benign historical detections suppressed;
- global user exclusion rejected;
- unknown `EncodedCommand` payload remains detectable;
- other suspicious PowerShell behaviors remain detectable.

Full before/after report: [`tuning-register.md`](tuning-register.md).

## 10. Dashboards

### SOC - Executive Overview

Provides management-oriented visibility into:

- total, active and closed cases;
- priority distribution;
- detections and affected assets;
- ATT&CK coverage;
- investigation status;
- case trends and closure time.

### SOC - Triage Operations

Provides analyst-oriented visibility into:

- active case queue;
- SLA status;
- analyst ownership;
- SSH failures;
- suspicious PowerShell activity;
- Sysmon activity;
- Windows account changes;
- suspicious network connections;
- endpoint log health;
- event volume by source;
- Splunk WARN/ERROR activity.

### SOC - Detection Coverage

Provides detection-engineering visibility into:

- implemented detections;
- ATT&CK techniques;
- data-source readiness;
- validation status;
- investigation depth;
- tuning status.

Visual evidence: [`../screenshots/`](../screenshots/).

## 11. Operational findings

The project exposed several realistic SOC engineering issues:

- raw text matching can capture non-security events that merely contain the same string;
- threshold increases can reduce noise while also creating blind spots;
- suspicious syntax does not determine malicious intent without context;
- broad allowlists can suppress future unknown malicious behavior;
- endpoint last-seen monitoring is required to distinguish healthy telemetry from stale collection;
- incomplete CIM enrichment can lead to `unknown` account-change fields;
- executive metrics become inconsistent when dashboards use different case populations.

These findings were treated as engineering observations rather than hidden from the final portfolio.

## 12. Validation status and metrics

| Metric | Lab-observed result |
| --- | ---: |
| Implemented detections | 5 |
| Validated detections | 5 |
| Fully investigated detections | 2 |
| Formally tuned detections | 2 |
| Confirmed True Positive investigations | 1 |
| Confirmed Benign Positive investigations | 1 |
| Confirmed False Positives | 0 |
| Historical closed case without recorded classification | 1 |
| Dashboards | 3 |
| Playbooks | 3 |
| Detailed incident reports | 2 |

These numbers describe the controlled lab dataset only.

## 13. Limitations

- The environment is a small isolated lab rather than a production SOC.
- The event corpus is intentionally limited and does not represent enterprise-scale diversity.
- DET-03 through DET-05 were validated but did not complete formal before/after tuning.
- Some Windows account-change fields showed incomplete CIM enrichment.
- Endpoint telemetry became stale during later documentation work, demonstrating collection-health visibility but limiting fresh event generation.
- No generalized detection-accuracy percentages are claimed.

## 14. Security and publication controls

Repository documentation is sanitized for publication. Passwords, tokens, cookies, private keys, API credentials, and session secrets are excluded. Private RFC1918 lab addresses are retained only where useful for reproducing investigation context.

See [`../SECURITY.md`](../SECURITY.md).

## 15. Technical competencies demonstrated

- Splunk Enterprise administration fundamentals;
- Windows and Linux security-log ingestion;
- Sysmon process and network analysis;
- SPL development;
- field extraction and correlation;
- Splunk CIM / data-model use;
- scheduled alerts and throttling;
- MITRE ATT&CK mapping;
- SOC triage and SLA workflow;
- PowerShell payload analysis;
- process-tree reconstruction;
- SSH authentication investigation;
- incident classification and documentation;
- dashboard engineering;
- detection tuning and regression testing;
- evidence-backed technical reporting.

## 16. Conclusion

The lab demonstrates a complete defensive workflow rather than an isolated collection of searches. Telemetry was ingested, converted into scheduled detections, routed through a repeatable triage process, investigated with host and user context, classified, documented, and used to improve detection logic.

The strongest technical outcome is the feedback loop between investigation and engineering: DET-01 reduced irrelevant candidate events without losing observed attack windows, while DET-02 rejected an overly broad suppression strategy and preserved detection of unknown payloads. This demonstrates practical SOC reasoning in addition to Splunk configuration skills.
