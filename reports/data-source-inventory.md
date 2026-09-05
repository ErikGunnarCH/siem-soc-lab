# Data Source Inventory

This inventory documents the telemetry sources used by the SIEM/SOC lab and maps them to the detections and investigations they support.

## Inventory summary

| Platform | Splunk index | Source / sourcetype | Primary telemetry | Used by |
| --- | --- | --- | --- | --- |
| Windows | `soc_sysmon` | Sysmon / Windows Event Log | Process creation, command line, parent process, process GUID/PID | DET-02, DET-04, INC-01 |
| Windows | `soc_sysmon` | Sysmon EventCode 3 | Process network connections | SOC Operations dashboard / investigation context |
| Windows | CIM Change data model | Account-change normalized events | User object creation and change context | DET-03 |
| Windows | CIM Change data model | Registry-change normalized events | Registry path/action context | DET-05 |
| Linux | `soc_linux` | `linux_secure` | SSH authentication failures, invalid users, accepted authentication, session context | DET-01, INC-02 |
| Linux | `soc_linux` | `auditd` | Linux audit activity / supplemental system context | SOC Operations dashboard |
| Splunk platform | `_internal` / platform telemetry | Splunk service logs | WARN/ERROR operational events | SOC Operations dashboard |

## Windows telemetry

### Sysmon process creation

Primary fields used:

- `host`
- `User`
- `Image`
- `CommandLine`
- `ParentImage`
- `ParentCommandLine`
- `ProcessId`
- `ParentProcessId`
- `ProcessGuid`
- `ParentProcessGuid`

Operational use:

- suspicious PowerShell detection;
- scheduled-task creation detection;
- Base64 payload extraction;
- process-tree reconstruction;
- child-process validation.

### Sysmon network connections

Primary fields used include process image, destination IP, destination port, user and host context.

Operational use:

- suspicious-process network-context panel;
- supporting investigation evidence.

### Change data model — account changes

Primary normalized fields used by DET-03:

- `All_Changes.action`
- `All_Changes.object_category`
- `All_Changes.user`
- `All_Changes.object`
- `All_Changes.object_path`
- `All_Changes.status`
- `All_Changes.vendor_product`

Known limitation: some account-change dashboard fields appeared as `unknown`, demonstrating incomplete enrichment in the available lab data.

### Change data model — registry changes

Primary normalized fields used by DET-05:

- `All_Changes.action`
- `All_Changes.object_category`
- `All_Changes.object_path`
- `All_Changes.change_type`
- `All_Changes.object_attrs`
- `All_Changes.user`

The rule focuses on `Run` and `RunOnce` persistence paths.

## Linux telemetry

### `linux_secure`

Primary SSH fields extracted from raw events:

- source IP;
- source port;
- target user;
- authentication outcome;
- SSH process/session identifier.

Operational use:

- DET-01 brute-force correlation;
- INC-02 authentication timeline;
- successful-authentication validation;
- session-open validation;
- SSH failure trend dashboard.

### `auditd`

Used as a supplemental Linux source and included in event-volume monitoring to demonstrate multi-source ingestion.

## Splunk operational telemetry

Splunk internal WARN/ERROR events are surfaced in the SOC Operations dashboard to provide visibility into platform-side operational problems alongside endpoint telemetry.

## Data quality / health observations

The lab deliberately monitors telemetry health rather than assuming ingestion is current.

Observed examples:

- `WIN-END-01` and `LNX-END-01` later became `STALE` based on last-seen event age;
- Linux initially appeared as `NO DATA` until the health search was corrected to use historical last-seen data;
- Windows account-change normalization contained incomplete fields in the available dataset.

These are retained as operational findings because a SOC must distinguish detection problems from collection or normalization problems.

## Detection-to-source mapping

| Rule | Required data source | Available in lab | Validation status |
| --- | --- | --- | --- |
| DET-01 | Linux SSH authentication logs | Yes | Validated + Tuned |
| DET-02 | Sysmon Process Creation | Yes | Validated + Tuned |
| DET-03 | Windows Account Change / CIM Change | Yes | Validated |
| DET-04 | Sysmon Process Creation | Yes | Validated |
| DET-05 | Registry Change / CIM Change | Yes | Validated |

## Security note

This inventory documents logical telemetry requirements only. Credentials, tokens, private keys, session secrets, and unrelated personal information are intentionally excluded from the repository.
