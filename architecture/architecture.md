# Architecture

## Logical components

```text
+-------------------+            +-------------------+
| Windows Endpoint  |            | Linux Endpoint    |
| WIN-END-01        |            | LNX-END-01        |
| Sysmon telemetry  |            | SSH + audit logs  |
+---------+---------+            +---------+---------+
          |                                |
          +---------------+----------------+
                          |
                          v
                 +-------------------+
                 | Splunk Enterprise |
                 | SIEM / SOC Layer  |
                 +---------+---------+
                           |
          +----------------+----------------+
          |                |                |
          v                v                v
     Detections        Triage Queue      Dashboards
     & Alerts          & Case State      & Reporting
          |                |
          +--------+-------+
                   |
                   v
            Investigation
                   |
                   v
        Classification / Closure
                   |
                   v
                 Tuning
```

## Data flow

### Windows

Windows process, registry, and network telemetry is collected through Sysmon and indexed in `soc_sysmon`. The project primarily uses Sysmon EventCode 1 for process creation and EventCode 3 for network connection context.

### Linux

Linux authentication and audit telemetry is indexed in `soc_linux`. `linux_secure` provides SSH authentication evidence used for brute-force detection and investigation. Audit telemetry is also available for broader system context.

## Detection layer

Five detections are scheduled in Splunk and map to MITRE ATT&CK techniques. Correlation keys are used to group repeat activity and support alert throttling.

## Case-management layer

A lookup-backed workflow tracks case ID, detection ID, correlation key, status, owner, notes, creation time, and last update. Closed cases are removed from the active queue but retained for history and closure metrics.

## Dashboard layer

- `SOC - Executive Overview`
- `SOC - Triage Operations`
- `SOC - Detection Coverage`

## Security note

The architecture shown here is intentionally logical and sanitized. No authentication secrets are stored in this repository.
