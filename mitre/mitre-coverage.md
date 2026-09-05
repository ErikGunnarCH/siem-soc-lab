# MITRE ATT&CK Coverage

| Detection | Technique | Technique name | Evidence source |
| --- | --- | --- | --- |
| DET-01 | T1110.001 | Password Guessing | Linux SSH authentication failures |
| DET-02 | T1059.001 | PowerShell | Sysmon process creation / PowerShell command line |
| DET-03 | T1136.001 | Local Account | Windows account creation / CIM Change |
| DET-04 | T1053.005 | Scheduled Task | Sysmon process creation / scheduled-task tooling |
| DET-05 | T1547.001 | Registry Run Keys / Startup Folder | Registry change / CIM Change |

## Coverage summary

- Implemented detections: 5
- Validated detections: 5
- Covered ATT&CK techniques: 5
- Fully investigated detections: 2
- Tuned detections: 2

## Interpretation

This table describes what the laboratory currently detects; it is not a claim of comprehensive ATT&CK coverage. Each mapped technique has a validated rule and supporting telemetry in the lab dataset.

## Engineering notes

ATT&CK mapping is used as a common language for detection intent and coverage analysis. Rule effectiveness still depends on telemetry quality, environment context, thresholds, suppression logic, and investigation procedures.
