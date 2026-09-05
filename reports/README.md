# Reports Index

This directory consolidates the formal reporting deliverables produced from the SIEM/SOC lab.

## Phase 14 deliverables

| Required deliverable | Repository artifact | Status |
| --- | --- | --- |
| Detailed technical report | [`technical-report.md`](technical-report.md) | Complete |
| One-page executive report | [`executive-report.md`](executive-report.md) | Complete |
| Incident report | [`../incidents/INC-01-Windows-Suspicious-PowerShell.md`](../incidents/INC-01-Windows-Suspicious-PowerShell.md) and [`../incidents/INC-02-Linux-SSH-Brute-Force.md`](../incidents/INC-02-Linux-SSH-Brute-Force.md) | Complete |
| Detection catalog | [`../detections/detection-catalog.md`](../detections/detection-catalog.md) | Complete |
| MITRE ATT&CK matrix | [`../mitre/mitre-coverage.md`](../mitre/mitre-coverage.md) | Complete |
| Data-source inventory | [`data-source-inventory.md`](data-source-inventory.md) | Complete |
| Test register | [`test-register.md`](test-register.md) | Complete |
| False-positive / tuning register | [`tuning-register.md`](tuning-register.md) | Complete |
| Lessons learned | [`../lessons-learned/lessons-learned.md`](../lessons-learned/lessons-learned.md) | Complete |

## Reporting principles

The reporting layer follows the same evidence discipline used throughout the project:

- lab-observed metrics only;
- clear distinction between True Positive, Benign Positive, and False Positive;
- no generalized production-performance claims;
- tuning documented with before/after evidence and missed-event risk;
- validation status kept separate from formal tuning status;
- sanitized publication with secrets excluded.

## Recommended reading order

For a recruiter or hiring manager:

1. [`executive-report.md`](executive-report.md)
2. [`../README.md`](../README.md)
3. [`../screenshots/README.md`](../screenshots/README.md)
4. [`../detections/detection-catalog.md`](../detections/detection-catalog.md)

For a technical interviewer:

1. [`technical-report.md`](technical-report.md)
2. [`../spl/`](../spl/)
3. [`../incidents/`](../incidents/)
4. [`tuning-register.md`](tuning-register.md)
5. [`test-register.md`](test-register.md)
