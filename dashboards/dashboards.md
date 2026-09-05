# Dashboards

## SOC - Executive Overview

Purpose: executive-level visibility into SOC case volume, current workload, affected assets, ATT&CK coverage, and investigation progress.

Key panels:

- Total Cases
- Active Cases
- Closed Cases
- Average Closure Time
- Cases by Priority
- Cases by Detection Rule
- Investigation Status
- Affected Assets
- Users / Accounts Involved
- Cases by MITRE ATT&CK Technique
- Case Trend Over Time

## SOC - Triage Operations

Purpose: operational SOC view for active case management, SLA tracking, analyst workload, telemetry activity, and collection health.

Key panels:

- active case queue
- cases by priority
- cases by detection rule
- cases by analyst
- SLA status and breached cases
- closed-case history
- SSH authentication failures
- suspicious PowerShell processes
- Sysmon event activity
- Windows account changes
- suspicious process network connections
- endpoint log health
- event volume by source
- Splunk WARN/ERROR activity

Operational findings discovered while building this dashboard included stale endpoint telemetry and incomplete CIM field enrichment for some Windows account-change data.

## SOC - Detection Coverage

Purpose: detection-engineering coverage and validation status.

Key panels:

- Implemented Detections
- MITRE ATT&CK Techniques Covered
- Detection Catalog
- Coverage by MITRE ATT&CK Technique
- Detection Data Source Readiness
- Validated Detection Tests
- Detection Tuning Status
- Case Classification Outcomes
- Fully Investigated Detection Rules
- Detection Validation Matrix

At the completed dashboard milestone, the lab contained 5 validated detections, 5 mapped ATT&CK techniques, 2 fully investigated rules, and 2 formally tuned rules.

## Screenshot guidance

Screenshots added to this repository should be sanitized and placed under `screenshots/`. Do not publish credentials, tokens, cookies, browser profile data, or unrelated personal information.
