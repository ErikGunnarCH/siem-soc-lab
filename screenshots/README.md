# Visual Evidence

This directory contains a curated subset of screenshots from the working Splunk lab. The goal is not to archive every screen captured during development, but to preserve the evidence that best demonstrates practical SOC, SIEM and detection-engineering work.

All images were selected from the completed lab, cropped to remove unnecessary browser chrome, compressed for GitHub viewing, and reviewed for obvious credentials or secrets.

## Recruiter / reviewer quick gallery

### SOC Executive Overview

![SOC Executive Overview](executive-overview.webp)

Shows the executive-facing case view with total, active and closed case metrics plus priority and detection-rule context. This demonstrates that the project extends beyond isolated SPL searches into operational security reporting.

### SOC Triage Operations

![SOC Triage Operations](triage-operations.webp)

Shows an active analyst queue with case ownership, priority, SLA context and correlation details. This is evidence of a working triage workflow rather than a dashboard-only lab.

### Detection Coverage

![SOC Detection Coverage](detection-coverage.webp)

Shows the detection-engineering view with 5 implemented detections, 5 ATT&CK techniques, the rule catalog, ATT&CK coverage and data-source readiness.

## Detection-tuning evidence

### DET-01 — threshold analysis

![DET-01 threshold analysis](tuning/det01-threshold-analysis.webp)

The comparison tests `>=5`, `>=6` and `>=8` thresholds against observed SSH activity. The result supported retaining `>=5` because higher thresholds would discard observed detection windows. The final tuning improved event selection instead of simply increasing the threshold.

### DET-02 — regression test

![DET-02 regression test](tuning/det02-regression-test.webp)

The synthetic unknown-payload test demonstrates why a broad exclusion for `secadmin` was rejected. A user-wide exclusion would suppress the unknown payload, while the exact-payload allowlist continues to detect it.

## Evidence-selection principles

- Prefer screenshots that prove an analyst or engineering decision.
- Avoid near-duplicate screenshots.
- Keep screenshots tied to documented SPL, incidents, dashboards or tuning results.
- Do not publish passwords, API keys, authentication tokens, session cookies, private keys or unrelated personal information.
- Lab hostnames and RFC1918/private lab addresses may appear where they are needed to explain the investigation context.

For the written interpretation of these screenshots, see [`../dashboards/dashboards.md`](../dashboards/dashboards.md) and [`../reports/tuning-register.md`](../reports/tuning-register.md).
