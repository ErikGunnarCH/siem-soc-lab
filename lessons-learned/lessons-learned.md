# Lessons Learned

## Detection engineering

A correct alert is not necessarily a malicious incident. DET-02 correctly identified suspicious EncodedCommand syntax, but investigation showed the activity was an authorized lab test. This was treated as a Benign Positive rather than a False Positive.

## Context matters

PowerShell command syntax alone was insufficient to determine intent. Decoded payloads, parent/child process lineage, related persistence, and network context were required.

For SSH brute force, failure counts alone were insufficient. The investigation also checked for successful authentication, opened SSH sessions, and post-authentication activity.

## Tune the cause of noise

DET-01 initially matched three unrelated `sudo/grep` events because the raw event merely contained the phrase `Failed password for`. The best tuning action was to restrict the candidate events to real sshd messages, not simply increase the threshold.

## Threshold changes can create blind spots

Testing showed that increasing DET-01 from `>=5` to `>=6` would lose one observed window, while `>=8` would miss all observed windows associated with INC-02. Tuning must measure missed-event risk, not just alert reduction.

## Avoid broad allowlists

For DET-02, excluding the analyst account would suppress future unknown payloads executed by that account. Exact-payload allowlisting was safer because only already validated lab payloads were suppressed.

## Data quality is part of SOC operations

Dashboard work exposed stale endpoint telemetry and incomplete CIM field enrichment for Windows account-change events. Dashboards should reveal collection and normalization problems rather than hide them.

## Case workflow consistency

All executive metrics should use the same case population. Mixing the raw state lookup with active/closed saved searches initially produced inconsistent totals. Standardizing the population fixed the discrepancy.

## Portfolio discipline

Lab conclusions should be recorded precisely. Do not convert a Benign Positive into a False Positive, do not invent tuning percentages, and do not claim production effectiveness from a small controlled dataset.
