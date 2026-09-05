# Tuning Register

This report summarizes the two detections that completed formal before/after tuning.

## DET-01 — Linux SSH Brute Force

### Before

The broad base search selected 81 events containing the text `Failed password for`. Three of those events were not SSH authentication failures; they were `sudo` commands running `grep 'Failed password for' /var/log/secure`.

### After

The rule was restricted to real `sshd` / `sshd-session` failure messages.

- Selected events before: 81
- Real SSH failures after filtering: 78
- Irrelevant events removed: 3
- Triggered windows before: 9
- Triggered windows after: 9
- INC-02 windows preserved: 4 of 4
- Threshold: retained at `>=5` failures
- Window: retained at 5 minutes

### Risk analysis

Testing showed that raising the threshold to 6 would lose one observed five-attempt window. Raising it to 8 would miss every observed window associated with INC-02. The threshold was therefore retained and the event-selection logic was improved instead.

### Decision

**Tuning Approved.** Noise was removed without reducing observed detection-window coverage.

---

## DET-02 — Windows Suspicious PowerShell

### Before

Five PowerShell EncodedCommand executions generated detections. Investigation showed all five were authorized SIEM-lab activity, represented by three distinct Base64 payloads.

### Candidate strategies

1. Exclude the analyst account globally.
2. Allowlist only the exact payloads already validated as authorized.

A synthetic unknown-payload regression test demonstrated that a global user exclusion would suppress a new payload executed by the same account, while the exact-payload allowlist would still detect it.

### After

- Historical suspicious executions before: 5
- Known authorized historical detections after: 0
- Authorized payloads allowlisted: 3
- Global user exclusion: rejected
- Unknown EncodedCommand payloads: remain detectable
- Other suspicious PowerShell behaviors: remain detectable

### Decision

**Tuning Approved.** Exact-payload allowlisting was selected because it suppresses only known authorized activity while preserving detection of new payloads.

## Current catalog status

- Total detections: 5
- Validated detections: 5
- Tuned detections: 2
- Not yet formally reviewed for tuning: 3

## Classification evidence used during tuning

- Confirmed True Positive investigated: 1
- Confirmed Benign Positive investigated: 1
- Confirmed False Positives: 0
- Historical closed case without recorded classification: 1

All numbers above are lab-observed values and should not be interpreted as production performance claims.
