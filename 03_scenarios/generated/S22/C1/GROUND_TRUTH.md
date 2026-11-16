# Ground Truth: ev-S22

**Scenario:** Evidence Vacuum v3 HELD-OUT TEST scenario S22 (lateral, BENIGN).

**Generated:** 2026-11-03 13:00:00 UTC


## Attack Summary

This scenario simulates the following attack sequence:

1. **dev.sharma** on **FILE-RB-01**: Approved RDP maintenance session from the admin workstation
2. **dev.sharma** on **FILE-RB-01**: Disk cleanup


## Timeline

| Timestamp | Actor | System | Event Type | Details |
|-----------|-------|--------|------------|---------|
| 2026-11-03 13:41:51 UTC | dev.sharma | FILE-RB-01 | Rdp_Session | RDP session to 10.60.20.20:3389 (UID: CWr8lEHZB3PN0K6ox) |
| 2026-11-03 13:47:03 UTC | dev.sharma | FILE-RB-01 | Process | Skipped (rdp session not connected); no evidence emitted |


## Source Evidence Status

Canonical ground truth remains authoritative. Source rows may be `visible`, `delayed`, `dropped`, `filtered`, or `out_of_window` depending on the selected observation profile and sensor placement.

| Storyline ID | Source | Status Counts |
|--------------|--------|---------------|
| rdp | sysmon | filtered: 1, visible: 17 |
| rdp | windows_security | visible: 14 |
| rdp | zeek | visible: 4 |


## Indicators of Compromise (IOCs)

### Network IOCs

- 10.60.20.20:3389 (Lateral Movement)
- Zeek UID: CWr8lEHZB3PN0K6ox

### User IOCs

- dev.sharma (compromised account)
