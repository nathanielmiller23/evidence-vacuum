# Ground Truth: ev-S21

**Scenario:** Evidence Vacuum v3 HELD-OUT TEST scenario S21 (lateral, MALICIOUS).

**Generated:** 2026-11-03 13:00:00 UTC


## Attack Summary

This scenario simulates the following attack sequence:

1. **dev.sharma** on **FILE-RB-01**: RDP to file server from a staff workstation with stolen admin credentials
2. **dev.sharma** on **FILE-RB-01**: Archive of client records staged


## Timeline

| Timestamp | Actor | System | Event Type | Details |
|-----------|-------|--------|------------|---------|
| 2026-11-03 13:41:56 UTC | dev.sharma | FILE-RB-01 | Rdp_Session | RDP session to 10.60.20.20:3389 (UID: CBlEZwPFeqizvH2PX20) |
| 2026-11-03 13:47:19 UTC | dev.sharma | FILE-RB-01 | Process | Skipped (rdp session not connected); no evidence emitted |


## Source Evidence Status

Canonical ground truth remains authoritative. Source rows may be `visible`, `delayed`, `dropped`, `filtered`, or `out_of_window` depending on the selected observation profile and sensor placement.

| Storyline ID | Source | Status Counts |
|--------------|--------|---------------|
| rdp | sysmon | filtered: 1, visible: 20 |
| rdp | windows_security | visible: 19 |
| rdp | zeek | visible: 4 |


## Indicators of Compromise (IOCs)

### Network IOCs

- 10.60.20.20:3389 (Lateral Movement)
- Zeek UID: CBlEZwPFeqizvH2PX20

### User IOCs

- dev.sharma (compromised account)
