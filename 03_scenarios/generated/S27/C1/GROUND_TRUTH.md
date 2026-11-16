# Ground Truth: ev-S27

**Scenario:** Evidence Vacuum v3 HELD-OUT TEST scenario S27 (group, MALICIOUS).

**Generated:** 2026-11-03 13:00:00 UTC


## Attack Summary

This scenario simulates the following attack sequence:

1. **dev.sharma** on **DC-RB-01**: Admin credentials used from a staff workstation
2. **dev.sharma** on **DC-RB-01**: Staff user added to Remote Desktop Users


## Timeline

| Timestamp | Actor | System | Event Type | Details |
|-----------|-------|--------|------------|---------|
| 2026-11-03 13:40:14 UTC | dev.sharma | DC-RB-01 | Logon | Network logon from 10.60.10.22 (LogonID: 0x7a76dca) |
| 2026-11-03 13:42:53 UTC | dev.sharma | DC-RB-01 | Group_Member_Added | Added cole.price to group Remote Desktop Users |


## Indicators of Compromise (IOCs)

### Network IOCs

- 10.60.10.22 (Attacker IP)

### User IOCs

- Group: Remote Desktop Users (compromised account)
- cole.price (compromised account)
- dev.sharma (compromised account)
