# Ground Truth: ev-S28

**Scenario:** Evidence Vacuum v3 HELD-OUT TEST scenario S28 (group, BENIGN).

**Generated:** 2026-11-03 13:00:00 UTC


## Attack Summary

This scenario simulates the following attack sequence:

1. **dev.sharma** on **DC-RB-01**: Admin session from the admin workstation
2. **dev.sharma** on **DC-RB-01**: New hire added to Billing-Share (change calendar)


## Timeline

| Timestamp | Actor | System | Event Type | Details |
|-----------|-------|--------|------------|---------|
| 2026-11-03 13:39:49 UTC | dev.sharma | DC-RB-01 | Logon | Network logon from 10.60.10.23 (LogonID: 0x1307103b) |
| 2026-11-03 13:42:41 UTC | dev.sharma | DC-RB-01 | Group_Member_Added | Added hana.ito to group Billing-Share |


## Indicators of Compromise (IOCs)

### Network IOCs

- 10.60.10.23 (Attacker IP)

### User IOCs

- Group: Billing-Share (compromised account)
- dev.sharma (compromised account)
- hana.ito (compromised account)
