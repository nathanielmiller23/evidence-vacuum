# Ground Truth: ev-S24

**Scenario:** Evidence Vacuum v3 HELD-OUT TEST scenario S24 (task, BENIGN).

**Generated:** 2026-11-03 13:00:00 UTC


## Attack Summary

This scenario simulates the following attack sequence:

1. **dev.sharma** on **WS-HITO-01**: Admin network logon from the admin workstation
2. **dev.sharma** on **WS-HITO-01**: IT deployment task (approved name and installer share)


## Timeline

| Timestamp | Actor | System | Event Type | Details |
|-----------|-------|--------|------------|---------|
| 2026-11-03 13:36:36 UTC | dev.sharma | WS-HITO-01 | Logon | Network logon from 10.60.10.23 (LogonID: 0xe77bd25) |
| 2026-11-03 13:41:21 UTC | dev.sharma | WS-HITO-01 | Scheduled_Task_Created | Scheduled task created: \RB-IT\Deploy-VetChart |


## Indicators of Compromise (IOCs)

### Network IOCs

- 10.60.10.23 (Attacker IP)

### Process IOCs

- Scheduled Task: \RB-IT\Deploy-VetChart

### User IOCs

- dev.sharma (compromised account)

### File IOCs

- msiexec.exe /i \\FILE-RB-01\Deploy\VetChart-4.2.msi /qn
