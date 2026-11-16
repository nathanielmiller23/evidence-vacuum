# Ground Truth: ev-S25

**Scenario:** Evidence Vacuum v3 HELD-OUT TEST scenario S25 (dump, MALICIOUS).

**Generated:** 2026-11-03 13:00:00 UTC


## Attack Summary

This scenario simulates the following attack sequence:

1. **cole.price** on **WS-CPRICE-01**: Interactive logon
2. **cole.price** on **WS-CPRICE-01**: LSASS dumped with comsvcs.dll


## Timeline

| Timestamp | Actor | System | Event Type | Details |
|-----------|-------|--------|------------|---------|
| 2026-11-03 13:38:22 UTC | cole.price | WS-CPRICE-01 | Logon | Network logon from 139.162.174.124 (LogonID: 0xead2907) |
| 2026-11-03 13:44:19 UTC | cole.price | WS-CPRICE-01 | Process | Process: C:\Windows\System32\rundll32.exe (PID: 5112) - `rundll32.exe C:\Windows\System32\comsvcs.dll, M...` |


## Indicators of Compromise (IOCs)

### Network IOCs

- 139.162.174.124 (Attacker IP)

### Process IOCs

- C:\Windows\System32\rundll32.exe
- `rundll32.exe C:\Windows\System32\comsvcs.dll, MiniDump 712 C:\Users\Public\lsass.dmp full`

### User IOCs

- cole.price (compromised account)
