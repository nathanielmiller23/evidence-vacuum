# Ground Truth: ev-S26

**Scenario:** Evidence Vacuum v3 HELD-OUT TEST scenario S26 (dump, BENIGN).

**Generated:** 2026-11-03 13:00:00 UTC


## Attack Summary

This scenario simulates the following attack sequence:

1. **cole.price** on **WS-CPRICE-01**: Interactive logon
2. **cole.price** on **WS-CPRICE-01**: Approved vendor tool dumps the hung VetChart process


## Timeline

| Timestamp | Actor | System | Event Type | Details |
|-----------|-------|--------|------------|---------|
| 2026-11-03 13:38:21 UTC | cole.price | WS-CPRICE-01 | Logon | Network logon from 45.79.19.196 (LogonID: 0xfa78790) |
| 2026-11-03 13:43:39 UTC | cole.price | WS-CPRICE-01 | Process | Process: C:\Program Files\VetChart\Tools\vcdump.exe (PID: 3044) - `"C:\Program Files\VetChart\Tools\vcdump.exe" -p...` |


## Indicators of Compromise (IOCs)

### Network IOCs

- 45.79.19.196 (Attacker IP)

### Process IOCs

- C:\Program Files\VetChart\Tools\vcdump.exe
- `"C:\Program Files\VetChart\Tools\vcdump.exe" -p vetchart.exe -o C:\ProgramData\VetChart\Dumps\vetchart_hang.dmp`

### User IOCs

- cole.price (compromised account)
