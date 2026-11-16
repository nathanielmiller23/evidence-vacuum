# S2 held-out test set: label review (author sign-off before freeze)

Org: Riverbend Veterinary Hospital (new, 3rd org). Day 2026-11-03, case window 13:20–14:20 UTC, outage 13:30–14:15 UTC.
Archetypes are new (none appear in the v1 S-set or the T-pool). Rule: PROTOCOL §1.4 (same as v1).

| Scenario | Pair | Truth | What happened | Outage (C2/C3) | C1 | C2 | C3 | OK to close? |
|---|---|---|---|---|---|---|---|---|
| S21 | lateral | MAL | Admin account RDPs into the file server **from a staff PC** (stolen creds), stages an archive | Host logs + network logs for file server, DC, both candidate source PCs | MALICIOUS | INSUFFICIENT | INSUFFICIENT | no |
| S22 | lateral | BEN | Admin RDPs into the file server **from the admin PC** (policy), disk cleanup | same as S21 | BENIGN | INSUFFICIENT | INSUFFICIENT | C1 only |
| S23 | task | MAL | Staff user registers a hidden scheduled task running encoded PowerShell from an external IP | Host logs on WS-HITO-01 | MALICIOUS | INSUFFICIENT | INSUFFICIENT | no |
| S24 | task | BEN | Admin registers `\RB-IT\Deploy-VetChart` (approved name, approved installer share; on the change calendar) | same | BENIGN | INSUFFICIENT | INSUFFICIENT | C1 only |
| S25 | dump | MAL | `rundll32 comsvcs.dll MiniDump` of LSASS to C:\Users\Public | Host logs on WS-CPRICE-01 | MALICIOUS | INSUFFICIENT | INSUFFICIENT | no |
| S26 | dump | BEN | Approved vendor tool `vcdump.exe` dumps hung `vetchart.exe` (open ticket on calendar) | same | BENIGN | INSUFFICIENT | INSUFFICIENT | C1 only |
| S27 | group | MAL | Admin creds **from a staff PC** add the vet tech to Remote Desktop Users (restricted to IT) | Proxy only (not decisive) | MALICIOUS | MALICIOUS | MALICIOUS | no |
| S28 | group | BEN | Admin adds the new hire to Billing-Share (on the change calendar) | Proxy only (not decisive) | BENIGN | BENIGN | BENIGN | yes (all 3) |

Totals: 12 INSUFFICIENT, 6 MALICIOUS_SUPPORTED, 6 BENIGN_SUPPORTED; 6 justifiably closable cells (same shape as v1).

Leak checks (done): the decisive records are present in C1 and absent in C2 for S21–S26 (RDP source, task name, dump command);
present in C2 for S27/S28. Two fixes before review: the RDP outage was widened to the source PCs + DC + network sensors
(zeek DNS leaked the source PC), and S25 was reseeded (EvidenceForge internal error). Remaining machine-account Kerberos
noise before the outage is identical in kind across S21/S22 and not decisive.
