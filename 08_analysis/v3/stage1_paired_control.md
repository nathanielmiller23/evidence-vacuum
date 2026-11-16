# v3 Stage 1a: paired control, post hoc on v2 outputs (EXPLORATORY: this data has been seen)

Veto rule: if the gap check objects, a proposed `close` becomes `collect_more`.

| Pipeline | Correct | Justified closes | Unsupported closes |
|---|---|---|---|
| G-ft alone | 35/45 | 4/12 | 2 |
| G-ft + R2 veto | 33/45 | 0/12 | 0 |
| G-ft + Jev relevant_gap veto (>= 0.1) | 34/45 | 1/12 | 0 |
| G-ft + Jev relevant_gap veto (>= 0.2) | 35/45 | 3/12 | 1 |
| G-ft + Jev relevant_gap veto (>= 0.3) | 36/45 | 4/12 | 1 |
| G-ft + Jev relevant_gap veto (>= 0.4) | 35/45 | 4/12 | 2 |
| G-ft + Jev relevant_gap veto (>= 0.5) | 35/45 | 4/12 | 2 |
| G-ft + Jev relevant_gap veto (>= 0.6) | 35/45 | 4/12 | 2 |

## G-ft closes and what each check said

| run | label | closure defensible | R2 action | Jev relevant_gap |
|---|---|---|---|---|
| A__S07__C1__20261115T030836Z | BENIGN_SUPPORTED | yes | collect_more | 0.07 |
| A__S08__C2__20261115T030000Z | INSUFFICIENT | no | collect_more | 0.18 |
| A__S10__C1__20261115T030728Z | BENIGN_SUPPORTED | yes | collect_more | 0.1 |
| A__S10__C2__20261115T030409Z | INSUFFICIENT | no | collect_more | 0.35 |
| A__S12__C2__20261115T030253Z | BENIGN_SUPPORTED | yes | escalate | 0.13 |
| C__S12__C1__20261115T032628Z | BENIGN_SUPPORTED | yes | escalate | 0.22 |
