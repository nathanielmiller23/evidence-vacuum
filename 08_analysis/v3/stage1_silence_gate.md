# v3 Stage 1b: sensor-silence gate behind G-ft (post hoc on seen v2 data: EXPLORATORY)

Calibration on T001–T060 complete (C1) streams: longest natural winsec/sysmon silence = 16.7 min → threshold = 22 min (natural max + 5).
Same T-pool, gapped (C2) streams: 52/60 scenarios exceed the threshold (gaps on decisive host sensors, consequential or not).

| Pipeline | Correct | Justified closes (of 12) | Unsupported closes |
|---|---|---|---|
| G-ft alone | 35/45 | 4 | 2 |
| G-ft + silence gate | 37/45 | 4 | 0 |

| G-ft close | label | defensible | longest decisive host-sensor silence (min) | gate |
|---|---|---|---|---|
| A__S07__C1__20261115T030836Z | BENIGN_SUPPORTED | yes | 8.3 | pass |
| A__S08__C2__20261115T030000Z | INSUFFICIENT | no | 42.3 | VETO |
| A__S10__C1__20261115T030728Z | BENIGN_SUPPORTED | yes | 11.5 | pass |
| A__S10__C2__20261115T030409Z | INSUFFICIENT | no | 46.0 | VETO |
| A__S12__C2__20261115T030253Z | BENIGN_SUPPORTED | yes | 9.4 | pass |
| C__S12__C1__20261115T032628Z | BENIGN_SUPPORTED | yes | 9.4 | pass |
