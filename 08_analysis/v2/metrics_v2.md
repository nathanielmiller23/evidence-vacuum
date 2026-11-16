# v2 reviewer results (evaluated on 45 frozen v1 answers; labels = frozen v1 rubric)

| Arm | Unnecessary escalation (benign cells) | Unsupported closures | Correct action | False 'malicious' on benign | Invalid |
|---|---|---|---|---|---|
| investigator (v1 A/C) | 12/12 (100%; 76%–100%) | 0/33 (0%; 0%–10%) | 33/45 (73%; 59%–84%) | – | 0 |
| G-base | 12/12 (100%; 76%–100%) | 0/33 (0%; 0%–10%) | 24/45 (53%; 39%–67%) | 0 | 0 |
| G-ft | 8/12 (67%; 39%–86%) | 2/33 (6%; 2%–20%) | 35/45 (78%; 64%–87%) | 5 | 1 |
| H-hosted | 12/12 (100%; 76%–100%) | 0/33 (0%; 0%–10%) | 33/45 (73%; 59%–84%) | 7 | 0 |
| H-stack | 12/12 (100%; 76%–100%) | 0/33 (0%; 0%–10%) | 33/45 (73%; 59%–84%) | 7 | 0 |
| Jev-reviewer | 12/12 (100%; 76%–100%) | 0/33 (0%; 0%–10%) | 23/45 (51%; 37%–65%) | 0 | 0 |
| R2-reviewer | 12/12 (100%; 76%–100%) | 0/33 (0%; 0%–10%) | 33/45 (73%; 59%–84%) | 4 | 0 |

## Paired tests (exact McNemar on per-answer correctness; b = ref right & arm wrong, c = ref wrong & arm right)

| Arm | vs | b / c | p |
|---|---|---|---|
| G-base | investigator (v1 A/C) | 9 / 0 | 0.004 |
| G-ft | investigator (v1 A/C) | 2 / 4 | 0.688 |
| H-hosted | investigator (v1 A/C) | 0 / 0 | 1.000 |
| H-stack | investigator (v1 A/C) | 0 / 0 | 1.000 |
| Jev-reviewer | investigator (v1 A/C) | 10 / 0 | 0.002 |
| R2-reviewer | investigator (v1 A/C) | 0 / 0 | 1.000 |
| investigator (v1 A/C) | G-base | 0 / 9 | 0.004 |
| G-ft | G-base | 2 / 13 | 0.007 |
| H-hosted | G-base | 0 / 9 | 0.004 |
| H-stack | G-base | 0 / 9 | 0.004 |
| Jev-reviewer | G-base | 1 / 0 | 1.000 |
| R2-reviewer | G-base | 0 / 9 | 0.004 |

## Per-cell actions (benign-supported cells, where over-escalation lives)

| run | label | investigator (v1 A/C) | G-base | G-ft | H-hosted | H-stack | Jev-reviewer | R2-reviewer |
|---|---|---|---|---|---|---|---|---|
| A S07 C1 | benign | collect_more | collect_more | close | collect_more | collect_more | collect_more | collect_more |
| A S08 C1 | benign | collect_more | collect_more | collect_more | collect_more | collect_more | collect_more | collect_more |
| A S10 C1 | benign | collect_more | collect_more | close | collect_more | collect_more | collect_more | collect_more |
| A S12 C1 | benign | escalate | collect_more | collect_more | collect_more | collect_more | collect_more | collect_more |
| A S12 C2 | benign | escalate | collect_more | close | escalate | escalate | collect_more | escalate |
| A S12 C3 | benign | escalate | collect_more | escalate | escalate | escalate | collect_more | collect_more |
| C S07 C1 | benign | escalate | collect_more | escalate | escalate | escalate | collect_more | escalate |
| C S08 C1 | benign | collect_more | collect_more | collect_more | collect_more | collect_more | collect_more | collect_more |
| C S10 C1 | benign | escalate | collect_more | escalate | escalate | escalate | collect_more | collect_more |
| C S12 C1 | benign | escalate | collect_more | close | escalate | escalate | collect_more | escalate |
| C S12 C2 | benign | escalate | collect_more | escalate | escalate | escalate | collect_more | escalate |
| C S12 C3 | benign | escalate | collect_more | escalate | escalate | escalate | collect_more | collect_more |
