# Evidence Vacuum: scored results

Runs scored: 48 investigations; rows: 192 (run × layer). Invalid/error investigator runs: 3.

## Main metrics (pooled over conditions), Wilson 95% CI

| Layer | Unsupported closure (UCR) | Supported resolution | Unnecessary escalation | Unjustified certainty | Appropriate abstention |
|---|---|---|---|---|---|
| A | 0/18 (0%; 0%–18%) | 6/12 (50%; 25%–75%) | 6/6 (100%; 61%–100%) | 2/12 (17%; 5%–45%) | 10/12 (83%; 55%–95%) |
| B | 0/18 (0%; 0%–18%) | 6/12 (50%; 25%–75%) | 6/6 (100%; 61%–100%) | 2/12 (17%; 5%–45%) | 10/12 (83%; 55%–95%) |
| A+R0 | 0/18 (0%; 0%–18%) | 6/12 (50%; 25%–75%) | 6/6 (100%; 61%–100%) | 2/12 (17%; 5%–45%) | 10/12 (83%; 55%–95%) |
| A+R2 | 0/18 (0%; 0%–18%) | 6/12 (50%; 25%–75%) | 6/6 (100%; 61%–100%) | 2/12 (17%; 5%–45%) | 10/12 (83%; 55%–95%) |
| C | 0/18 (0%; 0%–18%) | 4/12 (33%; 14%–61%) | 6/6 (100%; 61%–100%) | 1/12 (8%; 1%–35%) | 10/12 (83%; 55%–95%) |
| D | 0/18 (0%; 0%–18%) | 4/12 (33%; 14%–61%) | 6/6 (100%; 61%–100%) | 1/12 (8%; 1%–35%) | 10/12 (83%; 55%–95%) |
| C+R0 | 0/18 (0%; 0%–18%) | 4/12 (33%; 14%–61%) | 6/6 (100%; 61%–100%) | 1/12 (8%; 1%–35%) | 10/12 (83%; 55%–95%) |
| C+R2 | 0/18 (0%; 0%–18%) | 4/12 (33%; 14%–61%) | 6/6 (100%; 61%–100%) | 1/12 (8%; 1%–35%) | 10/12 (83%; 55%–95%) |

## By condition (investigator layers A and C)

| Layer | Cond | Closed | UCR | Supported resolution | Unjustified certainty | Disposition correct | Coverage mentioned (auto) |
|---|---|---|---|---|---|---|---|
| A | C1 | 0/8 (0%; 0%–32%) | 0/4 (0%; 0%–49%) | 4/8 (50%; 22%–78%) | – | 4/8 (50%; 22%–78%) | – |
| A | C2 | 0/8 (0%; 0%–32%) | 0/7 (0%; 0%–35%) | 1/2 (50%; 9%–91%) | 1/6 (17%; 3%–56%) | 6/8 (75%; 41%–93%) | 0/6 (0%; 0%–39%) |
| A | C3 | 0/8 (0%; 0%–32%) | 0/7 (0%; 0%–35%) | 1/2 (50%; 9%–91%) | 1/6 (17%; 3%–56%) | 6/8 (75%; 41%–93%) | 6/6 (100%; 61%–100%) |
| B | C1 | 0/8 (0%; 0%–32%) | 0/4 (0%; 0%–49%) | 4/8 (50%; 22%–78%) | – | 4/8 (50%; 22%–78%) | – |
| B | C2 | 0/8 (0%; 0%–32%) | 0/7 (0%; 0%–35%) | 1/2 (50%; 9%–91%) | 1/6 (17%; 3%–56%) | 6/8 (75%; 41%–93%) | 0/6 (0%; 0%–39%) |
| B | C3 | 0/8 (0%; 0%–32%) | 0/7 (0%; 0%–35%) | 1/2 (50%; 9%–91%) | 1/6 (17%; 3%–56%) | 6/8 (75%; 41%–93%) | 6/6 (100%; 61%–100%) |
| C | C1 | 0/8 (0%; 0%–32%) | 0/4 (0%; 0%–49%) | 3/8 (38%; 14%–69%) | – | 3/8 (38%; 14%–69%) | – |
| C | C2 | 0/8 (0%; 0%–32%) | 0/7 (0%; 0%–35%) | 0/2 (0%; 0%–66%) | 1/6 (17%; 3%–56%) | 5/8 (62%; 31%–86%) | 4/6 (67%; 30%–90%) |
| C | C3 | 0/8 (0%; 0%–32%) | 0/7 (0%; 0%–35%) | 1/2 (50%; 9%–91%) | 0/6 (0%; 0%–39%) | 6/8 (75%; 41%–93%) | 4/5 (80%; 38%–96%) |
| D | C1 | 0/8 (0%; 0%–32%) | 0/4 (0%; 0%–49%) | 3/8 (38%; 14%–69%) | – | 3/8 (38%; 14%–69%) | – |
| D | C2 | 0/8 (0%; 0%–32%) | 0/7 (0%; 0%–35%) | 0/2 (0%; 0%–66%) | 1/6 (17%; 3%–56%) | 5/8 (62%; 31%–86%) | 4/6 (67%; 30%–90%) |
| D | C3 | 0/8 (0%; 0%–32%) | 0/7 (0%; 0%–35%) | 1/2 (50%; 9%–91%) | 0/6 (0%; 0%–39%) | 6/8 (75%; 41%–93%) | 4/5 (80%; 38%–96%) |

## Paired comparisons (scenario-level; exact McNemar; paired bootstrap 95% CI of the difference)

Outcome `wrong_action` = final action differs from the justified action (escalate for MALICIOUS_SUPPORTED, close for BENIGN_SUPPORTED, not-close for INSUFFICIENT). Also reported: `unsupported_closure` and `definitive`.

| Hypothesis | Comparison | Outcome | x mean | y mean | diff (95% CI) | b / c | p (exact) |
|---|---|---|---|---|---|---|---|
| H1 (primary) | A-C1 → A-C2 (n=8) | unsupported_closure | 0.00 | 0.00 | +0.00 (+0.00, +0.00) | 0 / 0 | 1.000 |
| H1 | A-C1 → A-C2 (n=8) | definitive | 0.50 | 0.38 | -0.12 (-0.62, +0.38) | 3 / 2 | 1.000 |
| H1 | C-C1 → C-C2 (n=8) | unsupported_closure | 0.00 | 0.00 | +0.00 (+0.00, +0.00) | 0 / 0 | 1.000 |
| H1 | A-C1 → A-C2 (n=8) | wrong_action | 0.50 | 0.12 | -0.38 (-0.75, -0.12) | 3 / 0 | 0.250 |
| H2 | A-C2 → A-C3 (n=8) | unsupported_closure | 0.00 | 0.00 | +0.00 (+0.00, +0.00) | 0 / 0 | 1.000 |
| H2 | A-C2 → A-C3 (n=8) | definitive | 0.38 | 0.25 | -0.12 (-0.50, +0.25) | 2 / 1 | 1.000 |
| H2 | C-C2 → C-C3 (n=8) | definitive | 0.25 | 0.12 | -0.12 (-0.50, +0.25) | 2 / 1 | 1.000 |
| H2 | A-C2 → A-C3 (n=6) | coverage_mentioned_auto | 0.00 | 1.00 | +1.00 (+1.00, +1.00) | 0 / 6 | 0.031 |
| H2 | C-C2 → C-C3 (n=5) | coverage_mentioned_auto | 0.60 | 0.80 | +0.20 (-0.40, +0.80) | 1 / 2 | 1.000 |
| H3/H4 | A-C1 → B-C1 (n=8) | wrong_action | 0.50 | 0.50 | +0.00 (+0.00, +0.00) | 0 / 0 | 1.000 |
| H3/H4 | C-C1 → D-C1 (n=8) | wrong_action | 0.62 | 0.62 | +0.00 (+0.00, +0.00) | 0 / 0 | 1.000 |
| H3/H4 | A-C2 → B-C2 (n=8) | wrong_action | 0.12 | 0.12 | +0.00 (+0.00, +0.00) | 0 / 0 | 1.000 |
| H3/H4 | C-C2 → D-C2 (n=8) | wrong_action | 0.25 | 0.25 | +0.00 (+0.00, +0.00) | 0 / 0 | 1.000 |
| H3/H4 | A-C3 → B-C3 (n=8) | wrong_action | 0.12 | 0.12 | +0.00 (+0.00, +0.00) | 0 / 0 | 1.000 |
| H3/H4 | C-C3 → D-C3 (n=8) | wrong_action | 0.25 | 0.25 | +0.00 (+0.00, +0.00) | 0 / 0 | 1.000 |
| Q4 | A-C1 → C-C1 (n=8) | wrong_action | 0.50 | 0.62 | +0.12 (+0.00, +0.38) | 0 / 1 | 1.000 |
| Q4 | A-C2 → C-C2 (n=8) | wrong_action | 0.12 | 0.25 | +0.12 (+0.00, +0.38) | 0 / 1 | 1.000 |
| Q4 | A-C3 → C-C3 (n=8) | wrong_action | 0.12 | 0.25 | +0.12 (+0.00, +0.38) | 0 / 1 | 1.000 |

## Gate breakdown (closures only; a gate can only block a close)

| Base | Gate | Closes proposed | Unsupported closes blocked | Justified closes blocked | Unsupported closes passed |
|---|---|---|---|---|---|
| A | jev | 0 | 0 | 0 | 0 |
| A | r0 | 0 | 0 | 0 | 0 |
| A | r2 | 0 | 0 | 0 | 0 |
| C | jev | 0 | 0 | 0 | 0 |
| C | r0 | 0 | 0 | 0 | 0 |
| C | r2 | 0 | 0 | 0 | 0 |

## Calibration and faithfulness (investigator layers)

- **A**: Brier (confidence vs disposition correct) = 0.251 over 24 runs; mean confidence = 0.91; fabricated record IDs = 0/442 cited.
- **C**: Brier (confidence vs disposition correct) = 0.293 over 21 runs; mean confidence = 0.85; fabricated record IDs = 0/258 cited.

## CUGA traces (Config C)

| Cond | Mean tool calls | Zero-tool runs | Called get_coverage | Queried a gapped source |
|---|---|---|---|---|
| C1 | 14.4 | 1/8 | 0/8 | 7/8 |
| C2 | 13.8 | 1/8 | 0/8 | 7/8 |
| C3 | 11.6 | 1/8 | 6/8 | 6/8 |
