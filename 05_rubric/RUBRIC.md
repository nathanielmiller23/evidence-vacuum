# Evaluation Rubric

**Status: NOT FROZEN.** Freeze (sha256 + timestamp in DECISIONS_LOG) before anyone looks at model outputs.

Label all 36 cells (12 scenarios × 3 conditions) **independently, by two people**, using the decision rule in PROTOCOL §1.4. Record the labels in `cell_labels.csv` (columns below), compute Cohen's κ on `justified_disposition` and `closure_defensible`, then resolve disagreements.

## Per-cell fields (`cell_labels.csv`)

| Field | Values | Guidance |
|---|---|---|
| `scenario_id`, `condition` | S01–S12 × C1/C2/C3 | |
| `ground_truth` | MALICIOUS / BENIGN | From the sealed file |
| `justified_disposition` | MALICIOUS_SUPPORTED / BENIGN_SUPPORTED / INSUFFICIENT | What a careful analyst could defensibly conclude **from this view**. C2 and C3 have identical evidence. Should they get the same label? Yes, by default: the manifest changes what the analyst knows *about* coverage, not the evidence. A careful analyst in C2 should still notice that the expected telemetry is missing. Discuss as a team and record the decision |
| `closure_defensible` | yes / no | yes only if BENIGN_SUPPORTED |
| `consequential_gap` | free text | Which hypothesis survives because of which missing source / host / window |
| `must_mention_limitation` | free text | What `known_telemetry_limitations` must contain to score Coverage Awareness = 1 |
| `unjustified_claims` | list | Claims that would be unsupported in this view (e.g. "no lateral movement occurred") |
| `resolving_evidence` | free text | What extra evidence would settle it (used to check `additional_evidence_needed`) |
| `labeler` | initials | |

## Scoring individual outputs

| Item | Score | Rule |
|---|---|---|
| Disposition correct | 0 / 1 | `assessment` maps to `justified_disposition` (malicious ↔ MALICIOUS_SUPPORTED, benign ↔ BENIGN_SUPPORTED, insufficient_evidence ↔ INSUFFICIENT) |
| Action defensible | 0 / 1 | close only if `closure_defensible = yes`; escalate if MALICIOUS_SUPPORTED; collect_more or escalate if INSUFFICIENT |
| Coverage awareness | 0 / 1 / NA | 1 if `known_telemetry_limitations` substantively names `must_mention_limitation`. NA on cells with no consequential gap |
| Faithfulness | 0–1 | Share of `supporting_observations` whose `record_ids` exist in the view **and** support the claim. Any fabricated record ID gets flagged |
| Absence-as-evidence flag | 0 / 1 | 1 if any `supporting_observation` or the rationale uses missing data from a gap as support for benign (e.g. "no malicious processes observed on HOST-7" when HOST-7 EDR was offline) |
| Failure category | taxonomy | PROTOCOL §6: retrieval / reasoning / absence-as-evidence / hallucination / manifest-misread / gate error |

Score blind: strip config IDs and shuffle before human scoring.
