# Supplementary analysis: hand scoring + sensitivity reruns

## 1. Hand check of coverage awareness (step 6.1)
- Sheet: `hand_scoring_blind.csv` (45 valid investigator answers, setup names hidden and order shuffled). Single scorer, not independent.
- **Criterion:** the answer names at least one *decisive gapped source* (per `must_mention_limitation`) as missing or incomplete, rather than treating an empty result as negative evidence.
- **Auto-coder vs hand:** 16/23 agree, κ = 0.29. The auto-coder was too strict: it required explicit "not collected / missing" wording plus host and sensor, and missed answers that inferred incompleteness from the records ("records are non-contiguous", "only one auth record for the window", "no process-creation record"). It also had one false positive (H026: only DNS/TLS empties mentioned). **The hand scores replace the auto scores for coverage awareness.**

| | C2 (gap, no manifest) | C3 (gap + manifest) | Paired (n) | discordant b / c |
|---|---|---|---|---|
| A: gap noticed (hand) | 5/6 | 6/6 | 6 | 0 / 1 |
| C: gap noticed (hand) | 4/6 | 4/5 | 5 | 1 / 1 |
| A: gap precisely attributed (auto-style: names the outage/sensor/window) | 0/6 | 6/6 | 6 | 0 / 6 (exact p = 0.031) |

**Interpretation, which revises the auto-coded H2 claim:** without the manifest the investigator usually *notices* that the evidence is incomplete (A 5/6, C 4/6). The manifest mainly changes *how precisely* it explains the gap (attributing it to a named collection outage, sensor and window: 0/6 → 6/6 for A), not whether it notices. The earlier "0/6 vs 6/6" figure measures precise attribution, not awareness.

- **Absence-as-evidence:** 0/45 answers used missing records as positive evidence that nothing happened. Many explicitly caveated it ("empty results do not establish that no activity occurred").

## 2. Qualitative pattern behind the over-escalation (benign cells)
Benign scenarios were escalated (and sometimes called MALICIOUS) mostly because of **unrelated baseline activity that conflicts with the strict org context**, not because of the alerted activity. Examples: Google Drive / Dropbox / Slack / GlobalProtect / AnyConnect processes ("not an approved service"), tara.nguyen launching GPMC / RDP ("remote admin only from WS-KORTEGA-01"), a UserAssist entry decoding to powershell.exe, a SYSTEM 4648 for svc-reporting on WS-RIYER-01. In S08-C1 and S12-C1 the answers explicitly say the alerted activity *matches* the documented benign explanation, then still refuse to close because of other anomalies or missing proof of authorization. This is a **scope-creep / zero-tolerance** failure: any unexplained anomaly anywhere in the slice blocks resolution. It's also a design caveat: EvidenceForge's realistic noise plus a strict "nothing else is approved" context makes benign closure harder than in a curated benchmark.

## 3. Sensitivity reruns of the 3 failed CUGA cells (not in the primary analysis)
| Cell | Primary outcome | Rerun outcome (07_runs/reruns) | Label |
|---|---|---|---|
| S01-C1 | INVALID (empty answer, 0 tool calls) | malicious / escalate (13 calls) | MALICIOUS_SUPPORTED: correct |
| S06-C2 | INVALID (empty answer, 0 tool calls) | malicious / escalate (10 calls) | MALICIOUS_SUPPORTED: correct |
| S04-C3 | ERROR (OpenAI API timeout) | insufficient / collect_more (16 calls) | INSUFFICIENT: correct |

With reruns substituted, C's malicious detection on the complete view becomes 4/4 and C's supported resolution rises to 6/12. **No conclusion changes:** still 0 closures, so UCR = 0 and the gates are still untriggered. CUGA's operational failure rate (3/24 = 12.5% unusable runs in the primary pass, plus 1 valid run with 0 tool calls) is itself a reportable finding.
