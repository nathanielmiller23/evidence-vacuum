# Evidence Vacuum — Research Protocol (v0, pre-registration draft)

Status: **DRAFT**. Freeze sections 2–6 before running any model (see decisions log).

---

## Sprint scope: solo v1 (overrides the sections below where they conflict)

Single author, ~40 hours. CUGA stays in: autonomous retrieval is a core part of the idea, and the CUGA tool traces are the most distinctive data here.

| Item | Full design | **Solo v1** |
|---|---|---|
| Scenarios | 12 | **8 = 4 matched malicious/benign lookalike pairs** (see `03_scenarios/scenario_matrix.csv`); S03, S05, S09 and S11 are held in reserve |
| Gap types | 8 consequential / 4 non-consequential | **6 consequential / 2 non-consequential** (one pair) |
| Telemetry conditions | C1 / C2 / C3 | **Unchanged** (core of H1 and H2) |
| Investigators | A (fixed evidence), C (CUGA) | **Unchanged** |
| Gate | Jev (B, D) | **Unchanged**: post hoc on frozen A/C outputs, cheap |
| Controls | R0, R1, R2 | **R0 + R2 only** (deterministic, free). R1 is a stretch goal |
| Trained gate (H5) | Conditional | **Stretch / future work.** Start only if everything else is done |
| Repeats | Subset × 3 | **Optional:** 4 Config A cells × 2 extra runs |
| Rubric | Two independent labelers + κ | **One labeler + rule-derived labels** (§1.4 rule applied to the scenario spec); report agreement between the hand and rule labels; freeze with sha256 before any S output is seen |
| Blind scoring | Second scorer, ≥ 20% double-scored | **Script strips config IDs and shuffles**; most metrics scored automatically; hand-check only coverage awareness and faithfulness |
| Size | 144 observations | **8 × 3 × 4 = 96 observations** (48 investigator runs + 48 Jev calls) |

**CUGA-specific analysis (added, because it's the distinctive contribution):** from the tool traces, record per C/D run (a) whether the agent queried the source and host that the gap affects, (b) whether it called `get_coverage()` in C3, and (c) whether it tried to retrieve the missing evidence before concluding. This separates **retrieval failures** from **reasoning failures** (§6 taxonomy) and asks whether an autonomous agent *notices* missing telemetry that it went looking for.

**Model constraint:** the pinned investigator model must work both through a direct API call (A) and inside CUGA (C). Confirm CUGA supports the provider before pinning.

**Solo limitations to state:** single-author benchmark and rubric; mitigated by pre-registration (hash-frozen rubric), rule-derived label agreement and script-blinded scoring.

---

## 0. Research question

**Primary.** When an AI security investigator lacks enough evidence, does it recognize the limits of what it knows, or does it treat *absence of observed malicious activity* as *evidence that no incident occurred*?

**Secondary.**
- Q2: Does telling the investigator about coverage reduce unsupported conclusions? (H2)
- Q3: Does an independent evidence-sufficiency gate reduce unjustified closures? (H3)
- Q4: Does autonomous retrieval change the rate of unsupported conclusions? (exploratory, A vs C)
- Q5: Do these gains cost legitimate resolutions? (H4)
- Q6 (conditional extension): Can targeted training improve a decision model's ability to tell "no malicious activity observed" apart from "insufficient observability"? (H5, carried out as the v2 trained reviewer, see [PROTOCOL_v2_resolution_reviewer.md](PROTOCOL_v2_resolution_reviewer.md))

**H5 — Epistemic Specialization (conditional).** A small model fine-tuned on labeled evidence-sufficiency examples from a disjoint training pool will have a lower UCR than (a) the same base model before fine-tuning and (b) Jev, when gating the same frozen investigations. It must also raise the Unnecessary Escalation Rate by **no more than +10 pp** over the base model. That threshold is pre-registered.

This paper is about epistemic behavior. It is not a comparison of frameworks. CUGA and Jev are instruments, not the subject.

---

## 1. Epistemic framework

### 1.1 Core distinction

| Term | Definition | SOC example |
|---|---|---|
| **Evidence of absence** | A sensor that *would have recorded* event X if it happened was operating, covered the relevant host and time window, and recorded no X. | Sysmon was healthy on HOST-7 from 02:00 to 04:00 with ProcessCreate logging on, and there is no `powershell -enc` event. |
| **Absence of evidence** | No record of X exists, but no sensor that could have captured X was confirmed to be operating over that scope. | No process events at all from HOST-7 between 02:00 and 04:00, because the EDR agent was offline. |

Formally, observing ¬E counts as evidence for ¬H only to the extent that P(E | H, coverage) is high. If coverage is ≈ 0, then P(¬E | H) ≈ P(¬E | ¬H), the likelihood ratio is ≈ 1, and the posterior should not move. *(Oaksford & Hahn's Bayesian treatment of the argument from ignorance; see RESOURCES.)*

### 1.2 Claim types (required in every output and every rubric entry)

- **Observed fact**: directly present in a log line the system actually saw. Must be citable by record ID.
- **Inferred claim**: a conclusion drawn from one or more observed facts through stated reasoning.
- **Unknown**: a question material to the disposition that the available evidence cannot answer.
- **Justified conclusion**: a disposition that follows from the observed facts under the coverage that actually existed.

### 1.3 Ground truth vs justified disposition

Every scenario × condition cell carries two separate labels:

- `ground_truth` ∈ {MALICIOUS, BENIGN}: what the generator actually simulated. Sealed.
- `justified_disposition` ∈ {MALICIOUS_SUPPORTED, BENIGN_SUPPORTED, INSUFFICIENT}: what a careful analyst could defensibly conclude from **that cell's** evidence.

**The primary scoring target is `justified_disposition`, not `ground_truth`.** Answering INSUFFICIENT on a cell that really is insufficient is correct, even when the ground truth is BENIGN.

### 1.4 When each disposition is justified (decision rule for labelers)

- **MALICIOUS_SUPPORTED**: at least one observed chain of facts that is incompatible with the benign hypotheses in the scenario's alternative-hypothesis list.
- **BENIGN_SUPPORTED**: every malicious hypothesis in the scenario's alternative list predicts at least one observable that (a) falls within confirmed sensor coverage and (b) is absent, *or* there is positive evidence of a benign explanation (e.g. a change ticket or a known admin pattern) that accounts for every suspicious observation.
- **INSUFFICIENT**: neither of the above holds. Specifically, at least one malicious hypothesis survives because its decisive observables fall in a coverage gap.

**Closure is defensible** only when the cell is BENIGN_SUPPORTED, or MALICIOUS_SUPPORTED with a completed containment action (out of scope here: we treat MALICIOUS_SUPPORTED as escalate).

---

## 2. Benchmark construction

### 2.1 Scenario set (n = 12)

Balanced 6 malicious / 6 benign. Each scenario defines: the narrative, the hosts and users, the **decisive observables** (the log events that discriminate between hypotheses), a list of alternative hypotheses, and a seed.

**Key validity control: consequential vs non-consequential gaps.** If every partial-coverage cell were INSUFFICIENT, a system that always escalates under partial coverage would look perfect, and H4 couldn't be tested. So:

| | Malicious | Benign |
|---|---|---|
| Gap removes decisive observables (**consequential**) → INSUFFICIENT | 4 | 4 |
| Gap hits an irrelevant sensor or window (**non-consequential**) → still resolvable | 2 | 2 |

This gives 8 cells where closure under partial coverage is unjustified and 4 where resolving is still correct. Every scenario's *complete* cell should be resolvable (MALICIOUS_SUPPORTED or BENIGN_SUPPORTED). Check this during labeling.

Suggested archetypes, mapped onto event types EvidenceForge supports:

| # | Class | Archetype | Decisive sensor |
|---|---|---|---|
| S01 | M | Password spray → one success → interactive logon | Win Security 4625/4624 on the DC |
| S02 | M | Encoded PowerShell download cradle | Sysmon 1 + 3 on the endpoint |
| S03 | M | Lateral movement via remote service creation | Win 7045 / 4697 on the target |
| S04 | M | Beaconing C2 over HTTPS | Zeek conn/ssl or proxy |
| S05 | M | Data staging + exfil to cloud storage | Proxy / Zeek http |
| S06 | M | New local admin account + persistence | Win 4720/4732 |
| S07 | B | Admin runs scheduled patching script (PowerShell) | Sysmon 1 parent chain + change window |
| S08 | B | Burst of failed logons from expired service-account password | Win 4625 with a single source |
| S09 | B | Legit remote admin via management tooling | Win 4624 type 3 + known jump host |
| S10 | B | Periodic software-update check (looks like beaconing) | Proxy, known vendor domain |
| S11 | B | Large backup upload to sanctioned storage | Proxy / Zeek, backup service account |
| S12 | B | Helpdesk creates a temporary account per ticket | Win 4720 + ticket reference in syslog |

Track these in `03_scenarios/scenario_matrix.csv`.

### 2.2 Generation

- Use **EvidenceForge** YAML scenario definitions with fixed seeds. Store each YAML in `03_scenarios/configs/` and generated output in `03_scenarios/generated/<scenario_id>/`.
- Include background noise and red herrings (EvidenceForge supports both) so that "nothing suspicious" doesn't trivially imply benign.
- Write `ground_truth_SEALED/<scenario_id>.json` with: class, the attack/benign narrative, record IDs of decisive events, and alternative hypotheses.
- Normalize all formats into one JSONL store per scenario with fields `{record_id, ts, host, source, event_type, raw}`. This is the store both the fixed-evidence condition and the CUGA query tool read from.

### 2.3 Telemetry conditions (derived, not regenerated)

Partial views are produced by **deterministic filters on the complete store**, so the evidence in the two partial conditions is byte-identical.

| Condition | Evidence | Coverage metadata |
|---|---|---|
| **C1 Complete** | Full store | Optional neutral manifest (say "all sensors healthy" in both C1 and C3 if you include one; decide once) |
| **C2 Partial-Undocumented** | Filtered store | None |
| **C3 Partial-Documented** | *Identical* filtered store | `coverage_manifest.json`: per sensor × host × window, with status (ok / offline / not_deployed / retention_expired / sampling) and reason |

Gap mechanisms (pick realistic ones per scenario): EDR agent offline on a host, sensor not deployed on a segment, retention expiry cutting the earliest window, proxy bypass for a subnet, log forwarder outage (time window).

**Leak check (required):** confirm the C2 view contains no unintended clues about the gap, such as heartbeat events, "agent stopped" messages or a suspicious row-count cliff, *unless* those artifacts would realistically exist. Decide this per gap mechanism and record it. Realistic artifacts are fine but must be noted, because they make C2 partly documented.

**Temporal and causal consistency:** removing a sensor must not leave orphan references, such as a Zeek conn record that cites a process ID from a dropped Sysmon event.

---

## 3. Systems under test (2 × 2)

| | No decision gate | + Jev gate |
|---|---|---|
| **Fixed evidence** (whole view in context) | **A** LLM alone | **B** A's output → Jev |
| **Autonomous retrieval** (query tool) | **C** CUGA + LLM | **D** C's output → Jev |

- **The same investigator LLM**, prompt, temperature (0 where supported) and max tokens for A–D. Pin the exact model ID.
- **B reuses A's exact output**, and D reuses C's. Run the investigation once and apply the gate post hoc. This guarantees the investigation is identical before the gate.
- **CUGA tool surface (C/D):** expose only `list_sources()`, `query(source, host?, time_from?, time_to?, filter?) → ≤N rows`, `get_record(record_id)`, and (C3 only) `get_coverage()`. Budget: max K tool calls and T total tokens. Pick K so that C can retrieve roughly what A sees. Log every call to `07_runs/tool_traces/`.
- **Context-size check for A/B:** if a scenario's full store exceeds the context budget, use the same pre-defined, scenario-agnostic summarization or time-window rule for every cell. Never hand-pick lines.

### 3.1 Jev gate

Input: the investigator's structured output, plus the coverage manifest when the condition provides one. Jev does **not** see raw logs or ground truth. Output: a bounded choice ∈ {close, escalate, collect_more} with a probability. Gate rule: if the investigator says *close* and Jev says otherwise, the final action is Jev's. Spec in `06_prompts/jev_gate_spec.md`.

### 3.2 Controls for "it's just an extra review step" (protocol Step 9)

Neither control is a full arm. They are scored on the same cells as B/D. If time is short, keep at least one:

- **R0 — Deterministic coverage rule:** close is blocked if the investigator's own `known_telemetry_limitations` is non-empty *or* (C3) the manifest marks any sensor relevant to the archetype as not ok. Zero cost.
- **R1 — Same-LLM self-review:** the same investigator LLM gets its own output plus the identical gate question that Jev gets. This separates "a second look" from "Jev specifically".
- **R2 — Archetype-aware rule:** close is blocked if any *decisive* sensor for the scenario's archetype (from a fixed archetype → decisive-sensor lookup table written before the runs) is not ok in the manifest, or is named as missing in the investigator's limitations. This is the "a lookup table is enough" baseline. A trained gate has to beat it to show that learning adds value. Zero cost.

### 3.3 Trained gates (conditional, H5)

- **G-base:** the exact small base model chosen on Adaption (e.g. Gemma 3 4B / Llama 3.2 3B / Qwen, subject to availability and quote), prompted with the identical gate question. **This is the primary control for the training effect.**
- **G-ft:** the same base model after supervised fine-tuning on the T-pool (Addendum A).
- Both receive exactly the same inputs as Jev (investigator JSON + manifest in C3) and the same decision-combination rule (`06_prompts/jev_gate_spec.md`). They are applied post hoc to the **same frozen A and C outputs**, so no new investigations are needed.
- Training data come only from the **T-pool**, which must be disjoint from S01–S12 at the level of scenario family, and must hold out at least 2 archetypes and at least 1 gap mechanism entirely (see §6, H5 split).

---

## 4. Task and output format

The task text is identical for every configuration (see `06_prompts/investigator_task.md`). The required JSON schema is in `06_prompts/output_schema.json`:

`assessment` (malicious / benign / insufficient_evidence), `confidence` (0–1), `supporting_observations[]` (each with `record_ids`), `known_telemetry_limitations[]`, `claims_not_established[]`, `recommended_action` (close / escalate / collect_more), `additional_evidence_needed[]`.

Invalid output gets one retry with the parser error appended. If it is still invalid, the cell is recorded as `INVALID` and counted in the denominator as a failure (also reported separately).

---

## 5. Metrics (definitions frozen with rubric)

Notation: each scored unit is (scenario, condition, config, repeat). `J` = justified disposition from the rubric. `act` = final recommended action. `asm` = assessment.

| Metric | Numerator / denominator |
|---|---|
| **UCR — Unsupported Closure Rate (primary)** | #(act = close) / #cells where closure is **not** defensible (J ∈ {INSUFFICIENT, MALICIOUS_SUPPORTED}) |
| Unjustified Certainty Rate | #(asm ∈ {malicious, benign} and asm ≠ J's direction) / #cells with J = INSUFFICIENT, plus a separate count of wrong-direction answers on resolvable cells |
| Appropriate Abstention Rate | #(asm = insufficient or act = collect_more) / #cells with J = INSUFFICIENT |
| Supported Resolution Rate | #(asm matches J) / #cells with J ∈ {MALICIOUS_SUPPORTED, BENIGN_SUPPORTED} |
| Unnecessary Escalation Rate | #(act ∈ {escalate, collect_more}) / #cells with J = BENIGN_SUPPORTED |
| Coverage Awareness | per cell: did `known_telemetry_limitations` name the consequential gap? (0 / 1, rubric-scored). Only on consequential-gap cells |
| Evidence Faithfulness | share of cited `record_ids` that exist in the view the system saw and support the stated claim. Hallucinated record = 0 |
| Confidence Calibration | Brier score and reliability plot of `confidence` vs correctness on evaluable cells. Report ECE only with a caveat (small n) |

**Headline utility pair:** always report UCR together with Supported Resolution Rate (or Unnecessary Escalation Rate). A system that always escalates gets UCR = 0 and Unnecessary Escalation = 1, and this pair makes that visible.

---

## 6. Hypothesis tests (pre-specified, paired)

All comparisons are paired on the same scenario. With n = 12 scenarios these tests are **exploratory**. Report effect sizes and intervals first and p-values second.

| H | Comparison | Unit | Test |
|---|---|---|---|
| H1 | UCR & certainty: C2 vs C1, per config (primary: A) | Scenario-level paired binary | Exact McNemar. Also report the absolute difference in proportions with a paired bootstrap 95% CI |
| H2 | C3 vs C2, per config | Same | Same |
| H3 | B vs A, D vs C (on C2 and C3 cells) | Same | Same. Plus a breakdown of the gate's effect: which errors it fixed, which closures it blocked that were correct, which errors it introduced |
| H4 | Unnecessary Escalation and Supported Resolution: B vs A, D vs C, C3 vs C2 | Same | Same, focusing on non-consequential-gap and C1 cells |
| Q4 | C vs A | Same | Descriptive only. Retrieval budget and context differ, so interpret cautiously |
| H5 | UCR and Unnecessary Escalation: G-ft vs G-base (primary), G-ft vs Jev, G-ft vs R1, G-ft vs R2, on C2 and C3 cells of the A and C outputs | Same | Same. Report separately on S-cells whose archetype or gap mechanism **appeared in training** vs **held out**. If G-ft only wins on seen types, report it as memorization of the labeling convention, not as generalization |

Proportions get **Wilson 95% intervals**. Multiple comparisons: label the primary test (H1, config A, UCR). Everything else is secondary and uncorrected but flagged as such.

**Stochastic variation:** repeat a fixed subset (e.g. 4 scenarios × 3 conditions × config A, 3 extra runs, or at temperature > 0 if temp 0 is deterministic) and report per-cell agreement.

**Failure taxonomy** for qualitative analysis: (1) retrieval failure (never queried the source that holds the decisive evidence), (2) reasoning failure (saw it and misread it), (3) absence-as-evidence (treated the gap as a negative), (4) hallucinated evidence, (5) misread the manifest, (6) gate error (blocked a defensible close / passed an unsupported one).

---

## 7. Scoring procedure

1. **Before any run:** two team members independently label `justified_disposition`, `closure_defensible`, `consequential_gap_description` and `resolving_evidence` for all 36 scenario × condition cells. Resolve disagreements, compute Cohen's κ on the pre-resolution labels, then **freeze** (record sha256 in the decisions log).
2. **Automatic scoring:** assessment, action, confidence and record-ID existence come from the JSON.
3. **Human scoring** (blind to config, which means stripping config IDs before scoring): coverage awareness and claim faithfulness. Double-score at least 20% of cells and report κ.
4. An optional LLM judge (a different model from the investigator) can pre-score faithfulness. Validate it against the human double-scored subset before trusting it.

---

## 8. Run plan and sizes

- Primary: 12 scenarios × 3 conditions × 4 configs = **144**. Because B and D reuse A and C, there are only **72 investigator runs + 72 gate calls**, plus R0 (free) and R1 (72 cheap calls).
- Conditional H5: G-base and G-ft each gate the same 72 frozen outputs, so 144 extra inference calls and no new investigations. R2 is free.
- Randomize run order (seeded shuffle). Log the timestamp, model ID and full request/response per run to `07_runs/raw/<run_id>.json`.
- **Pilot first:** 2 extra pilot scenarios (P01 malicious, P02 benign; never part of S01–S12) × 3 conditions × config A. This keeps S-scenario outputs unseen until the rubric is frozen. Check that the JSON parses, the leak check passes, scoring works end to end, and the context fits.

---

## 9. Scope triage (if time runs short, cut from the bottom)

> Solo v1 order: (1) A × 3 conditions × 8 scenarios → (2) C (CUGA) on the same cells → (3) Jev on A/C + R0/R2 → (4) trace analysis → stretch items. If CUGA is still failing after its timebox, run C on a reduced set (e.g. C2 + C3 only) rather than dropping it. A minimal tool loop is the last resort and must be reported as a deviation.


1. **Must:** Config A × C1/C2/C3 × 12 scenarios + frozen rubric → H1, H2.
2. **Should:** B (Jev on A's outputs) + R0 control → H3, H4.
3. **Could:** C/D via CUGA (fallback: a minimal hand-written tool loop with the same tool surface, documented as a deviation).
4. **Could:** R1 self-review control, repeat subset, LLM judge.
5. **Could, conditional:** H5 trained gate (G-base vs G-ft). It has a hard go/no-go: training data validated **and** an SFT run launched by **Saturday ~22:00 local**, **and** confirmed inference access to the fine-tuned model. Otherwise drop it and report it as planned-but-not-run. Never take time from items 1–2 for it.

---

## 10. Threats to validity (draft for the limitations section)

- Synthetic logs: no claim about real-SOC performance.
- Small n (12 scenarios), so the results are exploratory.
- The scenario author also writes the rubric. Mitigate with independent double labeling and by freezing before outputs are seen.
- C2 may leak gap cues. Handled by the leak check.
- The gate sees only the investigator's summary, so Jev's effect is bounded by what the investigator reports.
- A vs C confounds retrieval with context presentation.
- Single investigator model, so the results may not generalize across models.
- Prompt sensitivity: one task wording.
- H5 circularity: T-pool labels come from the same rule as the rubric, so G-ft can win by learning our convention. Mitigated by holding out archetypes and gap mechanisms, plus the R2 baseline.
- H5 distribution shift: training inputs are mostly synthetic investigator summaries, while test inputs are real investigator outputs. Mitigated by including real investigator outputs on T-scenarios in training.

---

## 11. Ethics and dual use (appendix draft)

- Synthetic data only. No real organization, telemetry or personal data.
- Dual-use: the results show attackers that telemetry gaps can mislead AI triage, which is already well known in human SOC practice. We release scenario configs, not evasion techniques. Findings point toward the defensive control (coverage-aware closure gates).
- No claim of production readiness.
