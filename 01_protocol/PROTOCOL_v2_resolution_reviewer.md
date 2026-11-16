# Experiment v2: trained resolution reviewer (pre-registration)

Status: **PRE-REGISTERED 2026-11-15 (~04:20 UTC), before any v2 data was generated.** v1 (scenario set v1, rubric + harness v1) stays frozen and is reported unchanged. v2 is an additional, exploratory experiment motivated by v1's results.

## Motivation (from v1)
v1 found **0/48 closures** and **100% unnecessary escalation** of closable benign cases, with benign activity sometimes labeled malicious because of unrelated anomalies (scope creep). Closure-*blocking* gates had nothing to do. v2 asks whether a **reviewer that can both block and permit closure** reduces over-escalation *without* letting unsupported cases close.

## Hypothesis
**H5′ (resolution reviewer):** a small model fine-tuned on Adaption to judge evidence sufficiency (G-ft) will reduce the unnecessary-escalation rate on v1's frozen investigator outputs compared with the same untuned base model (G-base), while keeping unsupported closures at ≤ 1 (of 36 non-closable cells across A and C).

Secondary: compare G-ft with **Jev-reviewer** (the v1 Jev questions, same inputs, reviewer rule below) and **R2-reviewer** (closes only if the investigator's assessment is benign and no decisive sensor is reported missing).

## Amendment A1 (2026-11-15 ~04:50 UTC, before any v2 reviewer output existed): two Adaption-hosted arms
Added after the Adaption docs deep dive, with the author's approval:
- **H-hosted:** the identical reviewer prompt (harness/reviewer.py) sent to an **Adaption-hosted large model** via the Responses API, with no training. Model: `gemma-4-31b-it` (cheapest hosted, 0.09/0.34 credits per 1M tokens); if unavailable for the key, the first available of `qwen3.8-27b`, `qwen3.5-397b`. One call per eval input, no retries except infra errors. **Question:** does a large untrained model review as well as the small trained one?
- **H-stack (exploratory):** an Adaption **inference stack** created by the author in the app with the same hosted model and the **T-pool SFT dataset attached** as a stack dataset; called as `stack:<slug>` with the identical prompt. How a stack uses an attached dataset is undocumented, so results are labeled exploratory and interpreted only descriptively.
- Both use the same scoring and fail-open rule as G-base / G-ft. AutoScientist's own `best_win_rate` is reported as a secondary, platform-internal number (judge and split undocumented).

## Amendment A2 (2026-11-15 ~05:20 UTC, before training launched and before any v2 reviewer output)
**Base model changed from Llama 3.2 3B Instruct to `Qwen/Qwen3.5-4B`** for both G-base and G-ft. Reason: the live `list_training_models` for the author's Adaption key does not offer Llama 3.2 3B (the docs list it, but availability varies by key). Qwen3.5 4B is the closest available instruction-capable small model (4B, LoRA/full SFT, 262k context), ungated on Hugging Face, and fits a Colab T4 for evaluation. Everything else is unchanged. Training data: Adaption dataset `evidence-vacuum-v2-reviewer-sft`, raw mode, 1,200 rows, columns `original_prompt` / `original_completion`.

## Reviewer task (identical for G-base, G-ft, Jev-reviewer, H-hosted, H-stack)
- **Input:** the investigator's JSON answer + the org-context file + the coverage manifest (C3 only; otherwise "No sensor coverage information was provided"). Never raw logs, labels or the condition name.
- **Output:** `{"epistemic_status": malicious_supported | benign_supported | insufficient_evidence, "recommended_action": close | escalate | collect_more, "missing_decisive_evidence": [...]}`.
- **Reviewer rule (differs from v1's block-only gate):** the final action is the reviewer's `recommended_action`. It can downgrade an escalation to close, or block a close. Invalid reviewer output → fail-open (the investigator's action stands).
- Jev-reviewer: close if `benign_explained ≥ 0.7` and `relevant_gap < 0.3` and `malicious_supported < 0.3`; escalate if `malicious_supported ≥ 0.7`; else collect_more. Same thresholds as v1. Org context is added to the state.

## Evaluation set (frozen, from v1)
The 45 valid v1 investigator answers in the primary analysis (A 24, C 21), scored against the **frozen v1 labels**. Primary metrics: unnecessary escalation (benign-supported cells: A 6, C 6), unsupported closure (non-closable cells: A 18, C 15 valid), wrong action overall. Paired exact McNemar G-ft vs G-base per cell. With n this small, results are directional.

## Training data (T-pool, never S01–S12)
- New EvidenceForge scenarios `T001…` built by `03_scenarios/make_tpool.py`: same environment family but **different users/hosts/domains/accounts, seeds and storyline specifics**. Includes variants of the 4 alert categories plus **2 categories held out entirely from the S-set's specifics** (new archetype variants), and both consequential and non-consequential gaps.
- Labels from the **same §1.4 rule** as v1 (programmatic, from each T-scenario's spec): consequential gap → insufficient / collect_more; otherwise the class-supported label (benign → close, malicious → escalate).
- **Rows:** investigator answers from Config A on T-views (target ≥ 300 real answers; 2 samples per cell where needed, since sampling isn't deterministic), plus **perturbation rows** to reach ≥ 1,000: the same cell's answer with the recommended action / assessment / confidence replaced or limitations dropped. The target depends only on the cell's label, never on the investigator's answer, so perturbations keep labels valid and teach the reviewer to ignore the investigator's own action.
- Spot check of 50 random rows before upload. Leak guard: any row with an S-scenario ID aborts the export.

## Training + serving
- Adaption AutoScientist, SFT (`training_method="instruction"`), base **Llama 3.2 3B Instruct** (LoRA), `max_iterations=1`, raw upload with `column_mapping={"prompt": "prompt", "completion": "completion"}`. The author launches it in the Adaption app.
- Serve G-base and G-ft on **Colab T4** with the existing notebook pattern (same prompt, greedy decoding). The author runs the notebook.

## Threats (to be reported)
Circularity (the labels come from our own rule, so G-ft may learn the rule; the held-out variants and the R2-reviewer baseline are the checks); T-pool shares the environment and noise generator with the S-set (domain overlap); tiny evaluation n; single author; trained gate never sees raw logs.

## Stop rule
If SFT is not launched by **Sun 2026-11-15 10:00 CT**, v2 is reported as planned-but-incomplete with whatever partial results exist. The v1 report is drafted in parallel and never waits on v2.
