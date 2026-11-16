# Experiment v3: cost-aware "ruthless optimization" (solo, one day)

Status: **PLAN, to be pre-registered (frozen with a sha256) at the end of Stage 0, before any v3 output is seen.** v1 and v2 stay frozen and are submitted first. v3 is a follow-up, or a short addendum if it finishes before the deadline (Mon Nov 16, 5:59 AM CT).

## 1. Question and scoreboard
Can a low-cost pipeline **resolve benign cases without ever closing on missing decisive evidence**?

- **Primary:** correct final action against the justified label, **subject to unsupported closures = 0** (a hard constraint, not a trade-off).
- **Secondary:** justified-closure rate (out of closable cases), false-malicious rate, unnecessary escalation, gap noticed, Brier score, cost per case ($ and credits), latency, failure rate.
- "Never close" gets 0 justified closures. It is the v1 baseline to beat, not a winner.

## 2. What v1/v2 taught us, and how each lesson shapes v3
| Lesson | Evidence | v3 consequence |
|---|---|---|
| The failure is calibration and scope, not capability | Gaps noticed, attacks caught, 12/12 benign cases escalated over unrelated noise; 31B reviewer identical to investigator | Fix scope in the prompt first; frontier model only as a $3 probe |
| Fine-tuning was the only lever that unlocked closures, and it also unlocked unsupported ones | G-ft: 4 justified, 2 unsupported (both benign truth, decisive logs missing) | Retrain with gap-contrastive pairs, **always** behind a gap check (paired control) |
| CUGA added cost and failure points without accuracy | 15/24 vs 18/24; 3/24 failed; zero-tool runs; six config fixes | **Dropped.** Logs fit in context, so retrieval isn't the bottleneck. CUGA's real test is big telemetry → v4 |
| Jev is a good narrow gate but a poor standalone reviewer, partly due to my untuned thresholds | v1: nothing to block; v2: 23/45, never approved a closure | Jev is used **only** as the gap check behind a closer, with thresholds tuned on dev |
| Run-to-run noise is unknown | Single sample per cell in v1 | Measure Luna agreement; use voting |
| Generalization was within archetype families | T-pool and S-set shared families | S2 uses **new archetypes** and a third org |

## 3. Pipeline under test
```
alert + logs ──► Investigator (Luna, prompt P*, k votes) ──► proposed action
                                                     │
                      if proposed = close OR collect_more on a benign-leaning case
                                                     ▼
                         Reviewer v3 (Qwen3.5-4B LoRA, gap-contrastive)
                                                     │ proposes close
                                                     ▼
                Gap check (paired control): coverage rule  AND/OR  Jev relevant_gap
                     close only if no decisive source is missing or reported missing
```
Each box is turned on only if it passes its stage gate below. Ablations report every subset.

## 4. Stages, decision gates, time and cost
### Stage 0: setup and freeze (~2 h, $0)
1. **S2 test set:** 16 scenarios = 8 malicious/benign lookalike pairs, **new archetypes** (candidates: lateral movement vs admin RDP; data exfil vs scheduled backup; persistence via scheduled task vs software deploy; credential dumping vs AV scan; plus up to 4 more), in a **third fictional org**. Use only archetypes EvidenceForge supports, and confirm that first. Same gap mechanics (40-min decisive-sensor gap), same 3 views → **48 cells**.
2. Add the new alert categories to `decisive_sensors.json` (v3 copy); rule-derive the labels; **you hand-review all 48**; the leak check passes.
3. **Dev split:** T-pool by scenario family: train 70% / dev-eval 30%; a **36-cell stratified dev subset** for fast screening.
4. Freeze the S2 set, rubric v3, this plan (sha256 → DECISIONS_LOG). **No one looks at S2 outputs until Stage 6.**

### Stage 1: free checks on existing data (~30 min, $0)
- **1a Paired control, post hoc:** apply the coverage rule (R2 / manifest) and Jev relevant_gap behind G-ft's 45 v2 outputs. Target: keep 4 justified closes, block 2 unsupported. (Exploratory: the data has been seen.)
- **1b Luna stability:** agreement of the 2 existing Luna samples per T-pool cell (action and label). Low agreement → voting is worth it (Stage 3); high → skip to k=3.
- **1c Jev threshold sweep** on T-pool reviewer data: pick the relevant_gap cutoff that blocks all gapped-benign closes at the least cost in justified closes.

### Stage 2: prompt and schema fixes, Luna, 36-cell dev subset (~1 h, ~$0.60)
| Variant | Change |
|---|---|
| P1 | v1 prompt (baseline, rerun for a fair comparison) |
| P2 | **Scope fix:** judge only the alerted activity; new `unrelated_findings[]` field → "open a separate ticket"; every escalation reason must cite a record **of the alerted activity** |
| P3 | P2 + **closure checklist:** benign explanation cited, each decisive source for this alert category confirmed present for the alert window |
| P4 | P3 + **realistic org context** ("approved tooling list; other services may exist") instead of "nothing else approved" |
Gate: keep the variant with the most correct actions **and 0 unsupported closures**; ties → simpler prompt.

### Stage 3: voting and frontier probe, same 36 cells (~1 h, ~$5)
- **Luna ×5 votes** with P*: close only if ≥4/5 vote close; escalate if ≥3/5 escalate; else collect_more.
- **Sol ×1** with P*. Astra **off** (run a 12-cell spot check, ~$6, only if Sol differs from Luna by ≥4 cells).
- **Cross-family voter (Adaption credits, ~0 cost):** hosted gemma-4-31b ×5 with P*, alone and mixed with Luna (see §5).
- Gate: cheapest configuration within 1 correct action of the best, with 0 unsupported closures.

### Stage 4: retrain the reviewer (~3 h incl. training, ~$5 on Colab + Luna)
- **Data: scale up 5×, by variety, not just count.** Generate ~300 T-pool scenarios (EvidenceForge is free; ~900 Luna investigations ≈ $4, or ≈ 3 credits on hosted gemma). Vary along the axes that matter: **gap position, duration and which sensor is missing**; consequential vs non-consequential gaps; noise level; 4+ orgs; archetype variants. All archetype families stay **disjoint from S2**. Build views, then delete raw bundles (~6 MB per scenario).
- **Learning curve:** train on 25 / 50 / 100% of the data and plot dev-eval score. This answers "does more data fix it?" directly. A flat curve means the bottleneck is not data.
- **Compute:** training runs on Adaption (see §5), so the Colab ceiling applies only to inference. Scale is then limited by EvidenceForge generation time. Measured on the v2 T-pool: 60 scenarios in 26 min with 4 parallel streams (≈ 2.3/min incl. ~12% reseeds), ~6.3 MB raw per scenario. First test 12–16 streams on the 24-core machine. Tiers: **300 tomorrow** (~1–2 h); **1–2k overnight** only if the learning curve is still rising at 100%; **10k = v4** (≈ 18–72 h of generation, ~$135 per Luna sample pass, and it needs more archetype templates or the extra rows are near-duplicates).
- **Gap-contrastive pairs:** same case shown complete (→ close) and gapped (→ collect_more), so the gap, not the archetype, flips the label. Gapped-benign rows **upweighted ×3**. Targets must **name the decisive source checked**.
- **Training:** Qwen3.5-4B QLoRA in Colab (T4), **2–3 epochs, explicit LR (1e-4)**, r16. Full control, no platform opacity, no credits.
- Gate: on dev-eval, reviewer + gap check makes **more justified closures than Stage 3 and 0 unsupported**. If not, v3 ships without the reviewer.

### Stage 5: assemble and freeze (~30 min)
Pick the final pipeline from the dev scoreboard; freeze config, prompts, seeds, thresholds and adapter hash; log the full search (number of configs tried).

### Stage 6: one-shot S2 evaluation (~1 h, ~$2–6)
Run once on all 48 S2 cells:
1. **v1 baseline:** Luna setup A, v1 prompt
2. **Best investigator only** (Stage 3 winner)
3. **Final pipeline** (+ reviewer + gap check, if they passed)
4. **Sol ×1 with P*** (frontier reference)

Paired exact McNemar (3 vs 1, 3 vs 2), Wilson CIs, paired bootstrap. The v1 S-set is reported as a secondary "seen" benchmark.

## 5. Adaption credits (account balance redacted for publication; 1 credit = $1)
**Correction:** v2 (AutoScientist 3 iterations + all hosted calls) used only ~0.015 credits. Training was either free or **not yet billed**. Before any big launch: look up the training price, launch one small run, and re-check the balance. You approve every launch.

**Training options opened up** (current model list, all SFT + DPO except Gemma 3 4B):
| Model | Why | Can we run it after training? |
|---|---|---|
| Qwen3.5-4B (as v2) | Direct comparison with G-ft | Yes, Colab T4 |
| **Qwen3.5-9B** | Bigger reviewer, still cheap to run | Yes, Colab T4 in 4-bit |
| gpt-oss-20b / Qwen3.6-35B-A3B | Reasoning-trained; the same family as the original investigator plan | Needs a bigger GPU (rent ~1 h) unless Adaption serves fine-tunes |
| gemma-4-31B-it | Same model as the hosted reviewer arm, 262k context → could train an **investigator** on full logs | Only if Adaption can **serve** the fine-tune; check first |

**Recommended use:**
1. **Main arm:** Qwen3.5-9B LoRA SFT on the 5× variety-scaled T-pool with gap-contrastive pairs. `max_iterations = 1` with an explicit recipe (2–3 epochs, LR 1e-4), so the platform can't change it silently. Also a 4B arm for comparison with v2.
2. **DPO arm (now feasible):** chosen = rule-correct action, rejected = the investigator's real wrong answers (over-escalation or unsupported close). The ≥ 12k pairs come from many cheap samples per T-pool cell (hosted gemma ×15 + Luna ×2).
3. **Stretch:** a trained **investigator** (gemma-4-31B, full logs in context), only if Adaption serves fine-tuned models.
4. **Learning curve** at 25 / 50 / 100% data, run on Adaption, which removes the Colab compute ceiling (Colab is only for inference).

**Inference stays essentially free:** hosted gemma-4-31b costs ~0.09 credits per M input tokens, so one full-log investigation (~30k tokens) is ~0.003 credits. 100 credits ≈ 30,000 investigations. That enables things that would cost hundreds of dollars on OpenAI:
- **Big cross-family ensembles:** gemma ×15 + Luna ×5 per case, on dev and S2. Does a different model family break the "never close" consensus?
- **Large replicate study:** 10 replicates of every S-set and S2 cell, giving real error bars on "0 closures" and closure rates (the honest-read concern #5).
- **LLM-judge for coverage awareness:** re-code all runs with gemma, validated against the 48 blind hand scores (v1 auto-coder κ = 0.29, so it must clear κ ≥ 0.6 to be used).
- **Never** attach the v1 Visualize dataset or any S/S2 data to training or stacks; stack self-improvement stays off.

Recommendation: plan for **Colab training + credits on inference**. That's both the cheapest and the most informative mix.

## 6. Pre-registered hypotheses (exploratory, n small)
- **H6 (scope):** P2 or later raises justified closures on dev vs P1, with 0 unsupported.
- **H7 (paired control):** reviewer + gap check has fewer unsupported closures than the reviewer alone, losing ≤ 1 justified closure (post hoc on v2, then on S2).
- **H8 (headline):** the final pipeline beats the v1 baseline on correct action on S2, with 0 unsupported closures.
- **H9 (capability):** Sol ×1 doesn't differ from Luna ×5 on justified closures (expected null; it supports "calibration, not capability").

## 7. Budget and timebox
| Item | Cost | Time |
|---|---|---|
| Stage 0 S2 build + label review | $0 | 2 h |
| Stage 1 free checks | $0 | 0.5 h |
| Stage 2 prompts (Luna) | ~$0.60 | 1 h |
| Stage 3 votes + Sol + gemma | ~$5 + <5 credits | 1 h |
| Stage 4 bigger T-pool + Colab QLoRA | ~$1 | 2.5 h |
| Stage 5–6 freeze + S2 | ~$2–6 | 1.5 h |
| **Total** | **~$9–13 OpenAI + Adaption training (price TBD; cap 300 credits)** | **~8.5 h** |
Kill rules: if Stage 0 isn't frozen by hour 3, drop Stage 4. If Colab training fails twice, ship without the reviewer. Never run S2 twice.

## 8. Not doing (and why)
CUGA (no accuracy gain with in-context logs; v4 test on big telemetry), Astra at scale (cost vs "not capability"), DPO (needs ≥ 12k pairs), self-improving stack (needs a controlled feedback loop), independent human labelers (no second person tomorrow; disclosed limitation).

## 9. Before starting
- [ ] v1+v2 report submitted
- [ ] Adaption billing page: credits left and the cost of one AutoScientist iteration
- [ ] OK to spend ~$5 on Sol (Astra off)
- [ ] Colab session with a T4 available
