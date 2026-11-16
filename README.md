# Evidence Vacuum

**Do AI security investigators treat missing logs as proof nothing happened?**
Code, data and runs for a small, pre-specified, hash-frozen study built at the Apart Research AI × Epistemics Sprint (Nov 2026).
All data is **synthetic** (generated with EvidenceForge). No real organizations, telemetry or personal data, and no API keys.

- **Results, all in one place:** [`08_analysis/RESULTS_LOG.md`](08_analysis/RESULTS_LOG.md)
- **Protocols and plans:** [`01_protocol/`](01_protocol/)

## Findings in brief

All exploratory (see Notes). Full tables: [`08_analysis/RESULTS_LOG.md`](08_analysis/RESULTS_LOG.md).

- **v1:** the investigator (GPT-6 Luna, alone and as a CUGA agent) never closed a case (0/48) and never used missing logs as evidence of absence (0/45 answers). It failed the other way: every justifiably closable benign case (12/12) was escalated or held. Closure checkpoints (Jev, R0, R2) therefore had nothing to act on.
- **v2:** no untrained reviewer produced a justified closure. A Qwen3.5 4B reviewer fine-tuned on Adaption made 4/12 justified closures and the best accuracy (35/45), but also 2/33 unsupported closures, the evidence-vacuum failure the study looked for.
- **v3:** on 8 new held-out incidents (run once), one scoping instruction raised the investigator from 18/24 to 23/24 correct and from 0/6 to 5/6 justified closures (the 6 closable cases come from 4 benign incidents, and the gains came from 3 of them), with 0 unsupported closures (exact McNemar p = 0.0625 at the view level; views of one incident are not independent, so treat this as descriptive). An investigator that always escalates would also score 18/24, so the gain is entirely in correctly closing benign cases. On the practice pool, a different model (Gemma 4 31B) made 38 closures on cases whose key logs were missing (counted across repeated samples); a silence check that reads only log metadata blocked all 38 (from 9 distinct cases), at the cost of 3 justified closures. On the held-out test it changed no decision.

## Terms used in the files

- **Views (conditions):** `C1` = complete logs, `C2` = a collection gap (40 minutes in v1) that hides the decisive evidence, except in one deliberately harmless control pair, undocumented, `C3` = the same gap plus a coverage manifest naming the outage.
- **Cell:** one scenario in one view (8 scenarios × 3 views = 24 cells per test set).
- **Labels:** each cell is `MALICIOUS_SUPPORTED`, `BENIGN_SUPPORTED` or `INSUFFICIENT` (the evidence cannot settle it). Closing is justified only for `BENIGN_SUPPORTED`; any other closure is **unsupported**.
- **Setups:** A = all logs in one prompt, C = the CUGA agent with log tools; B and D are A and C behind the Jev checkpoint. R0 and R2 are rule baselines.

## What's in here

| Folder | Contents |
|---|---|
| `01_protocol/` | Pre-specified protocol (v1), v2 reviewer protocol (+ amendments), v3 plan |
| `03_scenarios/` | Scenario builders (`make_*.py`), EvidenceForge configs + seeds (`configs/`, `tpool/configs/`), sealed ground truth, freeze manifests, `generate.sh`, and the raw logs of the 8 v3 test incidents (`generated/S21`–`S28`) |
| `04_conditions/` | The three log views per incident: `complete/`, `partial_undocumented/` (logs missing), `partial_documented/` (logs missing + coverage note) |
| `05_rubric/` | Answer key (`cell_labels.csv`), rubric, freeze manifest |
| `06_prompts/` | Investigator task, output schema, Jev checkpoint spec |
| `harness/` | Runners: LLM (`run_fixed.py`), CUGA agent (`run_cuga.py`), checkpoints (`gates.py`), reviewers, v3 runner and silence check |
| `07_runs/` | The model answers behind the reported results (`raw/` = v1, `tpool/` = v2 practice pool, `v3/` = v3). Pilot runs are not included |
| `08_analysis/` | Scoring scripts, scored rows, metric tables, figures, v2/v3 reviewer inputs and outputs, training files |
| `notebooks/` | Colab notebooks for the Qwen reviewers (v2 and v3) |
| `patches/` | The one-line CUGA patch |

Folder numbers follow the order of the research workflow. Folders 00, 02 and 09 held internal notes, literature notes and the report draft, and are not published.

Not included: the raw EvidenceForge output for the v1 and practice-pool incidents (~2 GB, regenerate it with `03_scenarios/generate.sh`) and the trained LoRA adapters (retrain them as in step 5, and step 6's notes for the v3 reviewer). The raw logs of the 8 v3 test incidents are included, because the v3 score needs them.

## Requirements

- Python 3.12, [uv](https://docs.astral.sh/uv/), git and bash (on Windows: Git Bash)
- API keys for the runs you want to repeat: **OpenAI** (investigator), **TypeSafe** (Jev checkpoint, v1/v2), **Adaption** (fine-tuning and hosted Gemma, v2/v3)
- A Google Colab T4 GPU for the Qwen reviewer notebooks. They pin the library versions used in the study (transformers 5.23.0, peft 0.21.3, accelerate 1.15.0, bitsandbytes 0.50.2) on Colab's preinstalled torch (2.14.1+cu130 at the time)
- Re-scoring the study's own answers needs **no keys** (see "Check the numbers" below)

## Detailed replication steps

Everything needed to rerun this from scratch. All data is synthetic.
Run every command from the repo root, in a bash shell (on Windows: Git Bash). These are the same steps as on the project page.
**Do the steps in order.** Each one builds on the last (for example, v3's tuning uses the v2 practice pool from step 5).

### 1. Get the code

Clone the repo byte-for-byte (so the hashes match), then check every frozen file against its recorded SHA-256.

**Clone and verify** (on macOS, type `python3` until step 2 activates the environment)
```bash
git clone -c core.autocrlf=false https://github.com/nathanielmiller23/evidence-vacuum
cd evidence-vacuum
python verify_freeze.py
```

`verify_freeze.py` prints "OK" when every frozen scenario, label, prompt and harness file matches. It also lists the few files that were changed after their freeze on purpose, with the reason; each of those is pinned to an approved hash, so any further edit (for example to a label) makes it fail.

### 2. Install the pinned tools

[EvidenceForge](https://github.com/Cisco-Talos/EvidenceForge) at `79fcfcd`, [CUGA](https://github.com/cuga-project/cuga-agent) at `f6e2335` plus a one-line patch, and [Jev](https://typesafe.ai/) pinned to `jev-1.14.0`. Everything runs in CUGA's venv. Add your own API keys to `.env` (none are included).

**EvidenceForge (log generator)**
```bash
git clone -c core.autocrlf=false https://github.com/Cisco-Talos/EvidenceForge tools/EvidenceForge
git -C tools/EvidenceForge checkout 79fcfcd
(cd tools/EvidenceForge && uv sync)
```

**CUGA agent + patch**
```bash
git clone https://github.com/cuga-project/cuga-agent tools/cuga-agent
git -C tools/cuga-agent checkout f6e2335
git -C tools/cuga-agent apply ../../patches/cuga-gpt6-reasoning-model.patch
(cd tools/cuga-agent && uv sync --python 3.12)
```

**Python environment** (on Windows, activate with `source tools/cuga-agent/.venv/Scripts/activate` instead)
```bash
source tools/cuga-agent/.venv/bin/activate
uv pip install -r requirements.txt
```

**API keys**
```bash
cp .env.example .env    # then add your keys
```

More detail:
- **Keys:** `OPENAI_API_KEY` (investigator), `TYPESAFE_API_KEY` (Jev, v1/v2), `ADAPTION_API_KEY` (fine-tuning and hosted Gemma, v2/v3). Optional checks: `python harness/probe_openai.py` (a tiny paid call that confirms the key and model ID) and `python harness/gate_selftest.py` (about $0.0002).
- **CUGA patch:** makes `_is_reasoning_model` also match `"gpt-6"`, because GPT-6 rejects a non-default temperature.
- **EvidenceForge spool folder:** `generate.sh` uses `EFORGE_SPOOL_DIR` (default `~/eforge-spool`). It must be a private folder. On Windows, keep it out of `AppData`.

### 3. Build the 8 test incidents

Generate each incident from its YAML and seed, cut the three log views, and check the hashes. The study's views are committed, so `git status` shows if yours differ.

**Generate and check** (uv may warn that the active environment doesn't match EvidenceForge's. That's expected and harmless: EvidenceForge runs in its own environment.)
```bash
python 03_scenarios/make_scenarios.py
bash 03_scenarios/generate.sh v1
python verify_freeze.py
git status 04_conditions
```

### 4. Run v1 (investigators and checkpoints)

Setup A (all logs in one prompt) and Setup C (the CUGA agent), then the Jev and rule checkpoints, then scoring. The runners skip cells that already have an answer, so move the study's runs aside first.

**Move the study's answers aside**
```bash
mv 07_runs/raw 07_runs/raw_published
```

**Investigate, check, score**
```bash
python harness/run_all.py --config A
python harness/run_all.py --config C
python harness/gates.py 07_runs/raw/*Z.json
python 08_analysis/score.py
```

More detail: `score.py` writes `08_analysis/metrics.md` and `scored_rows.csv`, and `python 08_analysis/make_figures.py` redraws the figures. Coverage awareness was scored by hand on a blind sheet. The study's filled sheet is `08_analysis/hand_scoring_blind.csv` (summary in `08_analysis/supplement.md`). `score.py` never overwrites it: when it exists, a fresh blank sheet goes to `hand_scoring_blind.new.csv` for your own hand scoring.

### 5. Run v2 (reviewers)

Build the practice pool, run the investigator on it, build the training file, fine-tune [Qwen3.5 4B](https://huggingface.co/Qwen/Qwen3.5-4B) with [Adaption](https://adaptionlabs.ai/) AutoScientist, run the reviewers, then score.

**Practice pool** (60 incidents, each a separate EvidenceForge run, so this takes a while)
```bash
python 03_scenarios/make_tpool.py
bash 03_scenarios/generate.sh tpool
```

**Investigator answers + training file**
```bash
mv 07_runs/tpool 07_runs/tpool_published
python harness/run_tpool.py --samples 2 --workers 4 --upto 60
python harness/build_sft.py --min-rows 1200
```

**Fine-tune, then the Qwen reviewers**

Upload the training file to Adaption (`prompt` and `completion` columns), run AutoScientist on Qwen3.5 4B, then run `notebooks/v2_reviewer_eval_colab.ipynb` in Colab. All v2 reviewers judge the study's 45 frozen v1 answers (`08_analysis/v2/eval_inputs.jsonl`, included).

**Other reviewers + score**
```bash
python harness/run_rule_reviewers.py
python harness/run_hosted_reviewer.py --model gemma-4-31b-it --name H-hosted
python 08_analysis/score_v2.py
```

More detail:
- **Practice pool only:** `--upto 60` restricts the run to T001–T060, because the repo also ships the views of the 240 v3 practice incidents.
- **Frozen v1 answers:** `eval_inputs.jsonl` holds the 45 study answers the reviewers judge. Rebuilding it from fresh v1 runs is not scripted.
- **Training file:** `build_sft.py` writes `08_analysis/v2/sft_reviewer.csv` (prompt, completion, plus label columns). The exact file the study uploaded is `08_analysis/v2/sft_reviewer_upload.csv`.
- **Fine-tune on Adaption:** upload the training file in raw mode, mapping `prompt` → prompt and `completion` → completion, and run AutoScientist on `Qwen/Qwen3.5-4B`. The study's run tried 3 iterations; the best (iteration 2) used LoRA r8/α16, lr 2e-5, 1 epoch. Download the adapter.
- **Colab notebook (T4 GPU):** put `08_analysis/v2/eval_inputs.jsonl` and the adapter, renamed to `adapter.tar.gz`, in `MyDrive/evidence-vacuum-v2/`. Run it once without the adapter (G-base) and once with it (G-ft), then copy `G-base.jsonl` and `G-ft.jsonl` from the Drive `outputs/` folder into `08_analysis/v2/outputs/` before `score_v2.py`.
- **H-stack (optional arm):** an Adaption inference stack on `gemma-4-31b-it` with the training file attached. Run `python harness/run_hosted_reviewer.py --list-models` to see your stack slug, then `--model stack:<slug> --name H-stack`.

### 6. Run v3 (scope fix + silence check)

Build the bigger practice pool and the fresh test set (frozen before tuning), run the scope-fix prompt on the test set once, then score with the silence check switched on.

**Practice pool + fresh test set** (240 practice incidents, so generation takes a while. A few fail inside EvidenceForge even in the study: T084, T115 and T154. `generate.sh` reports them and carries on, and later steps skip them.)
```bash
python 03_scenarios/make_tpool_v3.py
bash 03_scenarios/generate.sh tpool3
python 03_scenarios/check_decisive.py
python 03_scenarios/make_s2.py
bash 03_scenarios/generate.sh s2
```

**One-shot test, scored with the silence check**
```bash
python harness/run_v3.py --cells 08_analysis/v3/s2_cells.json \
  --variant P2 --backend openai:gpt-6-luna --tag s2_mine
python 08_analysis/score_v3.py --tag s2_mine --gate --gate-scope relevant
```

More detail:
- **New tags keep the study's runs untouched.** Your answers go to `07_runs/v3/<tag>/`. The study's are in `07_runs/v3/{stage2,stage3,tpool3,s2}`.
- **Tuning stages (practice pool only):** stage 2 compares prompts `P1` to `P4` on `08_analysis/v3/dev36.json` (`--variant P1` ... `--tag stage2_mine`, then `score_v3.py --tag stage2_mine --gate`). Stage 3 adds `--samples 5` (score with `--vote`), `--backend openai:gpt-6.1-sol` and `--backend adaption:gemma-4-31b-it`. The v1 baseline on the test set is `--variant P1`.
- **Silence check:** it reads the raw generated logs in `03_scenarios/generated/`. The study's logs for the 8 test incidents ship with the repo, so `generate.sh s2` skips them. To regenerate them yourself, delete those folders first (see "Test the log generator" below). Its 22-minute cutoff comes from the practice pool only (`08_analysis/v3/stage1_silence_gate.py`).
- **Retrained reviewer (dropped by the pre-set rule):** run the investigator on `08_analysis/v3/tpool3_cells_batch1.json` to `batch4.json` (`--variant P2 --tag tpool3`), then `python harness/build_sft_v3.py --runs 07_runs/v3/tpool3` (writes `08_analysis/v3/sft/sft_v3_full.csv`; the exact uploaded file is `08_analysis/v3/sft/sft_v3_upload.csv`). Upload it to Adaption the same way and train Qwen3.5-4B (LoRA r16/α32, lr 1e-4, 2 epochs, 1 iteration). Build its inputs with `python harness/build_reviewer_inputs_v3.py --runs 07_runs/v3/stage3 --match "P2__openai-gpt-6-luna" --out 08_analysis/v3/reviewer_dev_inputs.jsonl` and run `notebooks/v3_reviewer_colab.ipynb` (set `BASE = "Qwen/Qwen3.5-4B"`, `ADAPTER_TAR` and `NAME` in the CONFIG cell).

## Check the numbers (no API keys needed)

Scoring is deterministic. Run it on the study's own answers in `07_runs/` (step 2's Python environment is enough):

```bash
python 08_analysis/score.py
python 08_analysis/score_v2.py
```

These rewrite `08_analysis/metrics.md` and `08_analysis/v2/metrics_v2.md`, so `git diff` shows whether you got the same numbers.

The v3 test score uses the silence check, which reads the raw logs of the 8 test incidents. Those logs ship with the repo, so no generation is needed:

```bash
python 08_analysis/score_v3.py --tag s2 --gate --gate-scope relevant
```

The output should match `08_analysis/v3/s2_final_gate.md`.

### Test the log generator

To see whether EvidenceForge regenerates the same logs on your machine, regenerate one shipped incident and compare it with the committed files:

```bash
rm -rf 03_scenarios/generated/S21
bash 03_scenarios/generate.sh S21
git status 03_scenarios/generated/S21/C1/data 04_conditions
```

No changes listed means identical logs. The command compares only the log data and the views, because the generator's own manifest records the generation time. To restore the study's files afterwards, run `git checkout -- 03_scenarios/generated/S21 04_conditions/*/S21` (this overwrites any local changes to S21 only; best done in a disposable clone).

## Known limitations

An independent pre-publication audit reproduced every headline count from the shipped files (v1, v2, the v3 tuning tables and the held-out S2 result). It also found gaps in the end-to-end *rebuild* path, listed here so nobody mistakes a re-score for a rebuild.

- **Re-score vs. rebuild.** Re-scoring the published v1, v2 and S2 results needs no API keys and matches the stored tables. Regenerating everything from scratch is not yet a single clean recipe (next three points).
- **Seed adjustments.** 17 practice scenarios (T002 T004 T014 T030 T033 T037 T049 T084 T111 T115 T117 T147 T184 T193 T202 T214 T226) were reseeded after generator errors. The committed configs in `03_scenarios/tpool/configs` record the seeds actually used and are authoritative. Re-running `make_tpool.py` / `make_tpool_v3.py` rewrites them with the default formula, which produces a fresh dataset rather than the original one.
- **v1 to v2 inputs.** Step 4 archives `07_runs/raw` to `07_runs/raw_published`, but the v2 rule reviewers (`run_rule_reviewers.py`) read the 45 original runs from `07_runs/raw`. To re-run v2 reviewers on the frozen inputs, restore `07_runs/raw_published` to `07_runs/raw` first. Runners are resumable: existing output files make them skip work, so use a new `--name` or output folder for a fresh run.
- **Practice-pool gate scores need raw telemetry.** The practice pool's raw logs are not shipped (size). The silence gate now raises an error when they are missing instead of silently reporting "no veto"; regenerate them before `score_v3.py --gate` on practice tags. S2 raw logs are shipped and its gated score reproduces.
- **Failed scenarios.** Six practice scenarios produced empty views (T084, T115, T154, T241, T269, T274) and are excluded: 294 valid C1 scenarios and 286 valid gapped sets out of 300.
- **Training-set duplicates.** The v3 reviewer upload has 1,200 rows but 1,117 distinct prompts: some label-preserving perturbations were no-ops on short summaries (83 duplicate-prompt rows, no conflicting targets). The v2 upload has 1,200 distinct prompts.
- **Metric definitions differ by version.** v1 "unnecessary escalation" counts both escalate and hold; v3 counts escalate only. Unparsed answers count as "collect more" (correct on insufficient cells); for hosted Gemma that credits 4 failures (106/180 vs. 102/180 if every failure counts as wrong). S2 had no invalid answers.
- **Statistics are cell-level.** Views of the same incident are not independent: the S2 McNemar p = 0.063 treats 24 views as independent, but the 5 gains come from 3 incidents.
- **Provenance.** Model revisions and the Adaption run ID are not pinned (the run ID is redacted; adapter hashes identify the checkpoint, adapter weights are not shipped). `fig5_v3.png` was made separately and is not produced by `make_figures.py`.
- **Notebook archives.** The Colab notebooks extract adapter archives with Python's `filter="data"` (no path traversal or links); still only load archives you produced.

## Deviations from the plan

The protocols in `01_protocol/` were written before the runs. What changed, and why:

- **Smaller v1 scope:** 8 scenarios × 3 views = 24 cells (the protocol and rubric were drafted for 12 scenarios / 36 cells). See the solo-scope table at the top of `PROTOCOL.md`.
- **One labeler, not two:** `05_rubric/RUBRIC.md` describes two independent labelers and Cohen's κ. The study used one labeler applying the §1.4 decision rule. Labels derived mechanically from the same rule (`rule_labels.csv`) agree on 24/24 cells, which is a consistency check, not independent validation. The rubric file is hash-frozen, so it still shows the original wording (including its "NOT FROZEN" status line).
- **Hand scoring:** coverage awareness was scored by hand, blind to setup, because the automatic coder agreed too poorly (κ = 0.29). Single scorer.
- **v2 base model:** Llama 3.2 3B was replaced by Qwen3.5 4B before any reviewer output (amendment A2 in `PROTOCOL_v2_resolution_reviewer.md`), because Llama was not offered for training. The hosted Gemma arms were added at the same stage (amendment A1).
- **v2 training:** the protocol planned 1 AutoScientist iteration; the platform ran 3, and the best (iteration 2) was used.
- **v3 reviewer:** `PLAN_v3_run.md` planned a 9B reviewer; it was dropped and the 4B model was retrained instead, so the result is directly comparable with v2.
- **Smaller held-out set:** `PLAN_v3_run.md` planned S2 as 16 scenarios / 48 cells. It was built as 8 scenarios / 24 cells for time, and frozen at that size before any tuning. The plan file is hash-frozen, so it still says 48.
- **Dropped reviewer run on S2:** the plan sent a reviewer to the held-out test only if it passed the development rule. The retrained 4B reviewer failed it (12 unsupported closures on dev), but it was already frozen, so it was run once on S2 as an unplanned, supplementary check. Its 24/24 is reported for transparency only and was not used to pick the final pipeline.
- **Internal decisions log:** some frozen files (for example `RUBRIC.md`, `PLAN_v3_run.md`, `harness/cuga_config/settings.ev.toml`) refer to a decisions log. It was an internal working file and is not published; the deviations that matter are listed here.
- **Files edited after a freeze:** `python verify_freeze.py` lists each one with the reason (none changes a frozen result).

## Notes

- **Expect small differences when rerunning models.** GPT-6 Luna's sampling can't be fixed (no temperature setting), and each case ran once.
- **Cost:** all 48 Jev checkpoint calls cost about $0.002. The whole v3 run was about $10 of API calls.
- **Results are exploratory:** 8 test incidents per test set, one original investigator model (GPT-6 Luna), one run per held-out test case. Most differences are not statistically significant (see `08_analysis/RESULTS_LOG.md`).
- **Labels** follow a pre-specified rule and were frozen before the evaluation runs (only pilot runs came first). Labels and hand scores were produced with AI assistance under that rule, and were not reviewed by an independent labeler. The freeze timestamps are self-recorded (`frozen_at_utc` in each manifest), so the hashes prove the files have not changed since, not when they were frozen. That is why the study is called pre-specified and hash-frozen rather than pre-registered: no external registry or timestamp was used. (The protocol files in `01_protocol/` keep their original "pre-registration" wording, since they are left as written at the time.)
- **Synthetic indicators:** attacker addresses use reserved documentation ranges (203.0.113.0/24, 198.51.100.0/24) and fictional domains. Other public IPs in the logs are background traffic from EvidenceForge's built-in profiles.
- **Safety:** the scenarios use common, publicly documented techniques only. Recommendations are defensive.

## License

MIT. See [`LICENSE`](LICENSE).
