"""Build the v3 reviewer SFT set from investigator runs on the v3 T-pool extension (T061–T300 ONLY).

    python harness/build_sft_v3.py --runs 07_runs/v3/tpool3 [--frac 1.0 --tag full]

- T001–T060 are NOT used (they are the v3 dev-evaluation pool); S*/S2 never.
- Same reviewer prompt and target as v2 (harness/reviewer.py), so v2 and v3 adapters are comparable.
- Label validity from 03_scenarios/tpool/decisive_check.json (invalid C2/C3 cells excluded).
- Gap-contrastive by construction: every scenario contributes C1 (gap-free) and C2/C3 (gapped) cells.
- Gapped-BENIGN cells (benign truth, consequential gap -> INSUFFICIENT) are upweighted x3 with 2 extra
  label-preserving perturbations (not exact duplicates).
- --frac subsamples SCENARIOS (all their cells together) for the learning curve.
Outputs: 08_analysis/v3/sft/sft_v3_<tag>.csv/.jsonl
"""
import argparse
import csv
import json
import random
import sys
from collections import Counter
from copy import deepcopy
from pathlib import Path

HERE = Path(__file__).resolve().parent
WS = HERE.parent
sys.path.insert(0, str(HERE))
from build_sft import missing_for, perturb, prompt_text  # noqa: E402
from reviewer import target  # noqa: E402

TCFG = WS / "03_scenarios" / "tpool" / "configs"


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--runs", required=True)
    ap.add_argument("--frac", type=float, default=1.0)
    ap.add_argument("--tag", default="full")
    ap.add_argument("--seed", type=int, default=3003)
    ap.add_argument("--min-rows", type=int, default=1200, help="Adaption needs >= 1,000 rows; fill with label-preserving perturbations")
    a = ap.parse_args()
    rng = random.Random(a.seed)
    chk = json.loads((WS / "03_scenarios" / "tpool" / "decisive_check.json").read_text(encoding="utf-8"))
    scen = sorted({p.name.split("__")[2] for p in Path(a.runs).glob("*.json")})
    scen = [s for s in scen if s.startswith("T") and int(s[1:]) > 60]
    keep = set(rng.sample(scen, max(1, round(len(scen) * a.frac)))) if a.frac < 1 else set(scen)
    rows, reals = [], []
    for p in sorted(Path(a.runs).glob("*.json")):
        run = json.loads(p.read_text(encoding="utf-8"))
        tid, cond = run["scenario_id"], run["condition"]
        assert tid.startswith("T") and int(tid[1:]) > 60, f"LEAK GUARD: {tid}"
        if tid not in keep or not run.get("parsed"):
            continue
        v = chk.get(tid)
        if v is None or not v.get("valid_C1") or (cond != "C1" and not v.get("valid_C2C3")):
            continue
        meta = json.loads((TCFG / f"{tid}.meta.json").read_text(encoding="utf-8"))
        ctx = (WS / "03_scenarios" / meta["environment_context"]).read_text(encoding="utf-8").strip()
        man = meta["coverage_manifest"] if cond == "C3" else None
        lab = meta["labels"][cond]
        inv = run["parsed"]

        # bind this cell's values as defaults (avoids late binding when add() is reused for fill rows)
        def add(i, source, ctx=ctx, man=man, lab=lab, meta=meta, cond=cond, tid=tid, backend=run["backend"]):
            rows.append({"prompt": prompt_text(i, ctx, man), "completion": target(lab, missing_for(meta, cond)),
                         "scenario_id": tid, "condition": cond, "label": lab, "archetype": meta["archetype"],
                         "org": meta["org"], "gap_type": meta["gap_type"], "variant": meta["variant"],
                         "investigator": backend, "source": source})
        add(inv, "real")
        reals.append((inv, add))
        if meta["class"] == "BENIGN" and lab == "INSUFFICIENT":
            for k in rng.sample(["action", "assessment", "no_limits", "few_obs"], 2):
                add(perturb(inv, rng, k), f"upweight_{k}")
    kinds = ["few_obs", "no_limits", "assessment", "action"]
    i = 0
    while len(rows) < a.min_rows and reals:
        inv, add = reals[i % len(reals)]
        k = kinds[(i // len(reals)) % len(kinds)]
        add(perturb(inv, rng, k), f"fill_{k}")
        i += 1
    rng.shuffle(rows)
    out = WS / "08_analysis" / "v3" / "sft"
    out.mkdir(parents=True, exist_ok=True)
    with open(out / f"sft_v3_{a.tag}.csv", "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=list(rows[0]))
        w.writeheader()
        w.writerows(rows)
    with open(out / f"sft_v3_{a.tag}.jsonl", "w", encoding="utf-8") as f:
        for r in rows:
            f.write(json.dumps(r, ensure_ascii=False) + "\n")
    leaks = sum(1 for r in rows if any(s in r["prompt"] for s in ("S21", "S22", "S23", "S24", "S25", "S26", "S27", "S28", "Riverbend")))
    print(f"scenarios={len(keep)} rows={len(rows)} labels={dict(Counter(r['label'] for r in rows))} "
          f"sources={dict(Counter(r['source'] for r in rows))} S2-leak-rows={leaks}")


if __name__ == "__main__":
    main()
