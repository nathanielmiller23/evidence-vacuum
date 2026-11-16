"""Build the v2 SFT dataset for Adaption from T-pool investigator runs (never S-scenarios).

    tools/cuga-agent/.venv/Scripts/python.exe harness/build_sft.py --min-rows 1000

Outputs (08_analysis/v2/):
  sft_reviewer.csv     columns: prompt, completion (+ metadata), uploaded with processing_mode="raw",
                       column_mapping={"prompt": "prompt", "completion": "completion"}
  sft_reviewer.jsonl   same rows
  spotcheck_50.csv     50 random rows for the human spot check
The prompt column is the FULL rendered reviewer input (system + user), so any chat template works the same at
training and inference; the evaluation notebook uses harness/reviewer.py to render identically.
Targets depend only on the cell label from the T meta, never on the investigator's own answer.
"""
import argparse
import csv
import json
import random
from copy import deepcopy
from pathlib import Path

from reviewer import REVIEWER_SYSTEM, render_user, target

WS = Path(__file__).resolve().parents[1]
TCFG = WS / "03_scenarios" / "tpool" / "configs"
# Cells whose rule label is not valid because the "consequential" gap did not actually hide the decisive evidence
# (decisive-token check, 2026-11-15): rogue_admin account creation is logged on the DC (outside the workstation gap);
# shifted beacon/updater variants have their last beacon after the gap ends. Excluded rather than relabeled.
EXCLUDE = {(t, c) for t in ("T007", "T027", "T037", "T057", "T025", "T026", "T055", "T056") for c in ("C2", "C3")}
OUT = WS / "08_analysis" / "v2"


def missing_for(meta, cond):
    if meta["gap_type"] != "consequential" or cond == "C1":
        return []
    g = meta["gap"]
    hosts = [h for h in g["hosts"] if h != "*"] or ["proxy"]
    return [f"{s} for {', '.join(hosts)} {g['window'][0][11:16]}-{g['window'][1][11:16]} UTC" for s in g["sources"]]


def prompt_text(inv, ctx, man):
    return f"[SYSTEM]\n{REVIEWER_SYSTEM}\n[USER]\n{render_user(inv, ctx, man)}"


def perturb(inv, rng, kind):
    p = deepcopy(inv)
    if kind == "action":
        p["recommended_action"] = rng.choice([a for a in ("close", "escalate", "collect_more") if a != inv["recommended_action"]])
    elif kind == "assessment":
        p["assessment"] = rng.choice([a for a in ("malicious", "benign", "insufficient_evidence") if a != inv["assessment"]])
        p["confidence"] = round(rng.uniform(0.55, 0.98), 2)
    elif kind == "no_limits":
        p["known_telemetry_limitations"] = []
    elif kind == "few_obs":
        p["supporting_observations"] = inv["supporting_observations"][:2]
    return p


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--min-rows", type=int, default=1000)
    ap.add_argument("--seed", type=int, default=515)
    a = ap.parse_args()
    rng = random.Random(a.seed)
    OUT.mkdir(parents=True, exist_ok=True)
    real = []
    for p in sorted((WS / "07_runs" / "tpool").glob("A__T*__C?__*Z.json")):
        run = json.loads(p.read_text(encoding="utf-8"))
        if run["status"] != "VALID":
            continue
        tid, cond = run["scenario_id"], run["condition"]
        assert tid.startswith("T"), f"LEAK GUARD: {tid}"
        if (tid, cond) in EXCLUDE:
            continue
        meta = json.loads((TCFG / f"{tid}.meta.json").read_text(encoding="utf-8"))
        ctx = (WS / "03_scenarios" / meta["environment_context"]).read_text(encoding="utf-8").strip()
        man = meta["coverage_manifest"] if cond == "C3" else None
        real.append(dict(tid=tid, cond=cond, meta=meta, inv=run["parsed"], ctx=ctx, man=man, run_id=run["run_id"]))
    rows = []

    def add(r, inv, source):
        rows.append({"prompt": prompt_text(inv, r["ctx"], r["man"]),
                     "completion": target(r["meta"]["labels"][r["cond"]], missing_for(r["meta"], r["cond"])),
                     "scenario_id": r["tid"], "condition": r["cond"], "label": r["meta"]["labels"][r["cond"]],
                     "archetype": r["meta"]["archetype"], "org": r["meta"]["org"], "gap_type": r["meta"]["gap_type"],
                     "source": source, "run_id": r["run_id"]})

    for r in real:
        add(r, r["inv"], "real")
    kinds = ["action", "assessment", "no_limits", "few_obs"]
    i = 0
    while len(rows) < a.min_rows and real:
        r = real[i % len(real)]
        k = kinds[(i // len(real)) % len(kinds)]
        add(r, perturb(r["inv"], rng, k), f"perturb_{k}")
        i += 1
    rng.shuffle(rows)
    cols = list(rows[0])
    for name, data in (("sft_reviewer.csv", rows), ("spotcheck_50.csv", rng.sample(rows, min(50, len(rows))))):
        with open(OUT / name, "w", newline="", encoding="utf-8") as f:
            w = csv.DictWriter(f, fieldnames=cols)
            w.writeheader()
            w.writerows(data)
    with open(OUT / "sft_reviewer.jsonl", "w", encoding="utf-8") as f:
        for r in rows:
            f.write(json.dumps(r, ensure_ascii=False) + "\n")
    from collections import Counter
    print(f"real={len(real)} total={len(rows)} labels={dict(Counter(r['label'] for r in rows))} sources={dict(Counter(r['source'] for r in rows))}")


if __name__ == "__main__":
    main()
