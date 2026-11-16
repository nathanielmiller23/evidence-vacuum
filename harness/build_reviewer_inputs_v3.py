"""Render reviewer inputs (same reviewer prompt as v2/v3 training) from v3 investigator runs.

    python harness/build_reviewer_inputs_v3.py --runs 07_runs/v3/stage3 --match "P2__openai-gpt-6-luna" --out 08_analysis/v3/reviewer_dev_inputs.jsonl
    python harness/build_reviewer_inputs_v3.py --runs 07_runs/v3/s2 --match "P2__openai-gpt-6-luna" --out 08_analysis/v3/reviewer_s2_inputs.jsonl
Fields: run_id, scenario_id, condition, label, closure_defensible, investigator_action, prompt (+ gate_fires for the paired control).
Unparsed investigator answers are kept with investigator_action = collect_more and no prompt (the reviewer is skipped; fail-safe).
"""
import argparse
import json
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
WS = HERE.parent
sys.path.insert(0, str(HERE))
sys.path.insert(0, str(WS / "08_analysis"))
from build_sft import prompt_text  # noqa: E402
from prompts import scen_dir  # noqa: E402
from score_v3 import label  # noqa: E402
import silence_gate as sg  # noqa: E402


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--runs", required=True)
    ap.add_argument("--match", required=True)
    ap.add_argument("--out", required=True)
    a = ap.parse_args()
    n = 0
    with open(a.out, "w", encoding="utf-8") as f:
        for p in sorted(Path(a.runs).glob(f"{a.match}__*.json")):
            r = json.loads(p.read_text(encoding="utf-8"))
            sid, cond = r["scenario_id"], r["condition"]
            lab = label(sid, cond)
            if lab is None:
                continue
            meta = json.loads((scen_dir(sid) / f"{sid}.meta.json").read_text(encoding="utf-8"))
            ctxp = (WS / "03_scenarios" / meta["environment_context"]) if "/" in meta["environment_context"] else (scen_dir(sid) / meta["environment_context"])
            ctx = ctxp.read_text(encoding="utf-8").strip()
            man = meta["coverage_manifest"] if cond == "C3" else None
            inv = r.get("parsed")
            s = sg.silences(sid, cond, "relevant")
            gate = max([v for k, v in s.items() if k.split("@")[0] in ("winsec", "sysmon")] or [0]) >= 22
            f.write(json.dumps({"run_id": p.stem, "scenario_id": sid, "condition": cond, "label": lab,
                                "closure_defensible": "yes" if lab == "BENIGN_SUPPORTED" else "no",
                                "investigator_action": (inv or {}).get("recommended_action", "collect_more"),
                                "gate_fires": gate, "prompt": prompt_text(inv, ctx, man) if inv else None},
                               ensure_ascii=False) + "\n")
            n += 1
    print("wrote", n, "->", a.out)


if __name__ == "__main__":
    main()
