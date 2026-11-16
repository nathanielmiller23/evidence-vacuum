"""Score v3 runs: every (variant, backend) group in 07_runs/v3/<tag>/, optionally with k-vote aggregation and the silence gate.

    python 08_analysis/score_v3.py --tag stage2 [--vote] [--gate] [--out 08_analysis/v3/stage2.md]
Labels: T* from the T-pool meta (label-invalid cells from decisive_check.json are skipped); S2 (S21–S28) from the sealed labels.
Vote rule (pre-registered in PLAN_v3): close only if >= 4/5 (>= 80%) of samples close; else escalate if >= 3/5 escalate; else collect_more.
Gate: a proposed close becomes collect_more if the sensor-silence gate fires (threshold from Stage 1b, 22 min).
"""
import argparse
import json
import math
import sys
from collections import defaultdict
from pathlib import Path

WS = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(WS / "harness"))
WANT = {"MALICIOUS_SUPPORTED": {"escalate"}, "BENIGN_SUPPORTED": {"close"}, "INSUFFICIENT": {"escalate", "collect_more"}}
GATE_MIN = 22
PRICE = {"gpt-6-luna": (0.10, 0.50), "gpt-6.1-sol": (2.0, 10.0), "gpt-6-astra": (10.0, 50.0)}


def label(sid, cond):
    if sid.startswith("T"):
        chk = json.loads((WS / "03_scenarios" / "tpool" / "decisive_check.json").read_text(encoding="utf-8"))
        if cond != "C1" and not chk.get(sid, {}).get("valid_C2C3", False):
            return None
        return json.loads((WS / "03_scenarios" / "tpool" / "configs" / f"{sid}.meta.json").read_text(encoding="utf-8"))["labels"][cond]
    return json.loads((WS / "03_scenarios" / "ground_truth_SEALED" / f"{sid}.labels.json").read_text(encoding="utf-8"))["labels"][cond]


def vote(actions):
    n = len(actions)
    if sum(a == "close" for a in actions) >= math.ceil(0.8 * n):
        return "close"
    if sum(a == "escalate" for a in actions) >= math.ceil(0.6 * n):
        return "escalate"
    return "collect_more"


GATE_SCOPE = "all"


def gate_fires(sid, cond, cache={}):
    key = (sid, cond, GATE_SCOPE)
    if key not in cache:
        import silence_gate as sg
        s = sg.silences(sid, cond, GATE_SCOPE)
        cache[key] = max([v for k, v in s.items() if k.split("@")[0] in ("winsec", "sysmon")] or [0]) >= GATE_MIN
    return cache[key]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--tag", required=True)
    ap.add_argument("--vote", action="store_true")
    ap.add_argument("--gate", action="store_true")
    ap.add_argument("--out")
    ap.add_argument("--gate-scope", default="all", choices=["all", "relevant"])
    a = ap.parse_args()
    global GATE_SCOPE
    GATE_SCOPE = a.gate_scope
    groups = defaultdict(lambda: defaultdict(list))
    cost = defaultdict(float)
    invalid = defaultdict(int)
    for p in sorted((WS / "07_runs" / "v3" / a.tag).glob("*.json")):
        r = json.loads(p.read_text(encoding="utf-8"))
        g = (r["variant"], r["backend"])
        model = r["backend"].split(":", 1)[1]
        for at in r["attempts"]:
            u = at.get("usage") or {}
            if model in PRICE and u:
                cost[g] += u.get("input", 0) / 1e6 * PRICE[model][0] + u.get("output", 0) / 1e6 * PRICE[model][1]
        if not r.get("parsed"):
            invalid[g] += 1
        groups[g][(r["scenario_id"], r["condition"])].append((r.get("parsed") or {}).get("recommended_action", "collect_more"))
    L = [f"# v3 scores: {a.tag} (vote={a.vote}, silence gate={a.gate})\n",
         "| Variant | Backend | Cells | Correct | Justified closes | Unsupported closes | Unnecessary escalation (benign) | Invalid samples | API cost |",
         "|---|---|---|---|---|---|---|---|---|"]
    for g, cells in sorted(groups.items()):
        tot = cor = jus = uns = ue = closable = 0
        for (sid, c), acts in cells.items():
            lab = label(sid, c)
            if lab is None:
                continue
            finals = [vote(acts)] if a.vote else acts
            for f in finals:
                if a.gate and f == "close" and gate_fires(sid, c):
                    f = "collect_more"
                tot += 1
                cor += f in WANT[lab]
                jus += f == "close" and lab == "BENIGN_SUPPORTED"
                uns += f == "close" and lab != "BENIGN_SUPPORTED"
                if lab == "BENIGN_SUPPORTED":
                    closable += 1
                    ue += f == "escalate"
        L.append(f"| {g[0]} | {g[1]} | {tot} | {cor}/{tot} ({cor/max(tot,1):.0%}) | {jus}/{closable} | {uns} | {ue}/{closable} | {invalid[g]} | ${cost[g]:.2f} |")
    txt = "\n".join(L) + "\n"
    if a.out:
        Path(a.out).write_text(txt, encoding="utf-8")
    sys.stdout.reconfigure(encoding="utf-8")
    print(txt)


if __name__ == "__main__":
    main()
