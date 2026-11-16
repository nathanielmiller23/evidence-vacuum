"""v3 Stage 1a (EXPLORATORY, post hoc on seen v2 data): paired control = G-ft proposes, a gap check can veto a close.
Veto turns a 'close' into 'collect_more'. Gap checks: R2 decisive-sensor rule; Jev relevant_gap >= theta (sweep).
Writes 08_analysis/v3/stage1_paired_control.md
"""
import json
import sys
from pathlib import Path

WS = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(WS / "08_analysis"))
from score_v2 import WANT  # noqa: E402

V2 = WS / "08_analysis" / "v2"
recs = [json.loads(l) for l in open(V2 / "eval_inputs.jsonl", encoding="utf-8")]
load = lambda n: {json.loads(l)["run_id"]: json.loads(l) for l in open(V2 / "outputs" / f"{n}.jsonl", encoding="utf-8") if l.strip()}
G, R2, J = load("G-ft"), load("R2-reviewer"), load("Jev-reviewer")


def act_of(o, r):
    p = (o or {}).get("parsed")
    return p["recommended_action"] if p else r["investigator_action"]


def score(name, fn):
    rows = []
    for r in recs:
        a = fn(r)
        rows.append(dict(correct=int(a in WANT[r["label"]]), just=int(a == "close" and r["closure_defensible"] == "yes"),
                         unsup=int(a == "close" and r["closure_defensible"] == "no"),
                         run=r["run_id"], a=a))
    n_def = sum(1 for r in recs if r["closure_defensible"] == "yes")
    return f"| {name} | {sum(x['correct'] for x in rows)}/45 | {sum(x['just'] for x in rows)}/{n_def} | {sum(x['unsup'] for x in rows)} |", rows


L = ["# v3 Stage 1a: paired control, post hoc on v2 outputs (EXPLORATORY: this data has been seen)\n",
     "Veto rule: if the gap check objects, a proposed `close` becomes `collect_more`.\n",
     "| Pipeline | Correct | Justified closes | Unsupported closes |", "|---|---|---|---|"]
line, base = score("G-ft alone", lambda r: act_of(G.get(r["run_id"]), r)); L.append(line)
gft = lambda r: act_of(G.get(r["run_id"]), r)
line, _ = score("G-ft + R2 veto", lambda r: ("collect_more" if gft(r) == "close" and act_of(R2.get(r["run_id"]), r) != "close" else gft(r))); L.append(line)
for th in (0.1, 0.2, 0.3, 0.4, 0.5, 0.6):
    def f(r, th=th):
        a = gft(r)
        pr = (J.get(r["run_id"]) or {}).get("probabilities", {})
        return "collect_more" if a == "close" and pr.get("relevant_gap", 0) >= th else a
    line, _ = score(f"G-ft + Jev relevant_gap veto (>= {th})", f); L.append(line)
L.append("\n## G-ft closes and what each check said\n")
L.append("| run | label | closure defensible | R2 action | Jev relevant_gap |")
L.append("|---|---|---|---|---|")
for r in recs:
    if gft(r) == "close":
        pr = (J.get(r["run_id"]) or {}).get("probabilities", {})
        L.append(f"| {r['run_id']} | {r['label']} | {r['closure_defensible']} | {act_of(R2.get(r['run_id']), r)} | {pr.get('relevant_gap')} |")
out = WS / "08_analysis" / "v3" / "stage1_paired_control.md"
out.write_text("\n".join(L) + "\n", encoding="utf-8")
print("\n".join(L))
