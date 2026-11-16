"""v2 arms Jev-reviewer and R2-reviewer on the 45 frozen v1 answers (pre-registered rule, reviewer mode).

    tools/cuga-agent/.venv/Scripts/python.exe harness/run_rule_reviewers.py

Jev-reviewer: same 4 Jev questions as v1 + org context in the state; close if benign_explained >= 0.7 and
relevant_gap < 0.3 and malicious_supported < 0.3; escalate if malicious_supported >= 0.7; else collect_more.
R2-reviewer: close only if the investigator's assessment is benign and no decisive sensor (alert category table)
is bad in the C3 manifest or named in its limitations; escalate if the assessment is malicious; else collect_more.
Output: 08_analysis/v2/outputs/{Jev-reviewer,R2-reviewer}.jsonl
"""
import json
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
WS = HERE.parent
sys.path.insert(0, str(HERE))
from gates import JEV_MODEL, JEV_QUESTIONS, NO_COVERAGE  # noqa: E402

OUTD = WS / "08_analysis" / "v2" / "outputs"
CTX = (WS / "03_scenarios" / "configs" / "env_lakeview_v2.context.txt").read_text(encoding="utf-8").strip()
DECISIVE = json.loads((WS / "03_scenarios" / "decisive_sensors.json").read_text(encoding="utf-8"))


def main():
    from typesafe_sdk import Noul, TypeSafeClient
    OUTD.mkdir(parents=True, exist_ok=True)
    recs = [json.loads(l) for l in open(WS / "08_analysis" / "v2" / "eval_inputs.jsonl", encoding="utf-8")]
    fj = open(OUTD / "Jev-reviewer.jsonl", "w", encoding="utf-8")
    fr = open(OUTD / "R2-reviewer.jsonl", "w", encoding="utf-8")
    with TypeSafeClient(model=JEV_MODEL) as jev:
        for r in recs:
            run = json.loads((WS / "07_runs" / "raw" / f"{r['run_id']}.json").read_text(encoding="utf-8"))
            inv = run["parsed"]
            meta = json.loads((WS / "03_scenarios" / "configs" / f"{r['scenario_id']}.meta.json").read_text(encoding="utf-8"))
            man = meta["coverage_manifest"] if r["condition"] == "C3" else None
            # Jev-reviewer
            try:
                resp = jev.system_one(state={"organization_context": CTX, "investigator_findings": inv,
                                             "coverage_information": man if man is not None else NO_COVERAGE},
                                      questions={k: Noul(**v) for k, v in JEV_QUESTIONS.items()})
                p = {k: resp.nouls[k].noul for k in JEV_QUESTIONS}
                if p["benign_explained"] >= 0.7 and p["relevant_gap"] < 0.3 and p["malicious_supported"] < 0.3:
                    act, st = "close", "benign_supported"
                elif p["malicious_supported"] >= 0.7:
                    act, st = "escalate", "malicious_supported"
                else:
                    act, st = "collect_more", "insufficient_evidence"
                out = {"parsed": {"epistemic_status": st, "recommended_action": act}, "probabilities": p, "model": resp.model}
            except Exception as e:
                out = {"parsed": None, "error": f"{type(e).__name__}: {e}"}
            fj.write(json.dumps({"run_id": r["run_id"], "reviewer": "Jev-reviewer", **out}) + "\n")
            # R2-reviewer
            decisive = set(DECISIVE.get(meta["alert_category"], []))
            bad = {s["sensor"] for s in (man or {}).get("sensors", []) if s.get("status") != "ok"}
            lim = " ".join(inv.get("known_telemetry_limitations", [])).lower()
            hit = (decisive & bad) | {s for s in decisive if s.lower() in lim}
            if inv["assessment"] == "benign" and not hit:
                act, st = "close", "benign_supported"
            elif inv["assessment"] == "malicious":
                act, st = "escalate", "malicious_supported"
            else:
                act, st = "collect_more", "insufficient_evidence"
            fr.write(json.dumps({"run_id": r["run_id"], "reviewer": "R2-reviewer",
                                 "parsed": {"epistemic_status": st, "recommended_action": act}, "decisive_hit": sorted(hit)}) + "\n")
            print(r["run_id"], "done", flush=True)
    fj.close()
    fr.close()


if __name__ == "__main__":
    main()
