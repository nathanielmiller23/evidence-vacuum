"""Decision layers applied post hoc to a frozen investigator run (Config A -> B, Config C -> D).

    tools/cuga-agent/.venv/Scripts/python.exe harness/gates.py 07_runs/pilot/<run_id>.json [...]

Gates (all see the same inputs: the investigator's parsed JSON + the coverage manifest in C3 only;
never raw logs, ground truth, rubric labels or the condition label):
  jev  - TypeSafe Jev (pinned version), atomic Noul questions; decision logic in code
  r0   - deterministic: block close if any limitation is stated or (C3) any sensor is not ok
  r2   - deterministic: block close if a DECISIVE sensor for the scenario's archetype is not ok (C3)
         or is named in the investigator's limitations

Combination (06_prompts/jev_gate_spec.md): gates only BLOCK closures. Invalid / failed gate output is
fail-open (final = investigator's action) and is counted.
Design follows docs.typesafe.ai guidance: narrow atomic Nouls in one request, logic and thresholds
in code, no arithmetic or date comparison asked of Jev.
"""
import json
import os
import sys
import time
from pathlib import Path

from dotenv import load_dotenv

HERE = Path(__file__).resolve().parent
WS = HERE.parent
load_dotenv(WS / ".env")

JEV_MODEL = os.environ.get("JEV_MODEL_ID") or "jev-1.14.0"   # pinned version, not an alias
CLOSE_THRESHOLD = 0.7        # P(benign_explained) needed to allow a close (pre-registered)
GAP_THRESHOLD = 0.3          # P(relevant_gap) must be below this to allow a close (docs' Noul-screen bands 0.7 / 0.3)
MALICIOUS_THRESHOLD = 0.7    # when a close is blocked: escalate if P(malicious_supported) >= this, else collect_more
DECISIVE_SENSORS = WS / "03_scenarios" / "decisive_sensors.json"   # {archetype: [sensor, ...]}, frozen before runs

NO_COVERAGE = "No sensor coverage information was provided."

JEV_QUESTIONS = {
    # Decision questions (atomic; the rule combining them is in code, see gate_jev)
    "benign_explained": dict(
        instructions="The findings cite at least one observed log record that positively explains the alerted "
                     "activity as legitimate, such as a change ticket, a scheduled administrative task, or a known "
                     "authorized account."),
    # v2 wording (after P02): v1 fired on any stated caveat (e.g. "logs don't show the payload").
    "relevant_gap": dict(
        instructions="A sensor or log source needed to check the alerted host and time was offline, not deployed, "
                     "not collected, or stopped reporting during that time.",
        criteria={"true": "The coverage information or the findings name a specific sensor or log source that was down, "
                          "missing, or not collected for the alerted host or time.",
                  "false": "Every needed sensor was operating; the findings only note that the logs lack certain details "
                           "(such as file contents or payloads) or that authorization was not recorded."}),
    "malicious_supported": dict(
        instructions="The investigator findings establish that malicious activity occurred."),
    # Diagnostic question (logged for the failure analysis; does not drive the decision)
    "absence_as_evidence": dict(
        instructions="The findings treat the lack of log records as a reason to conclude that activity did not happen."),
}


def _manifest(run: dict):
    if run["condition"] != "C3":
        return None
    p = WS / "04_conditions" / "partial_documented" / run["scenario_id"] / "coverage_manifest.json"
    return json.loads(p.read_text(encoding="utf-8")) if p.exists() else None


def _bad_sensors(manifest) -> set[str]:
    if not manifest:
        return set()
    return {s["sensor"] for s in manifest.get("sensors", []) if s.get("status") != "ok"}


def gate_jev(parsed: dict, manifest) -> dict:
    from typesafe_sdk import Noul, TypeSafeClient
    state = {"investigator_findings": parsed,
             "coverage_information": manifest if manifest is not None else NO_COVERAGE}
    t0 = time.time()
    with TypeSafeClient(model=JEV_MODEL) as c:
        r = c.system_one(state=state, questions={k: Noul(**v) for k, v in JEV_QUESTIONS.items()})
    p = {k: r.nouls[k].noul for k in JEV_QUESTIONS}
    # Close is allowed only with a positive benign explanation AND no relevant gap.
    if p["benign_explained"] >= CLOSE_THRESHOLD and p["relevant_gap"] < GAP_THRESHOLD:
        action = "close"
    else:
        action = "escalate" if p["malicious_supported"] >= MALICIOUS_THRESHOLD else "collect_more"
    return {"action": action, "probabilities": p, "model": r.model,
            "usage": {"input_tokens": r.usage.input_tokens, "output_tokens": r.usage.output_tokens},
            "secs": round(time.time() - t0, 2)}


def gate_r0(parsed: dict, manifest) -> dict:
    blocked = bool(parsed.get("known_telemetry_limitations")) or bool(_bad_sensors(manifest))
    return {"action": "collect_more" if blocked else "close"}


def gate_r2(parsed: dict, manifest, scenario_id: str) -> dict:
    meta = json.loads((WS / "03_scenarios" / "configs" / f"{scenario_id}.meta.json").read_text(encoding="utf-8"))
    table = json.loads(DECISIVE_SENSORS.read_text(encoding="utf-8")) if DECISIVE_SENSORS.exists() else {}
    # Keyed by the ALERT category (shared by both members of a lookalike pair), never by the
    # ground-truth archetype, which a deployed rule could not know.
    decisive = set(table.get(meta.get("alert_category") or meta.get("archetype", ""), []))
    if not decisive:
        return {"action": None, "error": "no decisive-sensor entry for archetype"}
    lim_text = " ".join(parsed.get("known_telemetry_limitations", [])).lower()
    hit = (decisive & _bad_sensors(manifest)) | {s for s in decisive if s.lower() in lim_text}
    return {"action": "collect_more" if hit else "close", "decisive": sorted(decisive), "hit": sorted(hit)}


def combine(inv_action: str, gate: dict) -> tuple[str, str]:
    if inv_action != "close":
        return inv_action, "investigator_not_close"
    if gate.get("action") is None:
        return "close", "gate_invalid_fail_open"
    if gate["action"] != "close":
        return gate["action"], "gate_blocked_close"
    return "close", "gate_allowed_close"


def run_gates(run_path: Path) -> Path:
    run = json.loads(run_path.read_text(encoding="utf-8"))
    out = {"run_id": run["run_id"], "scenario_id": run["scenario_id"], "condition": run["condition"],
           "base_config": run["config"], "jev_model_requested": JEV_MODEL,
           "close_threshold": CLOSE_THRESHOLD, "gap_threshold": GAP_THRESHOLD,
           "malicious_threshold": MALICIOUS_THRESHOLD, "gates": {}}
    parsed = run.get("parsed")
    if parsed is None:
        out["final"] = {g: {"final_action": "INVALID", "reason": "investigator_invalid"} for g in ("jev", "r0", "r2")}
    else:
        manifest = _manifest(run)
        for name, fn in (("jev", lambda: gate_jev(parsed, manifest)),
                         ("r0", lambda: gate_r0(parsed, manifest)),
                         ("r2", lambda: gate_r2(parsed, manifest, run["scenario_id"]))):
            try:
                out["gates"][name] = fn()
            except Exception as e:  # recorded, fail-open
                out["gates"][name] = {"action": None, "error": f"{type(e).__name__}: {e}"}
        out["investigator_action"] = parsed["recommended_action"]
        out["final"] = {}
        for g, res in out["gates"].items():
            fa, reason = combine(parsed["recommended_action"], res)
            out["final"][g] = {"final_action": fa, "reason": reason}
    path = run_path.with_name(run_path.stem + "__gates.json")
    path.write_text(json.dumps(out, indent=1), encoding="utf-8")
    print(f"{run['run_id']}: investigator={out.get('investigator_action')} -> "
          + ", ".join(f"{g}={v['final_action']}({v['reason']})" for g, v in out["final"].items()))
    return path


if __name__ == "__main__":
    for p in sys.argv[1:]:
        run_gates(Path(p))
