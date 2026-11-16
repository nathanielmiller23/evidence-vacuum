"""Config A runner: the whole (scenario, condition) view goes into the prompt; one direct API call.

    tools/cuga-agent/.venv/Scripts/python.exe harness/run_fixed.py --scenario P01 --condition C2 --out 07_runs/pilot

Same model, system prompt, objective and schema as Config C (harness/prompts.py). No temperature is
sent (gpt-6-luna accepts only the default). One retry on invalid JSON, in the same conversation.
Failures are saved as outcomes.
"""
import argparse
import json
import os
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

from dotenv import load_dotenv
from openai import OpenAI

HERE = Path(__file__).resolve().parent
WS = HERE.parent
load_dotenv(WS / ".env")
sys.path.insert(0, str(HERE))

from log_tools import ToolSession, view_dir  # noqa: E402
from prompts import SYSTEM, load_alert, load_context, user_prompt_fixed  # noqa: E402
from validate import cited_ids_exist, parse_investigation  # noqa: E402

MAX_OUTPUT_TOKENS = 16000   # same budget as CUGA's roles


def _usage(r) -> dict:
    u = r.usage
    d = getattr(u, "completion_tokens_details", None)
    return {"input": u.prompt_tokens, "output": u.completion_tokens,
            "reasoning": getattr(d, "reasoning_tokens", None)}


def run_one(scenario: str, condition: str, out_dir: Path) -> Path:
    model = os.environ["MODEL_NAME"]
    sess = ToolSession(scenario, condition)          # reused only to load the same view + manifest
    events = (view_dir(scenario, condition) / "events.jsonl").read_text(encoding="utf-8")
    user = user_prompt_fixed(load_alert(scenario), events, sess.manifest, load_context(scenario))
    run_id = f"A__{scenario}__{condition}__{datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')}"
    msgs = [{"role": "system", "content": SYSTEM}, {"role": "user", "content": user}]
    record = {"run_id": run_id, "config": "A", "scenario_id": scenario, "condition": condition,
              "model": model, "n_records_in_view": len(sess.records), "system": SYSTEM,
              "task_chars": len(user), "attempts": [], "error": None}
    client = OpenAI()
    t0 = time.time()
    try:
        for attempt in range(2):
            r = client.chat.completions.create(model=model, messages=msgs, max_completion_tokens=MAX_OUTPUT_TOKENS)
            answer = r.choices[0].message.content or ""
            parsed, errs = parse_investigation(answer)
            record["attempts"].append({"answer": answer, "valid": parsed is not None, "validation_errors": errs,
                                       "model_returned": r.model, "finish_reason": r.choices[0].finish_reason,
                                       "usage": _usage(r)})
            if parsed is not None:
                break
            msgs += [{"role": "assistant", "content": answer},
                     {"role": "user", "content": "Your previous answer did not conform to the required JSON schema. "
                      "Errors: " + "; ".join(errs[:5]) + ". Respond with only the corrected JSON object."}]
        record["parsed"] = parsed
        record["status"] = "VALID" if parsed is not None else "INVALID"
        if parsed is not None:
            record["faithfulness_precheck"] = cited_ids_exist(parsed, set(sess.by_id))
    except Exception as e:  # recorded, not swallowed
        record.update(status="ERROR", parsed=None, error=f"{type(e).__name__}: {e}")
    record["duration_s"] = round(time.time() - t0, 1)
    out_dir.mkdir(parents=True, exist_ok=True)
    path = out_dir / f"{run_id}.json"
    path.write_text(json.dumps(record, indent=1, default=str), encoding="utf-8")
    u = record["attempts"][-1]["usage"] if record["attempts"] else {}
    print(f"{record['status']}  {run_id}  {record['duration_s']}s  tokens in/out={u.get('input')}/{u.get('output')} -> {path}")
    return path


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--scenario", required=True)
    ap.add_argument("--condition", required=True, choices=["C1", "C2", "C3"])
    ap.add_argument("--out", default=str(WS / "07_runs" / "pilot"))
    ap.add_argument("--infra-retries", type=int, default=2,
                    help="re-run when the API call dies on a connection error (no model output)")
    a = ap.parse_args()
    for attempt in range(a.infra_retries + 1):
        path = run_one(a.scenario, a.condition, Path(a.out))
        rec = json.loads(path.read_text(encoding="utf-8"))
        if not (rec["status"] == "ERROR" and "Connection" in (rec.get("error") or "") and not rec["attempts"]):
            break
        path.rename(path.with_suffix(".infra_error.json"))   # kept for the record, excluded from scoring
        print(f"infra error, retrying ({attempt + 1}/{a.infra_retries})")
        time.sleep(10)
