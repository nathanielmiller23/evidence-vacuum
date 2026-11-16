"""Config C runner: one CUGA investigation of one (scenario, condition) view.

Usage (from the workspace root, with CUGA's venv):
    tools/cuga-agent/.venv/Scripts/python.exe harness/run_cuga.py --scenario DUMMY01 --condition C2 --out 07_runs/pilot

Reads keys and CUGA settings from <workspace>/.env (ENV_FILE). Saves one JSON per run with the
raw answer, parsed result, validation errors, CUGA's tool-call log, our own tool-call log, and
timing. Failures (timeout, exception, invalid JSON) are saved as outcomes, never dropped.
"""
import argparse
import asyncio
import hashlib
import json
import os
import shutil
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

HERE = Path(__file__).resolve().parent
WS = HERE.parent
CUGA_DIR = WS / "tools" / "cuga-agent"
SETTINGS_SRC = HERE / "cuga_config" / "settings.ev.toml"
SETTINGS_DST = CUGA_DIR / "src" / "cuga" / "configurations" / "models" / "settings.ev.toml"

# Must happen before `import cuga`: CUGA reads env + settings at import time.
os.environ.setdefault("ENV_FILE", str(WS / ".env"))
shutil.copyfile(SETTINGS_SRC, SETTINGS_DST)
sys.path.insert(0, str(HERE))

from log_tools import MAX_TOOL_CALLS, ToolSession  # noqa: E402
from prompts import SYSTEM, load_alert, load_context, user_prompt_tools  # noqa: E402
from validate import cited_ids_exist, parse_investigation  # noqa: E402


def _git_head(path: Path) -> str:
    try:
        return subprocess.run(["git", "-C", str(path), "rev-parse", "HEAD"], capture_output=True, text=True).stdout.strip()
    except Exception:
        return "unknown"


def _sha(p: Path) -> str:
    return hashlib.sha256(p.read_bytes()).hexdigest()[:16]


async def run_one(scenario: str, condition: str, out_dir: Path, timeout_s: int) -> Path:
    from cuga import CugaAgent  # imported late on purpose (see above)

    sess = ToolSession(scenario, condition)
    tools = sess.tools()
    task = user_prompt_tools(load_alert(scenario), [t.name for t in tools], MAX_TOOL_CALLS, load_context(scenario))
    run_id = f"C__{scenario}__{condition}__{datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')}"

    agent = CugaAgent(tools=tools, special_instructions=SYSTEM, enable_knowledge=False,
                      auto_load_policies=False, filesystem_sync=False)
    record = {
        "run_id": run_id, "config": "C", "scenario_id": scenario, "condition": condition,
        "model": os.environ.get("MODEL_NAME"), "agent_setting_config": os.environ.get("AGENT_SETTING_CONFIG"),
        "settings_sha": _sha(SETTINGS_SRC), "cuga_commit": _git_head(CUGA_DIR),
        "max_tool_calls": MAX_TOOL_CALLS, "timeout_s": timeout_s,
        "system": SYSTEM, "task": task, "attempts": [], "error": None,
    }
    t0 = time.time()
    try:
        res = await asyncio.wait_for(agent.invoke(task, track_tool_calls=True), timeout_s)
        parsed, errs = parse_investigation(res.answer)
        record["attempts"].append({"answer": res.answer, "cuga_error": res.error, "valid": parsed is not None,
                                   "validation_errors": errs, "cuga_tool_calls": res.tool_calls})
        if parsed is None:  # one retry on the same thread, with the parser errors
            retry = ("Your previous answer did not conform to the required JSON schema. Errors: "
                     + "; ".join(errs[:5]) + ". Respond with only the corrected JSON object.")
            res2 = await asyncio.wait_for(agent.invoke(retry, thread_id=res.thread_id, track_tool_calls=True), timeout_s)
            parsed, errs = parse_investigation(res2.answer)
            record["attempts"].append({"answer": res2.answer, "cuga_error": res2.error, "valid": parsed is not None,
                                       "validation_errors": errs, "cuga_tool_calls": res2.tool_calls})
        record["parsed"] = parsed
        record["status"] = "VALID" if parsed is not None else "INVALID"
        if parsed is not None:
            record["faithfulness_precheck"] = cited_ids_exist(parsed, set(sess.by_id))
    except asyncio.TimeoutError:
        record.update(status="TIMEOUT", parsed=None, error=f"timeout after {timeout_s}s")
    except Exception as e:  # recorded, not swallowed
        record.update(status="ERROR", parsed=None, error=f"{type(e).__name__}: {e}")
    finally:
        record["duration_s"] = round(time.time() - t0, 1)
        record["our_tool_calls"] = sess.calls
        try:
            await agent.aclose()
        except Exception:
            pass

    out_dir.mkdir(parents=True, exist_ok=True)
    path = out_dir / f"{run_id}.json"
    path.write_text(json.dumps(record, indent=1, default=str), encoding="utf-8")
    print(f"{record['status']}  {run_id}  {record['duration_s']}s  tool calls: {len(sess.calls)}  -> {path}")
    return path


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--scenario", required=True)
    ap.add_argument("--condition", required=True, choices=["C1", "C2", "C3"])
    ap.add_argument("--out", default=str(WS / "07_runs" / "pilot"))
    ap.add_argument("--timeout", type=int, default=300)
    ap.add_argument("--infra-retries", type=int, default=2,
                    help="re-run from scratch when a run dies on a connection error before any tool call")
    a = ap.parse_args()
    for attempt in range(a.infra_retries + 1):
        path = asyncio.run(run_one(a.scenario, a.condition, Path(a.out), a.timeout))
        rec = json.loads(path.read_text(encoding="utf-8"))
        infra = rec["status"] == "ERROR" and "Connection" in (rec.get("error") or "") and not rec["our_tool_calls"]
        if not infra:
            break
        path.rename(path.with_suffix(".infra_error.json"))   # kept for the record, excluded from scoring
        print(f"infra error, retrying ({attempt + 1}/{a.infra_retries})")
        time.sleep(10)


if __name__ == "__main__":
    main()
