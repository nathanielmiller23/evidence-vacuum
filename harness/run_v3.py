"""v3 investigator runner: prompt variant x backend x samples over a list of cells, in parallel. Resumable.

    python harness/run_v3.py --cells 08_analysis/v3/dev36.json --variant P2 --backend openai:gpt-6-luna --samples 1 --tag stage2 --workers 6
    backends: openai:<model>   adaption:<hosted model id, e.g. gemma-4-31b-it>
Output: 07_runs/v3/<tag>/<variant>__<backend>__<SID>__<cond>__s<k>.json
"""
import argparse
import json
import re
import sys
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

from dotenv import load_dotenv
from jsonschema import Draft202012Validator

HERE = Path(__file__).resolve().parent
WS = HERE.parent
load_dotenv(WS / ".env")
sys.path.insert(0, str(HERE))
from log_tools import ToolSession, view_dir  # noqa: E402
from prompts import load_alert, load_context  # noqa: E402
from prompts_v3 import build  # noqa: E402
from validate import cited_ids_exist  # noqa: E402

COND = {"C1": "complete", "C2": "partial_undocumented", "C3": "partial_documented"}


def parse(text, schema):
    t = (text or "").strip()
    t = re.sub(r"^```(?:json)?\s*|\s*```$", "", t)
    try:
        obj = json.loads(t)
    except Exception as e:
        m = re.search(r"\{.*\}", t, re.S)
        if not m:
            return None, [f"json: {e}"]
        try:
            obj = json.loads(m.group(0))
        except Exception as e2:
            return None, [f"json: {e2}"]
    errs = [e.message for e in Draft202012Validator(schema).iter_errors(obj)]
    return (obj if not errs else None), errs


def call(backend, system, user):
    kind, model = backend.split(":", 1)
    if kind == "openai":
        from openai import OpenAI
        r = OpenAI().chat.completions.create(model=model, messages=[{"role": "system", "content": system},
                                                                    {"role": "user", "content": user}],
                                             max_completion_tokens=16000)
        u = r.usage
        return r.choices[0].message.content or "", {"input": u.prompt_tokens, "output": u.completion_tokens}
    if kind == "adaption":
        from adaption import Adaption
        r = Adaption().responses.create(model=model, input=f"[SYSTEM]\n{system}\n\n[USER]\n{user}")
        return r.output_text or "", {}
    raise ValueError(backend)


def run_cell(args):
    sid, cond, variant, backend, k, out_dir = args
    bname = backend.replace(":", "-")
    path = out_dir / f"{variant}__{bname}__{sid}__{cond}__s{k}.json"
    if path.exists():
        return path, "skip"
    sess = ToolSession(sid, cond)
    events = (view_dir(sid, cond) / "events.jsonl").read_text(encoding="utf-8")
    system, user, schema = build(variant, load_alert(sid), events, sess.manifest, load_context(sid))
    rec = {"scenario_id": sid, "condition": cond, "variant": variant, "backend": backend, "sample": k, "attempts": []}
    t0 = time.time()
    parsed = None
    for attempt in range(3):
        try:
            text, usage = call(backend, system, user)
        except Exception as e:  # infra error: retry, then record
            rec["attempts"].append({"error": f"{type(e).__name__}: {e}"})
            time.sleep(8 * (attempt + 1))
            continue
        parsed, errs = parse(text, schema)
        rec["attempts"].append({"answer": text, "valid": parsed is not None, "errors": errs[:5], "usage": usage})
        if parsed is not None:
            break
    rec["parsed"] = parsed
    rec["status"] = "VALID" if parsed else "INVALID"
    if parsed:
        rec["faithfulness_precheck"] = cited_ids_exist(parsed, set(sess.by_id))
    rec["duration_s"] = round(time.time() - t0, 1)
    out_dir.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(rec, indent=1, default=str), encoding="utf-8")
    return path, rec["status"]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--cells", required=True, help="JSON list of [scenario_id, condition]")
    ap.add_argument("--variant", required=True)
    ap.add_argument("--backend", required=True)
    ap.add_argument("--samples", type=int, default=1)
    ap.add_argument("--tag", required=True)
    ap.add_argument("--workers", type=int, default=6)
    a = ap.parse_args()
    cells = json.loads(Path(a.cells).read_text(encoding="utf-8"))
    out_dir = WS / "07_runs" / "v3" / a.tag
    jobs = [(s, c, a.variant, a.backend, k, out_dir) for (s, c) in cells for k in range(a.samples)]
    n = {"VALID": 0, "INVALID": 0, "skip": 0}
    with ThreadPoolExecutor(a.workers) as ex:
        for path, st in ex.map(run_cell, jobs):
            n[st] = n.get(st, 0) + 1
            print(st, path.name, flush=True)
    print("done", n)


if __name__ == "__main__":
    main()
