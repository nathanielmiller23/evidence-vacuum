"""v2 arms H-hosted / H-stack: run the identical reviewer prompt on Adaption's Responses API.

    tools/cuga-agent/.venv/Scripts/python.exe harness/run_hosted_reviewer.py --model gemma-4-31b-it --name H-hosted
    tools/cuga-agent/.venv/Scripts/python.exe harness/run_hosted_reviewer.py --model stack:<slug> --name H-stack
    tools/cuga-agent/.venv/Scripts/python.exe harness/run_hosted_reviewer.py --list-models

Needs ADAPTION_API_KEY in .env. Input: 08_analysis/v2/eval_inputs.jsonl (45 frozen v1 answers). Output:
08_analysis/v2/outputs/<name>.jsonl (resumable). The prompt is sent verbatim as the single input, exactly
as G-base/G-ft receive it as one user turn.
"""
import argparse
import json
import sys
import time
from pathlib import Path

from dotenv import load_dotenv

HERE = Path(__file__).resolve().parent
WS = HERE.parent
load_dotenv(WS / ".env")
sys.path.insert(0, str(HERE))
from reviewer import parse_review  # noqa: E402

INPUTS = WS / "08_analysis" / "v2" / "eval_inputs.jsonl"
OUTD = WS / "08_analysis" / "v2" / "outputs"


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--model")
    ap.add_argument("--name")
    ap.add_argument("--list-models", action="store_true")
    a = ap.parse_args()
    from adaption import Adaption
    client = Adaption()
    if a.list_models:
        for m in client.models.list(type="hosted"):
            print(getattr(m, "id", m))
        return
    OUTD.mkdir(parents=True, exist_ok=True)
    out = OUTD / f"{a.name}.jsonl"
    done = {json.loads(l)["run_id"] for l in open(out, encoding="utf-8")} if out.exists() else set()
    recs = [json.loads(l) for l in open(INPUTS, encoding="utf-8") if l.strip()]
    with open(out, "a", encoding="utf-8") as f:
        for r in recs:
            if r["run_id"] in done:
                continue
            t0 = time.time()
            text, err = None, None
            for attempt in range(3):
                try:
                    resp = client.responses.create(model=a.model, input=r["prompt"])
                    text = resp.output_text
                    break
                except Exception as e:  # infra errors only are retried
                    err = f"{type(e).__name__}: {e}"
                    time.sleep(5 * (attempt + 1))
            parsed = parse_review(text) if text else None
            f.write(json.dumps({"run_id": r["run_id"], "reviewer": a.name, "model": a.model, "raw": text, "parsed": parsed,
                                "error": None if text else err, "secs": round(time.time() - t0, 2)}, ensure_ascii=False) + "\n")
            f.flush()
            print(f"{r['run_id']}: {(parsed or {}).get('recommended_action', 'INVALID')}", flush=True)


if __name__ == "__main__":
    main()
