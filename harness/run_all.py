"""Full experiment runner: every (scenario, condition) for one config, in a seeded random order.

    tools/cuga-agent/.venv/Scripts/python.exe harness/run_all.py --config A
    tools/cuga-agent/.venv/Scripts/python.exe harness/run_all.py --config C

Resumable: a cell that already has a non-infra-error record in --out is skipped. Each run is a separate
process (the same runners used in the pilot), so a crash in one run can't affect the others.
B and D are produced afterwards by harness/gates.py on these frozen outputs.
"""
import argparse
import json
import random
import subprocess
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
WS = HERE.parent
SIDS = ["S01", "S08", "S02", "S07", "S04", "S10", "S06", "S12"]
CONDS = ["C1", "C2", "C3"]
SEED = {"A": 20261115, "C": 20261116}


def done(out: Path, cfg: str, sid: str, cond: str) -> bool:
    for p in out.glob(f"{cfg}__{sid}__{cond}__*.json"):
        if p.name.endswith(("__gates.json", ".infra_error.json")):
            continue
        return True
    return False


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--config", required=True, choices=["A", "C"])
    ap.add_argument("--out", default=str(WS / "07_runs" / "raw"))
    a = ap.parse_args()
    out = Path(a.out)
    out.mkdir(parents=True, exist_ok=True)
    cells = [(s, c) for s in SIDS for c in CONDS]
    random.Random(SEED[a.config]).shuffle(cells)
    (out / f"_order_{a.config}.json").write_text(json.dumps(cells), encoding="utf-8")
    script = "run_fixed.py" if a.config == "A" else "run_cuga.py"
    for i, (sid, cond) in enumerate(cells, 1):
        if done(out, a.config, sid, cond):
            print(f"[{i}/24] {a.config} {sid} {cond} already done, skipping", flush=True)
            continue
        cmd = [sys.executable, str(HERE / script), "--scenario", sid, "--condition", cond, "--out", str(out)]
        if a.config == "C":
            cmd += ["--timeout", "400"]
        r = subprocess.run(cmd, capture_output=True, text=True, encoding="utf-8", errors="replace", cwd=WS)
        status = [l for l in r.stdout.splitlines() if l.startswith(("VALID", "INVALID", "ERROR", "TIMEOUT", "infra"))]
        print(f"[{i}/24] {a.config} {sid} {cond}: {' | '.join(status) or 'NO STATUS (rc=%d)' % r.returncode}"[:220], flush=True)


if __name__ == "__main__":
    main()
