"""Run Config A on every T-pool cell (training data for v2), N samples per cell, K parallel workers.

    tools/cuga-agent/.venv/Scripts/python.exe harness/run_tpool.py --samples 2 --workers 4

Output: 07_runs/tpool/A__T###__C#__<ts>.json (same record format as v1). Resumable (counts existing samples).
"""
import argparse
import subprocess
import sys
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

HERE = Path(__file__).resolve().parent
WS = HERE.parent
OUT = WS / "07_runs" / "tpool"


def have(tid, cond):
    return len([p for p in OUT.glob(f"A__{tid}__{cond}__*.json") if not p.name.endswith(".infra_error.json")])


def run(cell):
    tid, cond = cell
    r = subprocess.run([sys.executable, str(HERE / "run_fixed.py"), "--scenario", tid, "--condition", cond, "--out", str(OUT)],
                       capture_output=True, text=True, encoding="utf-8", errors="replace", cwd=WS)
    st = [l.split()[0] for l in r.stdout.splitlines() if l.startswith(("VALID", "INVALID", "ERROR"))]
    return f"{tid} {cond} {st[-1] if st else 'NO-STATUS'}"


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--samples", type=int, default=2)
    ap.add_argument("--workers", type=int, default=4)
    ap.add_argument("--upto", type=int, default=None,
                    help="only run T-scenarios up to this number (60 = the v2 pool T001-T060); default: every built T-view")
    a = ap.parse_args()
    OUT.mkdir(parents=True, exist_ok=True)
    tids = sorted(p.stem for p in (WS / "04_conditions" / "complete").glob("T*"))
    if a.upto is not None:
        tids = [t for t in tids if int(t[1:]) <= a.upto]
    jobs = []
    for tid in tids:
        for cond in ("C1", "C2", "C3"):
            jobs += [(tid, cond)] * max(0, a.samples - have(tid, cond))
    print(f"{len(tids)} T-scenarios; {len(jobs)} runs to do", flush=True)
    done = 0
    with ThreadPoolExecutor(a.workers) as ex:
        for msg in ex.map(run, jobs):
            done += 1
            if done % 20 == 0 or not msg.endswith(" VALID"):
                print(f"[{done}/{len(jobs)}] {msg}", flush=True)
    print("finished", done, flush=True)


if __name__ == "__main__":
    main()
