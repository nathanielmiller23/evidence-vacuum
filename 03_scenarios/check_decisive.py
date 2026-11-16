"""Automatic decisive-token check for T-pool cells (v3). Writes tpool/decisive_check.json.

A cell's rule label is only valid if the gap does what its gap_type says:
  consequential     -> decisive token present in C1 and ABSENT in C2 (the gap hides the decisive evidence)
  non-consequential -> decisive token present in C2 (the decisive evidence survives the gap)
Invalid scenarios have their C2/C3 cells excluded from training (C1 stays valid either way if the token is in C1).
Usage: python 03_scenarios/check_decisive.py T001 ... (default: all T*.meta.json with built views)
"""
import json
import sys
from pathlib import Path

import yaml

HERE = Path(__file__).resolve().parent
CFG = HERE / "tpool" / "configs"
COND = HERE.parent / "04_conditions"


def token(meta, y):
    arch = meta["archetype"]
    evs = [e for st in y["storyline"] for e in st["events"]]
    if arch == "spray":
        return next(e["source_ip"] for e in evs if e["type"] == "credential_spray")
    if arch == "svc_rotation":
        return next(e["target_accounts"][0] for e in evs if e["type"] == "credential_spray")
    if arch == "macro_ps":
        return "svchelper.dll"
    if arch == "admin_patch":
        cl = next(e["command_line"] for e in evs if e["type"] == "process" and "-File" in e.get("command_line", ""))
        return cl.split("\\")[-1]
    if arch in ("beacon", "updater"):
        return next(e["hostname"] for e in evs if e["type"] == "beacon")
    if arch in ("rogue_admin", "helpdesk_temp"):
        return next(e["target_username"] for e in evs if e["type"] == "account_created")
    if arch in ("exfil", "backup_upload"):
        return [e["hostname"] for e in evs if e["type"] == "connection"][-1]
    raise ValueError(arch)


FAIL_IDS = ("eventid=4625", "eventid=4771", "eventid=4776")


def count(path, tok, failures_only=False):
    """Lines containing the token; for auth archetypes only failed-logon records count as decisive."""
    if not path.exists():
        return None
    t = tok.lower()
    n = 0
    for line in path.read_text(encoding="utf-8").splitlines():
        low = line.lower()
        if t in low and (not failures_only or any(f in low for f in FAIL_IDS)):
            n += 1
    return n


def main(ids):
    out = {}
    for tid in ids:
        meta = json.loads((CFG / f"{tid}.meta.json").read_text(encoding="utf-8"))
        y = yaml.safe_load((CFG / f"{tid}.yaml").read_text(encoding="utf-8"))
        tok = token(meta, y)
        fo = meta["archetype"] in ("spray", "svc_rotation")
        c1 = count(COND / "complete" / tid / "events.jsonl", tok, fo)
        c2 = count(COND / "partial_undocumented" / tid / "events.jsonl", tok, fo)
        if c1 is None or c2 is None:
            out[tid] = {"status": "missing_views"}
            continue
        cons = meta["gap_type"] == "consequential"
        ok_c1 = c1 > 0
        ok_gap = (c2 == 0) if cons else (c2 > 0)
        out[tid] = {"archetype": meta["archetype"], "gap_type": meta["gap_type"], "token": tok, "c1": c1, "c2": c2,
                    "valid_C1": ok_c1, "valid_C2C3": ok_c1 and ok_gap}
    (HERE / "tpool" / "decisive_check.json").write_text(json.dumps(out, indent=1), encoding="utf-8")
    bad = {k: v for k, v in out.items() if not v.get("valid_C2C3", False)}
    print(f"checked {len(out)}; C2/C3 invalid: {len(bad)}; C1 invalid: {sum(1 for v in out.values() if not v.get('valid_C1', False))}")
    for k, v in sorted(bad.items()):
        print(" ", k, v)


if __name__ == "__main__":
    ids = sys.argv[1:] or sorted(p.name.split(".")[0] for p in CFG.glob("T*.meta.json"))
    main(ids)
