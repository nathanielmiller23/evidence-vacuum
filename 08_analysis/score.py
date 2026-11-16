"""Score the frozen runs against the frozen rubric (PROTOCOL §5–6). Deterministic; re-run any time.

    tools/cuga-agent/.venv/Scripts/python.exe 08_analysis/score.py

Inputs : 07_runs/raw/{A,C}__S*.json (+ __gates.json), 05_rubric/cell_labels.csv, scenario metas.
Outputs (08_analysis/):
  scored_rows.csv / .jsonl   one row per (run × decision layer). Also the labeled dataset for the
                             Adaption Visualize import (checklist 8.3).
  metrics.md                 metric table by layer × condition with Wilson 95% CIs, paired tests, CUGA traces
  hand_scoring_blind.csv     anonymized, shuffled sheet for the hand check of coverage awareness (step 6.1)
Decision layers: A, C (no gate) · B = A+Jev, D = C+Jev · A+R0, A+R2, C+R0, C+R2 (controls).
"""
import csv
import json
import math
import random
import re
from collections import defaultdict
from pathlib import Path

import numpy as np

WS = Path(__file__).resolve().parents[1]
RAW = WS / "07_runs" / "raw"
OUT = WS / "08_analysis"
LAYER_NAME = {("A", None): "A", ("A", "jev"): "B", ("C", None): "C", ("C", "jev"): "D",
              ("A", "r0"): "A+R0", ("A", "r2"): "A+R2", ("C", "r0"): "C+R0", ("C", "r2"): "C+R2"}
MAP = {"malicious": "MALICIOUS_SUPPORTED", "benign": "BENIGN_SUPPORTED", "insufficient_evidence": "INSUFFICIENT"}
SENSOR_WORDS = {"sysmon": r"sysmon|endpoint|process|edr", "winsec": r"security|event log|windows event|authentication|logon|wef|event forwarding",
                "proxy": r"proxy"}


def wilson(k, n, z=1.96):
    if n == 0:
        return (float("nan"), float("nan"))
    p = k / n
    d = 1 + z * z / n
    c = (p + z * z / (2 * n)) / d
    h = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / d
    return (max(0.0, c - h), min(1.0, c + h))


def mcnemar_exact(b, c):
    """Two-sided exact McNemar on discordant counts b (x=1,y=0) and c (x=0,y=1)."""
    n = b + c
    if n == 0:
        return 1.0
    k = min(b, c)
    p = sum(math.comb(n, i) for i in range(0, k + 1)) / 2 ** n
    return min(1.0, 2 * p)


def paired_boot(x, y, reps=10000, seed=7):
    x, y = np.array(x, float), np.array(y, float)
    rng = np.random.default_rng(seed)
    idx = rng.integers(0, len(x), size=(reps, len(x)))
    d = (y[idx] - x[idx]).mean(axis=1)
    return float((y - x).mean()), float(np.percentile(d, 2.5)), float(np.percentile(d, 97.5))


def coverage_mentioned(limits, meta):
    """Heuristic auto-score: a limitation names a gapped host AND a gapped sensor family. Hand-checked in 6.1."""
    text = " ".join(limits).lower()
    hosts = [h.lower() for h in meta["gap"]["hosts"] if h != "*"] or ["proxy"]
    host_hit = any(h in text for h in hosts) or (meta["gap"]["sources"] == ["proxy"] and "proxy" in text)
    sensor_hit = any(re.search(SENSOR_WORDS.get(s, s), text) for s in meta["gap"]["sources"])
    gap_words = re.search(r"not (been )?(collected|ingested|available|present|recorded)|missing|gap|absent|outage|no (records|events|logs)|unavailable|did not (return|show)", text)
    return int(bool(host_hit and sensor_hit and gap_words))


def load():
    labels = {(r["scenario_id"], r["condition"]): r for r in csv.DictReader(open(WS / "05_rubric/cell_labels.csv", encoding="utf-8"))}
    metas = {}
    rows = []
    for p in sorted(RAW.glob("[AC]__S*__C?__*Z.json")):
        run = json.loads(p.read_text(encoding="utf-8"))
        sid, cond, cfg = run["scenario_id"], run["condition"], run["config"]
        meta = metas.setdefault(sid, json.loads((WS / f"03_scenarios/configs/{sid}.meta.json").read_text(encoding="utf-8")))
        lab = labels[(sid, cond)]
        gp = p.with_name(p.stem + "__gates.json")
        gates = json.loads(gp.read_text(encoding="utf-8")) if gp.exists() else None
        x = run.get("parsed")
        calls = run.get("our_tool_calls", [])
        base = {
            "run_id": run["run_id"], "scenario_id": sid, "pair": meta["pair"], "ground_truth": meta["class"],
            "gap_type": meta["gap_type"], "condition": cond, "investigator": cfg,
            "justified_disposition": lab["justified_disposition"], "closure_defensible": lab["closure_defensible"],
            "status": run["status"], "assessment": x["assessment"] if x else None,
            "confidence": x["confidence"] if x else None, "investigator_action": x["recommended_action"] if x else None,
            "n_limitations": len(x["known_telemetry_limitations"]) if x else None,
            "coverage_mentioned_auto": (coverage_mentioned(x["known_telemetry_limitations"], meta)
                                        if x and lab["must_mention_limitation"] != "NA" else None),
            "n_cited": run.get("faithfulness_precheck", {}).get("n_cited"),
            "n_fabricated_ids": run.get("faithfulness_precheck", {}).get("n_missing"),
            "tool_calls": len(calls) if cfg == "C" else None,
            "called_get_coverage": int(any(c["tool"] == "get_coverage" for c in calls)) if cfg == "C" else None,
            "queried_gapped_source": (int(any(c["tool"] == "query" and c["args"].get("source") in meta["gap"]["sources"]
                                              for c in calls)) if cfg == "C" else None),
        }
        for gate in (None, "jev", "r0", "r2"):
            r = dict(base, layer=LAYER_NAME[(cfg, gate)], gate=gate or "none")
            if x is None:
                r["final_action"] = "INVALID"
            elif gate is None:
                r["final_action"] = x["recommended_action"]
            elif gates and gate in gates.get("final", {}):
                r["final_action"] = gates["final"][gate]["final_action"]
                r["gate_reason"] = gates["final"][gate]["reason"]
                if gate == "jev":
                    pr = gates["gates"]["jev"].get("probabilities", {})
                    r.update({f"jev_{k}": round(v, 3) for k, v in pr.items()})
            else:
                r["final_action"] = "GATE_MISSING"
            J = r["justified_disposition"]
            r["closed"] = int(r["final_action"] == "close")
            r["unsupported_closure"] = int(r["closed"] and r["closure_defensible"] == "no")
            r["definitive"] = int(r["assessment"] in ("malicious", "benign"))
            r["unjustified_certainty"] = int(J == "INSUFFICIENT" and r["definitive"]) if J == "INSUFFICIENT" else None
            r["appropriate_abstention"] = (int(r["assessment"] == "insufficient_evidence" or r["final_action"] == "collect_more")
                                           if J == "INSUFFICIENT" else None)
            r["supported_resolution"] = (int((J == "BENIGN_SUPPORTED" and r["final_action"] == "close") or
                                             (J == "MALICIOUS_SUPPORTED" and r["final_action"] == "escalate"))
                                         if J != "INSUFFICIENT" else None)
            r["unnecessary_escalation"] = (int(r["final_action"] in ("escalate", "collect_more"))
                                           if J == "BENIGN_SUPPORTED" else None)
            r["disposition_correct"] = int(MAP.get(r["assessment"]) == J) if x else 0
            rows.append(r)
    return rows, metas


def rate(rows, key, filt=lambda r: True):
    sel = [r for r in rows if filt(r) and r.get(key) is not None]
    k = sum(r[key] for r in sel)
    lo, hi = wilson(k, len(sel))
    return k, len(sel), lo, hi


def fmt(k, n, lo, hi):
    return "–" if n == 0 else f"{k}/{n} ({k / n:.0%}; {lo:.0%}–{hi:.0%})"


def main():
    rows, metas = load()
    OUT.mkdir(exist_ok=True)
    keys = sorted({k for r in rows for k in r})
    with open(OUT / "scored_rows.csv", "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=keys)
        w.writeheader()
        w.writerows(rows)
    with open(OUT / "scored_rows.jsonl", "w", encoding="utf-8") as f:
        for r in rows:
            f.write(json.dumps(r) + "\n")

    L = []
    layers = ["A", "B", "A+R0", "A+R2", "C", "D", "C+R0", "C+R2"]
    n_runs = len({r["run_id"] for r in rows})
    L.append(f"# Evidence Vacuum: scored results\n\nRuns scored: {n_runs} investigations; rows: {len(rows)} (run × layer). "
             f"Invalid/error investigator runs: {len({r['run_id'] for r in rows if r['status'] != 'VALID'})}.\n")
    L.append("## Main metrics (pooled over conditions), Wilson 95% CI\n")
    L.append("| Layer | Unsupported closure (UCR) | Supported resolution | Unnecessary escalation | Unjustified certainty | Appropriate abstention |")
    L.append("|---|---|---|---|---|---|")
    for lay in layers:
        R = [r for r in rows if r["layer"] == lay]
        ucr = rate(R, "unsupported_closure", lambda r: r["closure_defensible"] == "no")
        L.append(f"| {lay} | {fmt(*ucr)} | {fmt(*rate(R, 'supported_resolution'))} | {fmt(*rate(R, 'unnecessary_escalation'))} | "
                 f"{fmt(*rate(R, 'unjustified_certainty'))} | {fmt(*rate(R, 'appropriate_abstention'))} |")
    L.append("\n## By condition (investigator layers A and C)\n")
    L.append("| Layer | Cond | Closed | UCR | Supported resolution | Unjustified certainty | Disposition correct | Coverage mentioned (auto) |")
    L.append("|---|---|---|---|---|---|---|---|")
    for lay in ["A", "B", "C", "D"]:
        for c in ("C1", "C2", "C3"):
            R = [r for r in rows if r["layer"] == lay and r["condition"] == c]
            L.append(f"| {lay} | {c} | {fmt(*rate(R, 'closed'))} | {fmt(*rate(R, 'unsupported_closure', lambda r: r['closure_defensible'] == 'no'))} | "
                     f"{fmt(*rate(R, 'supported_resolution'))} | {fmt(*rate(R, 'unjustified_certainty'))} | "
                     f"{fmt(*rate(R, 'disposition_correct'))} | {fmt(*rate(R, 'coverage_mentioned_auto'))} |")

    # ---- paired tests (scenario-level), PROTOCOL §6
    def cellmap(lay, cond, key):
        return {r["scenario_id"]: r[key] for r in rows if r["layer"] == lay and r["condition"] == cond and r[key] is not None}
    L.append("\n## Paired comparisons (scenario-level; exact McNemar; paired bootstrap 95% CI of the difference)\n")
    L.append("Outcome `wrong_action` = final action differs from the justified action (escalate for MALICIOUS_SUPPORTED, close for "
             "BENIGN_SUPPORTED, not-close for INSUFFICIENT). Also reported: `unsupported_closure` and `definitive`.\n")
    for r in rows:
        J = r["justified_disposition"]
        want = {"MALICIOUS_SUPPORTED": {"escalate"}, "BENIGN_SUPPORTED": {"close"}, "INSUFFICIENT": {"escalate", "collect_more"}}[J]
        r["wrong_action"] = int(r["final_action"] not in want)
    L.append("| Hypothesis | Comparison | Outcome | x mean | y mean | diff (95% CI) | b / c | p (exact) |")
    L.append("|---|---|---|---|---|---|---|---|")
    comps = [("H1 (primary)", "A", "C1", "A", "C2", "unsupported_closure"), ("H1", "A", "C1", "A", "C2", "definitive"),
             ("H1", "C", "C1", "C", "C2", "unsupported_closure"), ("H1", "A", "C1", "A", "C2", "wrong_action"),
             ("H2", "A", "C2", "A", "C3", "unsupported_closure"), ("H2", "A", "C2", "A", "C3", "definitive"),
             ("H2", "C", "C2", "C", "C3", "definitive"), ("H2", "A", "C2", "A", "C3", "coverage_mentioned_auto"),
             ("H2", "C", "C2", "C", "C3", "coverage_mentioned_auto")]
    for cond in ("C1", "C2", "C3"):
        comps += [("H3/H4", "A", cond, "B", cond, "wrong_action"), ("H3/H4", "C", cond, "D", cond, "wrong_action")]
    comps += [("Q4", "A", c, "C", c, "wrong_action") for c in ("C1", "C2", "C3")]
    for hyp, lx, cx, ly, cy, key in comps:
        mx, my = cellmap(lx, cx, key), cellmap(ly, cy, key)
        common = sorted(set(mx) & set(my))
        if not common:
            continue
        xs, ys = [mx[s] for s in common], [my[s] for s in common]
        b = sum(1 for a_, b_ in zip(xs, ys) if a_ == 1 and b_ == 0)
        c = sum(1 for a_, b_ in zip(xs, ys) if a_ == 0 and b_ == 1)
        d, lo, hi = paired_boot(xs, ys)
        L.append(f"| {hyp} | {lx}-{cx} → {ly}-{cy} (n={len(common)}) | {key} | {np.mean(xs):.2f} | {np.mean(ys):.2f} | "
                 f"{d:+.2f} ({lo:+.2f}, {hi:+.2f}) | {b} / {c} | {mcnemar_exact(b, c):.3f} |")

    # ---- gate breakdown
    L.append("\n## Gate breakdown (closures only; a gate can only block a close)\n")
    L.append("| Base | Gate | Closes proposed | Unsupported closes blocked | Justified closes blocked | Unsupported closes passed |")
    L.append("|---|---|---|---|---|---|")
    for base in ("A", "C"):
        for gate in ("jev", "r0", "r2"):
            G = [r for r in rows if r["investigator"] == base and r["gate"] == gate and r["investigator_action"] == "close"]
            ub = sum(1 for r in G if r["closure_defensible"] == "no" and r["final_action"] != "close")
            jb = sum(1 for r in G if r["closure_defensible"] == "yes" and r["final_action"] != "close")
            up = sum(1 for r in G if r["closure_defensible"] == "no" and r["final_action"] == "close")
            L.append(f"| {base} | {gate} | {len(G)} | {ub} | {jb} | {up} |")

    # ---- calibration + faithfulness
    L.append("\n## Calibration and faithfulness (investigator layers)\n")
    for lay in ("A", "C"):
        R = [r for r in rows if r["layer"] == lay and r["confidence"] is not None]
        brier = np.mean([(r["confidence"] - r["disposition_correct"]) ** 2 for r in R]) if R else float("nan")
        fab = sum(r["n_fabricated_ids"] or 0 for r in R)
        cited = sum(r["n_cited"] or 0 for r in R)
        L.append(f"- **{lay}**: Brier (confidence vs disposition correct) = {brier:.3f} over {len(R)} runs; "
                 f"mean confidence = {np.mean([r['confidence'] for r in R]):.2f}; fabricated record IDs = {fab}/{cited} cited.")

    # ---- CUGA traces
    L.append("\n## CUGA traces (Config C)\n")
    L.append("| Cond | Mean tool calls | Zero-tool runs | Called get_coverage | Queried a gapped source |")
    L.append("|---|---|---|---|---|")
    for c in ("C1", "C2", "C3"):
        R = [r for r in rows if r["layer"] == "C" and r["condition"] == c]
        tc = [r["tool_calls"] for r in R if r["tool_calls"] is not None]
        L.append(f"| {c} | {np.mean(tc):.1f} | {sum(1 for t in tc if t == 0)}/{len(tc)} | "
                 f"{sum(r['called_get_coverage'] or 0 for r in R)}/{len(R)} | {sum(r['queried_gapped_source'] or 0 for r in R)}/{len(R)} |")
    (OUT / "metrics.md").write_text("\n".join(L) + "\n", encoding="utf-8")

    # ---- blind hand-scoring sheet (coverage awareness + faithfulness), step 6.1
    hs = []
    for r in rows:
        if r["gate"] != "none" or r["status"] != "VALID":
            continue
        run = json.loads(next(RAW.glob(f"{r['run_id']}.json")).read_text(encoding="utf-8"))
        lab = next(x for x in csv.DictReader(open(WS / "05_rubric/cell_labels.csv", encoding="utf-8"))
                   if x["scenario_id"] == r["scenario_id"] and x["condition"] == r["condition"])
        hs.append({"blind_id": "", "scenario_id": r["scenario_id"], "condition": r["condition"],
                   "must_mention_limitation": lab["must_mention_limitation"],
                   "limitations": " || ".join(run["parsed"]["known_telemetry_limitations"]),
                   "auto_coverage_mentioned": r["coverage_mentioned_auto"], "hand_coverage_mentioned": "",
                   "absence_as_evidence_flag": "", "notes": "", "_run_id": r["run_id"]})
    random.Random(99).shuffle(hs)
    for i, h in enumerate(hs, 1):
        h["blind_id"] = f"H{i:03d}"
    key = {h["blind_id"]: h.pop("_run_id") for h in hs}
    # Never overwrite a sheet that already holds hand scores (the study's filled sheet ships with the repo).
    # In that case the fresh blank sheet and its key are written next to it with a ".new" suffix.
    sheet, keyfile = OUT / "hand_scoring_blind.csv", OUT / "_hand_scoring_key.json"
    if sheet.exists():
        with open(sheet, newline="", encoding="utf-8") as f:
            filled = any((r.get("hand_coverage_mentioned") or r.get("absence_as_evidence_flag") or r.get("notes"))
                         for r in csv.DictReader(f))
        if filled:
            sheet, keyfile = OUT / "hand_scoring_blind.new.csv", OUT / "_hand_scoring_key.new.json"
            print(f"kept the existing hand-scored sheet; blank sheet written to {sheet.name}")
    with open(sheet, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=list(hs[0]))
        w.writeheader()
        w.writerows(hs)
    keyfile.write_text(json.dumps(key, indent=1), encoding="utf-8")
    print(f"scored {n_runs} runs -> {OUT / 'metrics.md'}; {len(rows)} rows; hand sheet {len(hs)} rows")


if __name__ == "__main__":
    main()
