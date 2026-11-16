"""Score every v2 reviewer arm present in 08_analysis/v2/outputs/*.jsonl against the frozen v1 labels.

    tools/cuga-agent/.venv/Scripts/python.exe 08_analysis/score_v2.py

Final action = the reviewer's recommended_action; invalid/missing reviewer output → the investigator's action
(fail-open). Writes 08_analysis/v2/metrics_v2.md. Paired exact McNemar vs the investigator alone and vs G-base.
"""
import json
import math
from pathlib import Path

WS = Path(__file__).resolve().parents[1]
V2 = WS / "08_analysis" / "v2"
WANT = {"MALICIOUS_SUPPORTED": {"escalate"}, "BENIGN_SUPPORTED": {"close"}, "INSUFFICIENT": {"escalate", "collect_more"}}


def mcnemar(b, c):
    n = b + c
    return 1.0 if n == 0 else min(1.0, 2 * sum(math.comb(n, i) for i in range(min(b, c) + 1)) / 2 ** n)


def wilson(k, n, z=1.96):
    if n == 0:
        return float("nan"), float("nan")
    p = k / n
    d = 1 + z * z / n
    c = (p + z * z / (2 * n)) / d
    h = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / d
    return max(0, c - h), min(1, c + h)


def main():
    recs = [json.loads(l) for l in open(V2 / "eval_inputs.jsonl", encoding="utf-8")]
    arms = {"investigator (v1 A/C)": None}
    for p in sorted((V2 / "outputs").glob("*.jsonl")):
        arms[p.stem] = {json.loads(l)["run_id"]: json.loads(l) for l in open(p, encoding="utf-8") if l.strip()}
    res = {}
    L = ["# v2 reviewer results (evaluated on 45 frozen v1 answers; labels = frozen v1 rubric)\n",
         "| Arm | Unnecessary escalation (benign cells) | Unsupported closures | Correct action | False 'malicious' on benign | Invalid |",
         "|---|---|---|---|---|---|"]
    for name, outs in arms.items():
        rows = []
        for r in recs:
            o = (outs or {}).get(r["run_id"]) if outs is not None else None
            parsed = (o or {}).get("parsed")
            act = parsed["recommended_action"] if parsed else r["investigator_action"]
            st = parsed["epistemic_status"] if parsed else None
            rows.append({**r, "action": act, "invalid": outs is not None and not parsed,
                         "correct": int(act in WANT[r["label"]]),
                         "unsupported_close": int(act == "close" and r["closure_defensible"] == "no"),
                         "unnecessary_esc": int(act != "close") if r["label"] == "BENIGN_SUPPORTED" else None,
                         "false_mal": int(st == "malicious_supported") if r["label"] == "BENIGN_SUPPORTED" else None})
        res[name] = rows
        ben = [x for x in rows if x["unnecessary_esc"] is not None]
        nc = [x for x in rows if x["closure_defensible"] == "no"]
        ue, uc, ca = sum(x["unnecessary_esc"] for x in ben), sum(x["unsupported_close"] for x in nc), sum(x["correct"] for x in rows)
        fm = sum(x["false_mal"] or 0 for x in ben)
        f = lambda k, n: f"{k}/{n} ({k/n:.0%}; {wilson(k,n)[0]:.0%}–{wilson(k,n)[1]:.0%})"
        L.append(f"| {name} | {f(ue, len(ben))} | {f(uc, len(nc))} | {f(ca, len(rows))} | "
                 f"{fm if name != 'investigator (v1 A/C)' else '–'} | {sum(x['invalid'] for x in rows)} |")
    L.append("\n## Paired tests (exact McNemar on per-answer correctness; b = ref right & arm wrong, c = ref wrong & arm right)\n")
    L.append("| Arm | vs | b / c | p |")
    L.append("|---|---|---|---|")
    for ref in ("investigator (v1 A/C)", "G-base"):
        if ref not in res:
            continue
        for name, rows in res.items():
            if name == ref:
                continue
            b = sum(1 for x, y in zip(res[ref], rows) if x["correct"] and not y["correct"])
            c = sum(1 for x, y in zip(res[ref], rows) if not x["correct"] and y["correct"])
            L.append(f"| {name} | {ref} | {b} / {c} | {mcnemar(b, c):.3f} |")
    L.append("\n## Per-cell actions (benign-supported cells, where over-escalation lives)\n")
    L.append("| run | label | " + " | ".join(res) + " |")
    L.append("|---|---|" + "---|" * len(res))
    for i, r in enumerate(recs):
        if r["label"] == "BENIGN_SUPPORTED":
            L.append(f"| {r['investigator']} {r['scenario_id']} {r['condition']} | benign | " +
                     " | ".join(res[n][i]["action"] for n in res) + " |")
    (V2 / "metrics_v2.md").write_text("\n".join(L) + "\n", encoding="utf-8")
    print("\n".join(L[:3 + len(res)]))


if __name__ == "__main__":
    main()
