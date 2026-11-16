"""v3 Stage 1: calibrate the sensor-silence gate on T-pool (v2) C1 streams, then apply it post hoc behind G-ft (EXPLORATORY)."""
import json
import sys
from pathlib import Path

WS = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(WS / "harness")); sys.path.insert(0, str(WS / "08_analysis"))
import silence_gate as sg  # noqa: E402
from score_v2 import WANT  # noqa: E402

HOST_SENSORS = ("winsec", "sysmon")   # proxy is naturally bursty (up to ~40 min idle in complete data) -> not a heartbeat
def mx(s): return max([v for k, v in s.items() if k.split("@")[0] in HOST_SENSORS] or [0])

cal = {}
for i in range(1, 61):
    tid = f"T{i:03d}"
    cal[tid] = {"C1": mx(sg.silences(tid, "C1")), "C2": mx(sg.silences(tid, "C2"))}
natural = max(v["C1"] for v in cal.values())
thr = round(natural + 5)
V2 = WS / "08_analysis" / "v2"
recs = [json.loads(l) for l in open(V2 / "eval_inputs.jsonl", encoding="utf-8")]
G = {json.loads(l)["run_id"]: json.loads(l) for l in open(V2 / "outputs" / "G-ft.jsonl", encoding="utf-8") if l.strip()}
rows, detail = [], []
for r in recs:
    p = (G.get(r["run_id"]) or {}).get("parsed")
    a = p["recommended_action"] if p else r["investigator_action"]
    s = mx(sg.silences(r["scenario_id"], r["condition"]))
    v = s >= thr
    b = "collect_more" if (a == "close" and v) else a
    rows.append((r, a, b))
    if a == "close":
        detail.append(f"| {r['run_id']} | {r['label']} | {r['closure_defensible']} | {s} | {'VETO' if v else 'pass'} |")
def sc(i):
    c = sum(int(x[i] in WANT[x[0]['label']]) for x in rows)
    j = sum(int(x[i] == 'close' and x[0]['closure_defensible'] == 'yes') for x in rows)
    u = sum(int(x[i] == 'close' and x[0]['closure_defensible'] == 'no') for x in rows)
    return c, j, u
L = ["# v3 Stage 1b: sensor-silence gate behind G-ft (post hoc on seen v2 data: EXPLORATORY)\n",
     f"Calibration on T001–T060 complete (C1) streams: longest natural winsec/sysmon silence = {natural} min → threshold = {thr} min (natural max + 5).",
     f"Same T-pool, gapped (C2) streams: {sum(1 for v in cal.values() if v['C2'] >= thr)}/60 scenarios exceed the threshold (gaps on decisive host sensors, consequential or not).\n",
     "| Pipeline | Correct | Justified closes (of 12) | Unsupported closes |", "|---|---|---|---|",
     "| G-ft alone | %d/45 | %d | %d |" % sc(1), "| G-ft + silence gate | %d/45 | %d | %d |" % sc(2),
     "\n| G-ft close | label | defensible | longest decisive host-sensor silence (min) | gate |", "|---|---|---|---|---|"] + detail
(WS / "08_analysis" / "v3" / "stage1_silence_gate.md").write_text("\n".join(L) + "\n", encoding="utf-8")
print("\n".join(L))
