"""v3 Stage 1c: Luna self-agreement and baseline accuracy on the v2 T-pool (2 samples per cell; training data only)."""
import json
from collections import defaultdict
from pathlib import Path

WS = Path(__file__).resolve().parents[2]
WANT = {"MALICIOUS_SUPPORTED": {"escalate"}, "BENIGN_SUPPORTED": {"close"}, "INSUFFICIENT": {"escalate", "collect_more"}}
chk = json.loads((WS / "03_scenarios" / "tpool" / "decisive_check.json").read_text(encoding="utf-8"))
cells = defaultdict(list)
for p in sorted((WS / "07_runs" / "tpool").glob("A__T*.json")):
    d = json.loads(p.read_text(encoding="utf-8"))
    if str(d.get("status")).upper() == "VALID" and d.get("parsed"):
        cells[(d["scenario_id"], d["condition"])].append(d["parsed"])
n = agree_act = agree_ass = 0
acc = [0, 0]; closes = [0, 0, 0]  # justified, unsupported, closable cells
for (tid, c), ps in cells.items():
    meta = json.loads((WS / "03_scenarios" / "tpool" / "configs" / f"{tid}.meta.json").read_text(encoding="utf-8"))
    v = chk.get(tid, {})
    if c != "C1" and not v.get("valid_C2C3", True):
        continue
    lab = meta["labels"][c]
    for p in ps:
        a = p.get("recommended_action")
        acc[0] += a in WANT[lab]; acc[1] += 1
        closes[0] += a == "close" and lab == "BENIGN_SUPPORTED"
        closes[1] += a == "close" and lab != "BENIGN_SUPPORTED"
    closes[2] += len(ps) if lab == "BENIGN_SUPPORTED" else 0
    if len(ps) >= 2:
        n += 1
        agree_act += ps[0].get("recommended_action") == ps[1].get("recommended_action")
        agree_ass += ps[0].get("assessment") == ps[1].get("assessment")
L = ["# v3 Stage 1c: Luna self-agreement and baseline on the v2 T-pool (training data)\n",
     f"- Cells with 2 valid samples: {n}. Same action: {agree_act}/{n} ({agree_act/n:.0%}). Same assessment: {agree_ass}/{n} ({agree_ass/n:.0%}).",
     f"- Baseline (v1 prompt, Luna, all valid samples on label-valid cells): correct action {acc[0]}/{acc[1]} ({acc[0]/acc[1]:.0%}).",
     f"- Closes: justified {closes[0]} of {closes[2]} closable samples; unsupported {closes[1]}."]
(WS / "08_analysis" / "v3" / "stage1_luna_agreement.md").write_text("\n".join(L) + "\n", encoding="utf-8")
print("\n".join(L))
