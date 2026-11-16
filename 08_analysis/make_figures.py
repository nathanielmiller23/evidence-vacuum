"""Report figures from scored v1 data. Re-run any time.

    tools/cuga-agent/.venv/Scripts/python.exe 08_analysis/make_figures.py
"""
import csv
import json
from collections import Counter
from pathlib import Path

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt

WS = Path(__file__).resolve().parents[1]
FIG = WS / "08_analysis" / "figures"
FIG.mkdir(exist_ok=True)
rows = [json.loads(l) for l in open(WS / "08_analysis" / "scored_rows.jsonl")]
inv = [r for r in rows if r["gate"] == "none"]
plt.rcParams.update({"font.size": 10, "axes.spines.top": False, "axes.spines.right": False})
COL = {"close": "#2a9d8f", "escalate": "#e76f51", "collect_more": "#e9c46a", "INVALID": "#9e9e9e"}

# Fig 1: what the investigators did, by justified label
fig, axes = plt.subplots(1, 2, figsize=(9, 3.4), sharey=True)
labels = ["BENIGN_SUPPORTED", "MALICIOUS_SUPPORTED", "INSUFFICIENT"]
nice = {"BENIGN_SUPPORTED": "Benign\n(close is correct)", "MALICIOUS_SUPPORTED": "Malicious\n(escalate)", "INSUFFICIENT": "Insufficient\n(don't close)"}
for ax, who in zip(axes, ["A", "C"]):
    bottom = [0] * 3
    for act in ["close", "escalate", "collect_more", "INVALID"]:
        vals = [sum(1 for r in inv if r["investigator"] == who and r["justified_disposition"] == L and r["final_action"] == act) for L in labels]
        ax.bar([nice[L] for L in labels], vals, bottom=bottom, color=COL[act], label=act.replace("_", " "))
        bottom = [b + v for b, v in zip(bottom, vals)]
    ax.set_title({"A": "Setup A (all logs in prompt)", "C": "Setup C (CUGA agent)"}[who], fontsize=10)
axes[0].set_ylabel("Investigations")
axes[1].legend(frameon=False, fontsize=9)
fig.suptitle("No investigation closed anything; every closable benign case was escalated or held", fontsize=11)
fig.tight_layout()
fig.savefig(FIG / "fig1_actions_by_label.png", dpi=200)

# Fig 2: calibration (confidence vs correct disposition)
fig, ax = plt.subplots(figsize=(4.6, 3.4))
for who, m in (("A", "o"), ("C", "s")):
    R = [r for r in inv if r["investigator"] == who and r["confidence"] is not None]
    ax.scatter([r["confidence"] for r in R], [r["disposition_correct"] + (0.04 if who == "C" else -0.04) for r in R],
               marker=m, alpha=0.7, label=f"Setup {who}")
ax.set_yticks([0, 1], ["wrong", "correct"])
ax.set_xlabel("Stated confidence")
ax.set_xlim(0, 1.02)
ax.set_title("High confidence, mixed correctness", fontsize=11)
ax.legend(frameon=False)
fig.tight_layout()
fig.savefig(FIG / "fig2_calibration.png", dpi=200)

# Fig 3: gap awareness (hand-scored) vs precise attribution, C2 vs C3
hs = list(csv.DictReader(open(WS / "08_analysis" / "hand_scoring_blind.csv", encoding="utf-8")))
key = json.load(open(WS / "08_analysis" / "_hand_scoring_key.json"))
cnt = Counter()
tot = Counter()
for h in hs:
    if h["must_mention_limitation"] == "NA":
        continue
    who = key[h["blind_id"]][0]
    tot[(who, h["condition"])] += 1
    cnt[(who, h["condition"], "noticed")] += int(h["hand_coverage_mentioned"])
    cnt[(who, h["condition"], "precise")] += int(h["auto_coverage_mentioned"] or 0)
fig, ax = plt.subplots(figsize=(6, 3.4))
groups = [("A", "C2"), ("A", "C3"), ("C", "C2"), ("C", "C3")]
x = range(len(groups))
ax.bar([i - 0.18 for i in x], [cnt[(w, c, "noticed")] / tot[(w, c)] for w, c in groups], 0.36, label="gap noticed (hand)", color="#264653")
ax.bar([i + 0.18 for i in x], [cnt[(w, c, "precise")] / tot[(w, c)] for w, c in groups], 0.36, label="gap precisely attributed", color="#8ab17d")
ax.set_xticks(list(x), [f"{w} · {'no manifest' if c == 'C2' else 'manifest'}" for w, c in groups])
ax.set_ylim(0, 1.1)
ax.set_ylabel("Share of consequential-gap cells")
ax.set_title("Gaps are usually noticed; the manifest sharpens attribution", fontsize=11)
ax.legend(frameon=False, fontsize=9)
fig.tight_layout()
fig.savefig(FIG / "fig3_gap_awareness.png", dpi=200)
print("wrote", sorted(p.name for p in FIG.glob("*.png")))


# Fig 4 (v2): justified vs unsupported closures and correct actions per reviewer arm
V2 = WS / "08_analysis" / "v2"
recs = [json.loads(l) for l in open(V2 / "eval_inputs.jsonl", encoding="utf-8")]
order = [("investigator", None), ("Jev reviewer", "Jev-reviewer"), ("R2 rule", "R2-reviewer"), ("Untuned Qwen 4B", "G-base"),
         ("Hosted Gemma 31B", "H-hosted"), ("Adaption stack", "H-stack"), ("Fine-tuned Qwen 4B", "G-ft")]
WANT = {"MALICIOUS_SUPPORTED": {"escalate"}, "BENIGN_SUPPORTED": {"close"}, "INSUFFICIENT": {"escalate", "collect_more"}}
names, jc, uc, ca = [], [], [], []
for label, fname in order:
    outs = {} if fname is None else {json.loads(l)["run_id"]: json.loads(l) for l in open(V2 / "outputs" / f"{fname}.jsonl", encoding="utf-8")}
    acts = []
    for r in recs:
        p = (outs.get(r["run_id"]) or {}).get("parsed") if fname else None
        acts.append(p["recommended_action"] if p else r["investigator_action"])
    names.append(label)
    jc.append(sum(a == "close" and r["closure_defensible"] == "yes" for a, r in zip(acts, recs)))
    uc.append(sum(a == "close" and r["closure_defensible"] == "no" for a, r in zip(acts, recs)))
    ca.append(sum(a in WANT[r["label"]] for a, r in zip(acts, recs)))
fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(10, 3.6), gridspec_kw={"width_ratios": [1.2, 1]})
y = range(len(names))
ax1.barh([i + 0.2 for i in y], jc, 0.4, color="#2a9d8f", label="justified closures (of 12)")
ax1.barh([i - 0.2 for i in y], uc, 0.4, color="#e76f51", label="unsupported closures (of 33)")
ax1.set_yticks(list(y), names); ax1.invert_yaxis(); ax1.set_xlabel("Closures"); ax1.legend(frameon=False, fontsize=8, loc="upper right")
ax1.set_title("Only the fine-tuned reviewer ever closes", fontsize=10)
ax2.barh(list(y), ca, color=["#264653" if n != "Fine-tuned Qwen 4B" else "#8ab17d" for n in names])
ax2.set_yticks(list(y), [""] * len(names)); ax2.invert_yaxis(); ax2.set_xlim(0, 45); ax2.set_xlabel("Correct final action (of 45)")
for i, v in enumerate(ca):
    ax2.text(v + 0.5, i, str(v), va="center", fontsize=8)
ax2.set_title("Correct actions", fontsize=10)
fig.tight_layout()
fig.savefig(FIG / "fig4_v2_reviewers.png", dpi=200)
print("wrote fig4_v2_reviewers.png")
