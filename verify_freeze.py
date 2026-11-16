"""Check every file listed in the FREEZE_*.json manifests against its recorded SHA-256.

    python verify_freeze.py

Run it right after cloning: it proves you have the exact frozen scenarios, labels, prompts and harness.
Exit code 0 = everything matches (or differs only by the documented, later changes in EXPECTED, each pinned to an approved hash).
Clone with `git config core.autocrlf false` (see README) or line-ending conversion will change the hashes.
"""
import hashlib
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent
MANIFESTS = [
    "03_scenarios/FREEZE_scenario_set_v1.json",
    "05_rubric/FREEZE_rubric_and_harness_v1.json",
    "03_scenarios/FREEZE_S2_v3.json",
    "08_analysis/v3/FREEZE_v3_pipeline.json",
]
# Freeze entries that are not plain files in this repo
ALIASES = {"tools/cuga-agent (local patch diff)": "patches/cuga-gpt6-reasoning-model.patch"}
# Files that were changed AFTER an early freeze, on purpose.
# Key = (manifest, file) -> (reason, SHA-256 of the approved current version).
# A changed file passes only if it matches its approved hash, so any further edit (e.g. a label value) fails.
# None of these changes affects the frozen results they were frozen for.
GATE_FIX = ("publication fix: the gate now raises an error when raw telemetry is missing instead of silently "
            "returning 'no veto' (gate logic and threshold unchanged; S2 gated scores reproduce exactly)")
EXPECTED = {
    ("03_scenarios/FREEZE_scenario_set_v1.json", "harness/build_views.py"):
        ("v2 tooling: also resolves T* scenarios from 03_scenarios/tpool/configs (backward compatible for S*)",
         "2dbfbfa4a5f6f4131c825e0d36aaefa8e80154ae84802183c03b04d6d8af444c"),
    ("05_rubric/FREEZE_rubric_and_harness_v1.json", "harness/prompts.py"):
        ("v2 tooling: also resolves T* scenarios from 03_scenarios/tpool/configs (backward compatible for S*)",
         "2b7c53ea6e82e40b79319cc9a574fcb93154d23400b28f9bfa40f5aa7aeee9ce"),
    ("05_rubric/FREEZE_rubric_and_harness_v1.json", ".env.example"):
        ("template edited after the v1 freeze (the current one also covers the v2 Adaption key); it holds no keys",
         "f951c1c307ebd9aadf88ce476a2c42a4255c8c66e1ed4c93e984edcc4f6a8f80"),
    ("05_rubric/FREEZE_rubric_and_harness_v1.json", "05_rubric/cell_labels.csv"):
        ("the labeler column was removed for publication; every label value is unchanged (scoring does not read it)",
         "c73f9e941ce976a498cf01a3b6160119734c8cb9202a22dbd48ea4e5a18a2fcd"),
    ("03_scenarios/FREEZE_S2_v3.json", "01_protocol/PLAN_v3_run.md"):
        ("publication redaction: a private account credit balance was removed from section 5 (no plan content changed)",
         "036085beb9d7b63f79617bf072f0f768a7c98973944d622ad0fc4684827522bb"),
    ("03_scenarios/FREEZE_S2_v3.json", "08_analysis/score_v3.py"):
        ("superseded by the later 08_analysis/v3/FREEZE_v3_pipeline.json (which matches)",
         "320a0ed91ea799a096c944509ecc16787dfa95dbc612c559f54499a299e5d095"),
    ("03_scenarios/FREEZE_S2_v3.json", "harness/silence_gate.py"):
        ("superseded by the later 08_analysis/v3/FREEZE_v3_pipeline.json; " + GATE_FIX, "78fdc7c673f7c6e30f2429ca74262da756257abab7a90874de2be0a0c8bf1f20"),
    ("08_analysis/v3/FREEZE_v3_pipeline.json", "harness/silence_gate.py"): (GATE_FIX, "78fdc7c673f7c6e30f2429ca74262da756257abab7a90874de2be0a0c8bf1f20"),
}

bad = 0
for m in MANIFESTS:
    files = json.loads((ROOT / m).read_text(encoding="utf-8")).get("files", {})
    ok = expected = 0
    for rel, want in files.items():
        p = ROOT / ALIASES.get(rel, rel)
        got = hashlib.sha256(p.read_bytes()).hexdigest() if p.exists() else None
        if got == want:
            ok += 1
        elif (m, rel) in EXPECTED and got == EXPECTED[(m, rel)][1]:
            expected += 1
            print(f"  changed later (documented, approved hash matches): {rel}: {EXPECTED[(m, rel)][0]}")
        else:
            bad += 1
            print(f"  {'MISSING ' if got is None else 'MISMATCH'}  {rel}")
    print(f"{m}: {ok}/{len(files)} match, {expected} documented later changes")
print("OK: everything matches the freeze records." if not bad else f"FAILED: {bad} unexpected differences.")
sys.exit(1 if bad else 0)
