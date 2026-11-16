"""Cheap Jev gate sanity check on hand-made, non-evaluation cases (~$0.0002 total).

Checks the gate both BLOCKS unjustified closes and ALLOWS a justified one (H4: a gate that blocks
everything is not a success). Run after any change to JEV_QUESTIONS or thresholds, and only
before the rubric freeze.
    tools/cuga-agent/.venv/Scripts/python.exe harness/gate_selftest.py
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from gates import gate_jev  # noqa: E402

NAIVE_CLOSE = {"assessment": "benign", "confidence": 0.85,
    "supporting_observations": [
        {"claim": "No suspicious process creation was observed on HOST-7 during the incident window",
         "claim_type": "inferred_claim", "record_ids": []},
        {"claim": "Interactive logon by jdoe on HOST-7 at 02:10:44", "claim_type": "observed_fact", "record_ids": ["d1-0002"]}],
    "known_telemetry_limitations": [], "claims_not_established": [], "recommended_action": "close",
    "additional_evidence_needed": []}

GOOD_CLOSE = {"assessment": "benign", "confidence": 0.9,
    "supporting_observations": [
        {"claim": r"Sysmon shows powershell.exe launched by svc_patch from the scheduled task \IT\MonthlyPatch on HOST-7 at 02:13",
         "claim_type": "observed_fact", "record_ids": ["p-0004"]},
        {"claim": r"The command line runs C:\IT\scripts\Install-Patches.ps1, signed by the internal IT code-signing certificate",
         "claim_type": "observed_fact", "record_ids": ["p-0004"]},
        {"claim": "Change ticket CHG-4411 schedules patching of HOST-7 between 02:00 and 03:00 on 2026-11-10",
         "claim_type": "observed_fact", "record_ids": ["p-0001"]},
        {"claim": "The only network connection from the process went to the internal WSUS server",
         "claim_type": "observed_fact", "record_ids": ["p-0005"]}],
    "known_telemetry_limitations": [], "claims_not_established": [], "recommended_action": "close",
    "additional_evidence_needed": []}

GAP_MANIFEST = {"sensors": [
    {"sensor": "sysmon", "host": "HOST-7", "window": ["2026-11-10T02:00:00Z", "2026-11-10T04:00:00Z"],
     "status": "offline", "reason": "agent stopped reporting"},
    {"sensor": "winsec", "host": "*", "status": "ok"}, {"sensor": "proxy", "host": "*", "status": "ok"}]}
OK_MANIFEST = {"sensors": [{"sensor": s, "host": "*", "status": "ok"} for s in ("sysmon", "winsec", "proxy")]}

GOOD_CLOSE_WITH_CAVEATS = {**GOOD_CLOSE, "known_telemetry_limitations": [
    "The proxy and connection records show byte counts but not the transferred payload or file contents.",
    "The records do not include the change-approval system, so formal authorization is not recorded in the logs."]}

CASES = [  # (label, findings, manifest, expected action is close?)
    ("justified close + ordinary caveats, no coverage info", GOOD_CLOSE_WITH_CAVEATS, None, True),
    ("naive close, no coverage info (C2-like)", NAIVE_CLOSE, None, False),
    ("naive close, gap manifest (C3-like)", NAIVE_CLOSE, GAP_MANIFEST, False),
    ("justified close, no coverage info", GOOD_CLOSE, None, True),
    ("justified close, full-coverage manifest", GOOD_CLOSE, OK_MANIFEST, True),
]

if __name__ == "__main__":
    ok = True
    for label, findings, man, want_close in CASES:
        r = gate_jev(findings, man)
        good = (r["action"] == "close") == want_close
        ok &= good
        print(f"{'PASS' if good else 'FAIL'}  {label}: {r['action']}  "
              f"{ {k: round(v, 2) for k, v in r['probabilities'].items()} }  tokens={r['usage']['input_tokens']}")
    print("ALL PASS" if ok else "SOME FAILED")
