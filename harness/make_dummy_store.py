"""Write a tiny hand-made DUMMY01 scenario in all three conditions, for testing the harness only.

Not an evaluation scenario and never scored. Ground truth: MALICIOUS (encoded PowerShell download
cradle on HOST-7). The decisive evidence is Sysmon on HOST-7 between 02:00 and 04:00, which is
removed in C2/C3 (EDR agent offline). C3 also gets a coverage manifest.
"""
import json
from pathlib import Path

from log_tools import CONDITIONS, view_dir

SID = "DUMMY01"


def rec(i, ts, host, source, event_type, raw):
    return {"record_id": f"d1-{i:04d}", "ts": ts, "host": host, "source": source, "event_type": event_type, "raw": raw}


complete = [
    rec(1, "2026-11-10T01:55:02Z", "DC-1", "winsec", "4624", "Logon type 3 user=jdoe src=HOST-7 dst=DC-1"),
    rec(2, "2026-11-10T02:10:44Z", "HOST-7", "winsec", "4624", "Logon type 2 user=jdoe workstation=HOST-7"),
    rec(3, "2026-11-10T02:11:05Z", "HOST-7", "sysmon", "1", "ProcessCreate image=C:\\Windows\\explorer.exe user=jdoe"),
    rec(4, "2026-11-10T02:13:31Z", "HOST-7", "sysmon", "1",
        "ProcessCreate image=powershell.exe cmd='powershell -nop -w hidden -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBi...' parent=winword.exe user=jdoe"),
    rec(5, "2026-11-10T02:13:33Z", "HOST-7", "sysmon", "3",
        "NetworkConnect image=powershell.exe dst=185.199.10.44:443 user=jdoe"),
    rec(6, "2026-11-10T02:13:40Z", "HOST-7", "sysmon", "11", "FileCreate image=powershell.exe target=C:\\Users\\jdoe\\AppData\\Roaming\\upd.dll"),
    rec(7, "2026-11-10T02:20:12Z", "HOST-7", "proxy", "http", "GET https://update.vendor-av.com/defs user=SYSTEM status=200"),
    rec(8, "2026-11-10T03:05:50Z", "HOST-9", "sysmon", "1", "ProcessCreate image=chrome.exe user=asmith"),
    rec(9, "2026-11-10T03:30:00Z", "HOST-7", "winsec", "4634", "Logoff user=jdoe"),
    rec(10, "2026-11-10T04:15:22Z", "HOST-7", "sysmon", "1", "ProcessCreate image=outlook.exe user=jdoe"),
    rec(11, "2026-11-10T02:40:10Z", "HOST-9", "proxy", "http", "GET https://news.example.org/ user=asmith status=200"),
]


def in_gap(r):
    return (r["host"] == "HOST-7" and r["source"] == "sysmon"
            and "2026-11-10T02:00:00Z" <= r["ts"] < "2026-11-10T04:00:00Z")


partial = [r for r in complete if not in_gap(r)]
manifest = {
    "sensors": [
        {"sensor": "sysmon", "host": "HOST-7", "window": ["2026-11-10T02:00:00Z", "2026-11-10T04:00:00Z"],
         "status": "offline", "reason": "EDR/Sysmon agent stopped reporting; no process, network or file events collected"},
        {"sensor": "sysmon", "host": "*", "window": "outside listed gaps", "status": "ok"},
        {"sensor": "winsec", "host": "*", "status": "ok"},
        {"sensor": "proxy", "host": "*", "status": "ok"},
    ]
}

meta_dir = Path(__file__).resolve().parents[1] / "03_scenarios" / "configs"
meta_dir.mkdir(parents=True, exist_ok=True)
(meta_dir / f"{SID}.meta.json").write_text(json.dumps({
    "scenario_id": SID, "pilot_only": True, "archetype": "dummy_powershell",
    # Neutral trigger, independent of the telemetry that the gap removes:
    "alert_summary": "Helpdesk ticket: user jdoe reports opening an unexpected email attachment on HOST-7 "
                     "around 02:10 UTC on 2026-11-10 and asks whether anything happened."}, indent=1), encoding="utf-8")

for cond in CONDITIONS:
    d = view_dir(SID, cond)
    d.mkdir(parents=True, exist_ok=True)
    rows = complete if cond == "C1" else partial
    (d / "events.jsonl").write_text("".join(json.dumps(r) + "\n" for r in rows), encoding="utf-8")
    if cond == "C1":
        (d / "source_catalog.json").write_text(json.dumps(["winsec", "sysmon", "proxy"]), encoding="utf-8")
    if cond == "C3":
        (d / "coverage_manifest.json").write_text(json.dumps(manifest, indent=1), encoding="utf-8")
    print(cond, d, len(rows), "records")
