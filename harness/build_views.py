"""Build the three telemetry views (C1/C2/C3) for one scenario from EvidenceForge output.

    tools/cuga-agent/.venv/Scripts/python.exe harness/build_views.py P01

Steps (all deterministic, same rule for every scenario):
 1. Normalize every generated record (Windows Security/Sysmon XML, Zeek JSON, proxy access log)
    into {record_id, ts, host, source, event_type, raw}. `raw` is a compact key=value rendering
    (GUIDs, hashes, call traces and similar bulk fields are dropped to save tokens).
 2. Case slice: keep records inside the meta `window` that involve an entity the alert names
    (focus hosts / IPs / users). Same rule for every scenario; parameters come from the alert.
 3. C1 = slice. C2 = slice minus the gap (meta `gap`: sources x hosts x window), byte-identical
    otherwise. C3 = C2 + an analyst-facing coverage_manifest.json describing every sensor's status.
 4. Report sizes (records, ~tokens) and an orphan check.

Meta file: 03_scenarios/configs/<SID>.meta.json (see P01.meta.json for the fields).
Record IDs are assigned over the C1 slice in timestamp order, so they are stable across conditions.
"""
import json
import re
import sys
import xml.etree.ElementTree as ET
from datetime import datetime, timezone
from pathlib import Path

import yaml

WS = Path(__file__).resolve().parents[1]
NS = "{http://schemas.microsoft.com/win/2004/08/events/event}"
DROP_FIELDS = {"RuleName", "ProcessGuid", "ParentProcessGuid", "SourceProcessGUID", "TargetProcessGUID",
               "LogonGuid", "Hashes", "CallTrace", "Company", "Description", "Product", "FileVersion",
               "OriginalFileName", "TerminalSessionId", "UtcTime", "SubjectUserSid", "TargetUserSid",
               "TargetLogonGuid", "TransmittedServices", "LmPackageName", "KeyLength", "ImpersonationLevel",
               "RestrictedAdminMode", "VirtualAccount", "ElevatedToken", "TargetLinkedLogonId",
               "TargetOutboundUserName", "TargetOutboundDomainName", "SourceThreadId", "SourceUser", "TargetUser",
               "Archived", "IsExecutable"}
ZEEK_KEEP = {
    "conn": ["id.orig_h", "id.orig_p", "id.resp_h", "id.resp_p", "proto", "service", "duration", "orig_bytes",
             "resp_bytes", "conn_state"],
    "dns": ["id.orig_h", "id.resp_h", "query", "qtype_name", "rcode_name", "answers"],
    "ssl": ["id.orig_h", "id.resp_h", "id.resp_p", "server_name", "version", "established"],
    "http": ["id.orig_h", "id.resp_h", "method", "host", "uri", "status_code", "request_body_len",
             "response_body_len", "user_agent"],
}
PROXY_RE = re.compile(r'^(\S+) \S+ (\S+) \[([^\]]+)\] "(\S+) (\S+) [^"]*" (\d{3}) \S+ "[^"]*" "([^"]*)"(?: "([^"]*)")?')


def iso(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"


def parse_windows(path: Path, source: str):
    for _, el in ET.iterparse(path, events=("end",)):
        if el.tag != NS + "Event":
            continue
        sysel = el.find(NS + "System")
        eid = sysel.findtext(NS + "EventID")
        ts = sysel.find(NS + "TimeCreated").get("SystemTime")
        host = (sysel.findtext(NS + "Computer") or "").split(".")[0]
        fields = []
        for d in el.iter(NS + "Data"):
            k, v = d.get("Name"), (d.text or "").strip()
            if k in DROP_FIELDS or v in ("", "-", "%%1843", "0x0"):
                continue
            fields.append(f"{k}={v}")
        dt = datetime.fromisoformat(ts.replace("Z", "+00:00")[:26] + "+00:00" if "." in ts else ts.replace("Z", "+00:00"))
        yield {"ts": iso(dt), "host": host, "source": source, "event_type": eid, "raw": f"EventID={eid} " + " ".join(fields)}
        el.clear()


def parse_zeek(path: Path, kind: str, ip2host: dict):
    for line in path.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        r = json.loads(line)
        keep = ZEEK_KEEP.get(kind)
        parts = [f"{k}={r[k]}" for k in (keep or r.keys()) if k in r and k not in ("ts", "uid")]
        orig = r.get("id.orig_h", "")
        yield {"ts": iso(datetime.fromtimestamp(r["ts"], tz=timezone.utc)), "host": ip2host.get(orig, orig),
               "source": f"zeek_{kind}", "event_type": r.get("service") or kind, "raw": " ".join(parts)}


def parse_proxy(path: Path, ip2host: dict):
    for line in path.read_text(encoding="utf-8").splitlines():
        m = PROXY_RE.match(line)
        if not m:
            continue
        cip, user, t, method, url, status, ua, extra = m.groups()
        dt = datetime.strptime(t, "%d/%b/%Y:%H:%M:%S %z")
        extra = " ".join(p for p in (extra or "").split() if not p.startswith(("byte_scope=", "wire_sc_bytes=", "cs_bytes=")))
        raw = f"client={cip} user={user} {method} {url} status={status} ua=\"{ua}\" {extra}".strip()
        yield {"ts": iso(dt), "host": ip2host.get(cip, cip), "source": "proxy", "event_type": method, "raw": raw}


def load_all(bundle: Path, scenario_yaml: Path) -> list[dict]:
    scen = yaml.safe_load(scenario_yaml.read_text(encoding="utf-8"))
    ip2host = {s["ip"]: s["hostname"] for s in scen["environment"]["systems"] if s.get("ip")}
    recs = []
    for p in sorted((bundle / "data").rglob("*")):
        if not p.is_file():
            continue
        if p.name == "windows_event_security.xml":
            recs += parse_windows(p, "winsec")
        elif p.name == "windows_event_sysmon.xml":
            recs += parse_windows(p, "sysmon")
        elif p.parent.name.startswith("zeek") and p.suffix == ".json":
            recs += parse_zeek(p, p.stem, ip2host)
        elif p.name == "proxy_access.log":
            recs += parse_proxy(p, ip2host)
    return recs


def in_slice(r: dict, meta: dict) -> bool:
    w0, w1 = meta["window"]
    if not (w0 <= r["ts"] < w1):
        return False
    f = meta["focus"]
    if r["host"] in f.get("hosts", []):
        return True
    raw = r["raw"].lower()
    return any(t.lower() in raw for t in f.get("hosts", []) + f.get("ips", []) + f.get("users", []))


def in_gap(r: dict, gap: dict) -> bool:
    if r["source"] not in gap["sources"]:
        return False
    if gap.get("hosts") not in (None, ["*"]) and r["host"] not in gap["hosts"]:
        return False
    return gap["window"][0] <= r["ts"] < gap["window"][1]


def main(sid: str):
    meta = json.loads((WS / "03_scenarios" / ("tpool/configs" if sid.startswith("T") else "configs") / f"{sid}.meta.json").read_text(encoding="utf-8"))
    bundle = WS / "03_scenarios" / "generated" / sid / "C1"
    allrecs = load_all(bundle, WS / "03_scenarios" / ("tpool/configs" if sid.startswith("T") else "configs") / f"{sid}.yaml")
    sl = sorted((r for r in allrecs if in_slice(r, meta)), key=lambda r: (r["ts"], r["source"], r["host"], r["raw"]))
    for i, r in enumerate(sl, 1):
        r["record_id"] = f"{sid}-{i:05d}"
    sl = [{k: r[k] for k in ("record_id", "ts", "host", "source", "event_type", "raw")} for r in sl]
    part = [r for r in sl if not in_gap(r, meta["gap"])]
    catalog = sorted({r["source"] for r in allrecs})

    out = {}
    for cond, d, rows in (("C1", "complete", sl), ("C2", "partial_undocumented", part), ("C3", "partial_documented", part)):
        vd = WS / "04_conditions" / d / sid
        vd.mkdir(parents=True, exist_ok=True)
        text = "".join(json.dumps(r, ensure_ascii=False) + "\n" for r in rows)
        (vd / "events.jsonl").write_text(text, encoding="utf-8")
        if cond == "C1":
            (vd / "source_catalog.json").write_text(json.dumps(catalog), encoding="utf-8")
        if cond == "C3":
            (vd / "coverage_manifest.json").write_text(json.dumps(meta["coverage_manifest"], indent=1), encoding="utf-8")
        out[cond] = (len(rows), len(text) // 4)
    dropped = [r for r in sl if in_gap(r, meta["gap"])]
    print(f"{sid}: all={len(allrecs)} slice C1={out['C1'][0]} recs ~{out['C1'][1]} tok | "
          f"C2/C3={out['C2'][0]} recs ~{out['C2'][1]} tok | gap removed {len(dropped)} "
          f"({sorted({(r['source'], r['host']) for r in dropped})})")
    # sanity: C2 is an exact subset of C1
    c1 = {json.dumps(r, sort_keys=True) for r in sl}
    assert all(json.dumps(r, sort_keys=True) in c1 for r in part), "C2 not a subset of C1"
    return out


if __name__ == "__main__":
    for s in sys.argv[1:]:
        main(s)
