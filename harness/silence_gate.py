"""Sensor-silence ("heartbeat") gap check, computed from the FULL telemetry stream, not from the investigator's text.

For the alert category's decisive sensors (decisive_sensors.json), find the longest silence of each (sensor, host)
stream inside the case window. A stream counts only if that host emitted that sensor in the warm-up hour before the
window (so it is expected to be alive). In C2/C3 the stream is the full stream minus the scenario's gap; in C1 it is
complete. The gate vetoes a close if any decisive stream is silent for >= threshold minutes.
This uses no labels and no investigator output; a SIEM can compute it from ingestion metadata.
"""
import json
import sys
from datetime import datetime, timedelta
from functools import lru_cache
from pathlib import Path

WS = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(WS / "harness"))
from build_views import in_gap, load_all  # noqa: E402

DEC = json.loads((WS / "03_scenarios" / "decisive_sensors_v3.json").read_text(encoding="utf-8"))  # v3: v1 table + new S2 categories (v1 entries unchanged)
DEC.setdefault("large_upload", ["proxy", "sysmon"])
P = lambda s: datetime.fromisoformat(s.replace("Z", "+00:00"))


def cfg(sid):
    return WS / "03_scenarios" / ("tpool/configs" if sid.startswith("T") else "configs")


@lru_cache(maxsize=4)
def _all(sid):
    d = WS / "03_scenarios" / "generated" / sid / "C1"
    recs = load_all(d, cfg(sid) / f"{sid}.yaml")
    if not recs:  # missing telemetry must not read as "no silence, no veto"
        raise FileNotFoundError(f"silence gate: no raw telemetry for {sid} under {d}. Regenerate it (see README) "
                                "before scoring with --gate; the gate cannot be evaluated without it.")
    return recs


COND_DIR = {"C1": "complete", "C2": "partial_undocumented", "C3": "partial_documented"}


def relevant_hosts(sid, cond, meta):
    """Hosts an analyst would consider for this alert without any label: the alert's focus hosts, every host that
    appears in the case view the investigator sees, and the core servers (domain controller, file server)."""
    hs = set(meta["focus"].get("hosts", []))
    view = WS / "04_conditions" / COND_DIR[cond] / sid / "events.jsonl"
    for line in view.read_text(encoding="utf-8").splitlines():
        hs.add(json.loads(line)["host"])
    return hs


def silences(sid, cond, scope="all"):
    meta = json.loads((cfg(sid) / f"{sid}.meta.json").read_text(encoding="utf-8"))
    recs = _all(sid)
    if cond != "C1":
        recs = [r for r in recs if not in_gap(r, meta["gap"])]
    w0, w1 = P(meta["window"][0]), P(meta["window"][1])
    warm0 = w0 - timedelta(hours=1)
    out = {}
    for src in DEC.get(meta["alert_category"], []):
        hosts = {r["host"] for r in recs if r["source"] == src and warm0 <= P(r["ts"]) < w0}
        if scope == "relevant":
            rel = relevant_hosts(sid, cond, meta)
            hosts = {h for h in hosts if h in rel or h.startswith(("DC-", "FILE-"))}
        for h in hosts:
            ts = sorted(P(r["ts"]) for r in recs if r["source"] == src and r["host"] == h and w0 <= P(r["ts"]) < w1)
            pts = [w0] + ts + [w1]
            out[f"{src}@{h}"] = round(max((b - a).total_seconds() for a, b in zip(pts, pts[1:])) / 60, 1)
    return out


def veto(sid, cond, threshold_min, scope="all"):
    s = silences(sid, cond, scope)
    return any(v >= threshold_min for v in s.values()), s


if __name__ == "__main__":
    for sid in sys.argv[1:]:
        for c in ("C1", "C2"):
            print(sid, c, silences(sid, c))
