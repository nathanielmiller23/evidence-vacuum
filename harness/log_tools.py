"""Constrained log-query tools for the Config C (CUGA) investigator.

One ToolSession = one (scenario, condition) view. Tools read only that view's
JSONL store, so ground truth and other conditions are unreachable.

Store layout (written by the normalizer / gap filter, or make_dummy_store.py):
    04_conditions/<condition_dir>/<scenario_id>/events.jsonl
    04_conditions/partial_documented/<scenario_id>/coverage_manifest.json   (C3 only)
    04_conditions/complete/<scenario_id>/source_catalog.json                (same catalog for all conditions)

Record format (one JSON object per line):
    {"record_id": str, "ts": ISO-8601 str, "host": str, "source": str, "event_type": str, "raw": str}
"""
from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Optional

from langchain_core.tools import StructuredTool

WORKSPACE = Path(__file__).resolve().parents[1]
CONDITIONS = {"C1": "complete", "C2": "partial_undocumented", "C3": "partial_documented"}
MAX_ROWS = 25          # rows returned per query
MAX_TOOL_CALLS = 30    # our own hard budget, independent of CUGA's settings


def view_dir(scenario_id: str, condition: str) -> Path:
    return WORKSPACE / "04_conditions" / CONDITIONS[condition] / scenario_id


class ToolSession:
    """Holds one view's data plus a call log that we own (independent of CUGA's tracking)."""

    def __init__(self, scenario_id: str, condition: str, max_rows: int = MAX_ROWS,
                 max_calls: int = MAX_TOOL_CALLS):
        self.scenario_id, self.condition = scenario_id, condition
        self.max_rows, self.max_calls = max_rows, max_calls
        d = view_dir(scenario_id, condition)
        self.records = [json.loads(l) for l in (d / "events.jsonl").read_text(encoding="utf-8").splitlines() if l.strip()]
        self.by_id = {r["record_id"]: r for r in self.records}
        # Catalog comes from the COMPLETE view so the source list is identical across conditions
        # (a source vanishing from the list would itself leak the gap in C2).
        cat = view_dir(scenario_id, "C1") / "source_catalog.json"
        self.catalog = json.loads(cat.read_text(encoding="utf-8")) if cat.exists() else sorted({r["source"] for r in self.records})
        man = d / "coverage_manifest.json"
        self.manifest = json.loads(man.read_text(encoding="utf-8")) if (condition == "C3" and man.exists()) else None
        self.calls: list[dict] = []

    # ---- bookkeeping -------------------------------------------------------
    def _log(self, name: str, args: dict, result: str) -> str:
        self.calls.append({"i": len(self.calls) + 1, "t": time.time(), "tool": name, "args": args,
                           "n_chars": len(result), "result_preview": result[:500]})
        return result

    def _over_budget(self) -> bool:
        return len(self.calls) >= self.max_calls

    # ---- tool bodies -------------------------------------------------------
    def list_sources(self) -> str:
        """List the log sources available in this environment."""
        if self._over_budget():
            return self._log("list_sources", {}, "ERROR: tool-call budget exhausted. Give your final answer now.")
        hosts = sorted({r["host"] for r in self.records} | set(self._catalog_hosts()))
        out = json.dumps({"sources": self.catalog, "known_hosts": hosts})
        return self._log("list_sources", {}, out)

    def _catalog_hosts(self) -> list[str]:
        p = view_dir(self.scenario_id, "C1") / "events.jsonl"
        if not p.exists():
            return []
        return [json.loads(l)["host"] for l in p.read_text(encoding="utf-8").splitlines() if l.strip()]

    def query(self, source: str, host: str = "", time_from: str = "", time_to: str = "",
              contains: str = "", offset: int = 0) -> str:
        """Search one log source. Optional filters: host (exact), time_from/time_to (ISO-8601,
        inclusive), contains (case-insensitive substring of event_type or raw). Returns at most
        25 rows, oldest first, starting at `offset` (for paging), plus the total match count."""
        args = {"source": source, "host": host, "time_from": time_from, "time_to": time_to,
                "contains": contains, "offset": offset}
        if self._over_budget():
            return self._log("query", args, "ERROR: tool-call budget exhausted. Give your final answer now.")
        if source not in self.catalog:
            return self._log("query", args, json.dumps({"error": f"unknown source '{source}'", "sources": self.catalog}))
        c = contains.lower()
        rows = [r for r in self.records
                if r["source"] == source
                and (not host or r["host"] == host)
                and (not time_from or r["ts"] >= time_from)
                and (not time_to or r["ts"] <= time_to)
                and (not c or c in r["event_type"].lower() or c in r["raw"].lower())]
        rows.sort(key=lambda r: r["ts"])
        page = rows[max(0, int(offset)): max(0, int(offset)) + self.max_rows]
        out = json.dumps({"total_matches": len(rows), "offset": max(0, int(offset)), "returned": len(page),
                          "rows": page})
        return self._log("query", args, out)

    def get_record(self, record_id: str) -> str:
        """Fetch one log record by its record_id."""
        if self._over_budget():
            return self._log("get_record", {"record_id": record_id}, "ERROR: tool-call budget exhausted. Give your final answer now.")
        r = self.by_id.get(record_id)
        return self._log("get_record", {"record_id": record_id},
                         json.dumps(r) if r else json.dumps({"error": f"no record '{record_id}'"}))

    def get_coverage(self) -> str:
        """Return sensor coverage and collection status (which sensors were operating, for which
        hosts and time windows, and known gaps)."""
        if self._over_budget():
            return self._log("get_coverage", {}, "ERROR: tool-call budget exhausted. Give your final answer now.")
        return self._log("get_coverage", {}, json.dumps(self.manifest))

    # ---- LangChain tools ---------------------------------------------------
    def tools(self) -> list[StructuredTool]:
        ts = [StructuredTool.from_function(self.list_sources, name="list_sources"),
              StructuredTool.from_function(self.query, name="query"),
              StructuredTool.from_function(self.get_record, name="get_record")]
        if self.manifest is not None:          # C3 only
            ts.append(StructuredTool.from_function(self.get_coverage, name="get_coverage"))
        return ts
