"""Investigator prompt, shared by Config A (fixed evidence) and Config C (CUGA).

Mirrors 06_prompts/investigator_task.md. Freeze with the rubric. Must contain no hints about
telemetry gaps (that would contaminate C2).
"""
import json
from pathlib import Path

WS = Path(__file__).resolve().parents[1]
SCHEMA = json.loads((WS / "06_prompts" / "output_schema.json").read_text(encoding="utf-8"))

SYSTEM = ("You are a security investigator reviewing an alert. Base every claim only on the evidence "
          "available to you. Cite the record IDs that support each observation.")

OBJECTIVE = ("Objective: Determine whether the available security evidence supports a malicious-activity "
             "finding, a benign disposition, or an insufficient-evidence determination.")


def scen_dir(scenario_id: str) -> Path:
    """v2 addition: training-pool scenarios (T*) live in 03_scenarios/tpool/configs. S*/P* unchanged."""
    return WS / "03_scenarios" / ("tpool/configs" if scenario_id.startswith("T") else "configs")


def load_alert(scenario_id: str) -> str:
    meta = scen_dir(scenario_id) / f"{scenario_id}.meta.json"
    return json.loads(meta.read_text(encoding="utf-8"))["alert_summary"]


def load_context(scenario_id: str) -> str | None:
    """Fixed organization context for the scenario's environment (identical across conditions and configs).
    Added after the P02 pilot: without it nothing could be positively benign (no knowledge of approved
    vendors / service accounts). It must never mention telemetry coverage."""
    meta = json.loads((scen_dir(scenario_id) / f"{scenario_id}.meta.json").read_text(encoding="utf-8"))
    name = meta.get("environment_context")
    if not name:
        return None
    path = (WS / "03_scenarios" / name) if "/" in name else (scen_dir(scenario_id) / name)
    return path.read_text(encoding="utf-8").strip()


def _context_block(context: str | None) -> list[str]:
    return [f"Environment context (from the organization's asset and service inventory):\n{context}"] if context else []


def _schema_block() -> str:
    # Schema metadata keys are omitted: in the pilot the model copied "$schema"/"title" into its answer.
    shown = {k: v for k, v in SCHEMA.items() if k not in ("$schema", "title")}
    return ("Respond with a single JSON object (no prose, no code fences) that conforms to this JSON schema. "
            "Output only the instance, not the schema:\n" + json.dumps(shown, indent=1))


def user_prompt_fixed(alert: str, events_jsonl: str, manifest: dict | None, context: str | None = None) -> str:
    """Config A: whole view in context. Manifest only in C3."""
    parts = [f"Alert: {alert}", *_context_block(context), OBJECTIVE,
             "Evidence (one JSON log record per line):\n" + events_jsonl]
    if manifest is not None:
        parts.append("Sensor coverage and collection status:\n" + json.dumps(manifest, indent=1))
    parts.append(_schema_block())
    return "\n\n".join(parts)


def user_prompt_tools(alert: str, tool_names: list[str], max_calls: int, context: str | None = None) -> str:
    """Config C: evidence only via tools. Lists tools and budget, with no investigation strategy."""
    parts = [f"Alert: {alert}", *_context_block(context), OBJECTIVE,
             f"Evidence is available only through these tools: {', '.join(tool_names)}. "
             f"Retrieve evidence with the tools before answering. You may make at most {max_calls} tool calls.",
             _schema_block()]
    return "\n\n".join(parts)
