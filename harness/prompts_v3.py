"""v3 investigator prompt variants (Stage 2). P1 = the frozen v1 prompt; P2–P4 add scope and closure guidance.
None of them mentions telemetry gaps or coverage (that would contaminate C2); C3 still gets the manifest block.
"""
import json
from copy import deepcopy

from prompts import OBJECTIVE, SCHEMA, SYSTEM, _context_block

SCHEMA_V3 = deepcopy(SCHEMA)
SCHEMA_V3["required"] = SCHEMA_V3["required"] + ["unrelated_findings"]
SCHEMA_V3["properties"]["unrelated_findings"] = {
    "type": "array", "items": {"type": "string"},
    "description": "Anomalies NOT part of the alerted activity. They go to a separate ticket and do not decide this alert."}

SCOPE = ("Scope: decide only about the ALERTED activity. Other anomalies you notice (unapproved services, odd processes, "
         "unrelated hosts or users) go in `unrelated_findings` for a separate ticket; they must not by themselves decide "
         "this alert. If you recommend escalate, at least one supporting observation must cite a record of the alerted activity.")
CHECKLIST = ("Before recommending close, check all of these: (1) the alerted activity itself is visible in the evidence and "
             "cited; (2) it matches a specific legitimate explanation from the environment context (a named account, tool, "
             "schedule, ticket or change); (3) the evidence that would show the malicious alternative for this kind of "
             "alert is present for the alert window, not just absent. If (1) and (2) hold but (3) does not, recommend "
             "collect_more. If all three hold, recommend close, even if unrelated anomalies exist.")
REALISTIC = ("Note on the environment context: it lists what IT documented; it is not exhaustive. Software or services that "
             "the context does not mention are not, by themselves, evidence that the alerted activity is malicious.")


def _schema_block(schema) -> str:
    shown = {k: v for k, v in schema.items() if k not in ("$schema", "title")}
    return ("Respond with a single JSON object (no prose, no code fences) that conforms to this JSON schema. "
            "Output only the instance, not the schema:\n" + json.dumps(shown, indent=1))


def build(variant: str, alert: str, events_jsonl: str, manifest, context):
    """Returns (system, user, schema)."""
    if variant == "P1":
        guidance, schema = [], SCHEMA
    elif variant == "P2":
        guidance, schema = [SCOPE], SCHEMA_V3
    elif variant == "P3":
        guidance, schema = [SCOPE, CHECKLIST], SCHEMA_V3
    elif variant == "P4":
        guidance, schema = [SCOPE, CHECKLIST, REALISTIC], SCHEMA_V3
    else:
        raise ValueError(variant)
    parts = [f"Alert: {alert}", *_context_block(context), OBJECTIVE, *guidance,
             "Evidence (one JSON log record per line):\n" + events_jsonl]
    if manifest is not None:
        parts.append("Sensor coverage and collection status:\n" + json.dumps(manifest, indent=1))
    parts.append(_schema_block(schema))
    return SYSTEM, "\n\n".join(parts), schema
