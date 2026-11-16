"""Extract and validate an investigator answer against 06_prompts/output_schema.json.

No repair: a malformed answer is reported as invalid (one retry is the caller's job).
"""
import json
import re

from jsonschema import Draft202012Validator

from prompts import SCHEMA

_VALIDATOR = Draft202012Validator(SCHEMA)


def parse_investigation(text: str) -> tuple[dict | None, list[str]]:
    """Return (parsed, errors). parsed is None if no schema-valid JSON object was found."""
    if not text:
        return None, ["empty answer"]
    m = re.search(r"\{.*\}", text, flags=re.S)
    if not m:
        return None, ["no JSON object found"]
    try:
        obj = json.loads(m.group(0))
    except json.JSONDecodeError as e:
        return None, [f"JSON decode error: {e}"]
    errors = [f"{'/'.join(map(str, err.path)) or '<root>'}: {err.message}" for err in _VALIDATOR.iter_errors(obj)]
    return (obj if not errors else None), errors


def cited_ids_exist(parsed: dict, known_ids: set[str]) -> dict:
    """Faithfulness pre-check: which cited record_ids exist in the view the system saw."""
    cited = [rid for obs in parsed.get("supporting_observations", []) for rid in obs.get("record_ids", [])]
    missing = [rid for rid in cited if rid not in known_ids]
    return {"n_cited": len(cited), "n_missing": len(missing), "missing": missing}
