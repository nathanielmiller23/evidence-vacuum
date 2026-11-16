"""v2 resolution reviewer: ONE prompt definition shared by training-data export and evaluation (G-base, G-ft).

Input : investigator JSON answer + org context + coverage manifest (C3 only). Never raw logs, labels,
        scenario IDs or the condition name.
Output: {"epistemic_status": ..., "recommended_action": ..., "missing_decisive_evidence": [...]}
"""
import json
import re

REVIEWER_SYSTEM = (
    "You are an independent reviewer of security investigations. You receive an investigator's structured "
    "findings, the organization's inventory context, and sensor coverage information when available. Decide what the "
    "evidence actually supports for the ALERTED activity: malicious_supported (escalate), benign_supported (close), or "
    "insufficient_evidence (collect_more). Close only when the alerted activity is positively explained as legitimate "
    "and no telemetry needed to check it was missing. Unrelated anomalies elsewhere do not by themselves prevent closing "
    "the alerted activity. Never treat missing logs as proof that nothing happened. Respond with ONLY a JSON object with "
    'keys "epistemic_status", "recommended_action", "missing_decisive_evidence".')

NO_COVERAGE = "No sensor coverage information was provided."
STATUS_TO_ACTION = {"malicious_supported": "escalate", "benign_supported": "close", "insufficient_evidence": "collect_more"}
LABEL_TO_STATUS = {"MALICIOUS_SUPPORTED": "malicious_supported", "BENIGN_SUPPORTED": "benign_supported",
                   "INSUFFICIENT": "insufficient_evidence"}


_REC_ID = re.compile(r"\b(?:[STPD]\d{2,3}|DUMMY\d+|d1)-(\d{4,5})\b")


def render_user(investigator_output: dict, context: str | None, manifest: dict | None) -> str:
    payload = {"organization_context": context or "", "investigator_findings": investigator_output,
               "coverage_information": manifest if manifest is not None else NO_COVERAGE}
    # Mask scenario-specific record-ID prefixes (T013-00071 / S02-00045 -> REC-00071) so the reviewer can't key on
    # scenario identity, and train (T*) and eval (S*) inputs look the same. Added 2026-11-15 before any v2 eval output.
    return _REC_ID.sub(r"REC-\1", json.dumps(payload, ensure_ascii=False))


def render_messages(investigator_output, context, manifest):
    return [{"role": "system", "content": REVIEWER_SYSTEM},
            {"role": "user", "content": render_user(investigator_output, context, manifest)}]


def target(label: str, missing: list[str]) -> str:
    status = LABEL_TO_STATUS[label]
    return json.dumps({"epistemic_status": status, "recommended_action": STATUS_TO_ACTION[status],
                       "missing_decisive_evidence": missing}, ensure_ascii=False)


def parse_review(text: str):
    m = re.search(r"\{.*\}", text or "", flags=re.S)
    if not m:
        return None
    try:
        d = json.loads(m.group(0))
    except json.JSONDecodeError:
        return None
    if d.get("epistemic_status") not in STATUS_TO_ACTION or d.get("recommended_action") not in ("close", "escalate", "collect_more"):
        return None
    return d
