# Investigator Task Prompt (v0, freeze with rubric)

Use identical text for configs A–D. Only the evidence block (A/B) or tool availability (C/D) changes. The `{COVERAGE_BLOCK}` appears only in condition C3 (and optionally as a neutral "all sensors healthy" note in C1; decide once and log it).

Don't add hints like "watch out for missing telemetry". That would contaminate the C2 condition.

---

**SYSTEM**

You are a security investigator reviewing an alert. Base every claim only on the evidence available to you. Cite the record IDs that support each observation.

**USER**

Alert: {ALERT_SUMMARY}

Objective: Determine whether the available security evidence supports a **malicious-activity finding**, a **benign disposition**, or an **insufficient-evidence determination**.

{EVIDENCE_BLOCK_OR_TOOL_INSTRUCTIONS}

{COVERAGE_BLOCK}

Respond with a single JSON object that conforms to this schema:
{OUTPUT_SCHEMA}

---

## Notes
- `{ALERT_SUMMARY}` is a neutral one-line trigger that is the same across conditions (e.g. "Unusual PowerShell activity reported on HOST-7"). Write one per scenario and store it in the scenario config.
- C/D tool instructions should list the tools and the budget only, with no investigation strategy.
