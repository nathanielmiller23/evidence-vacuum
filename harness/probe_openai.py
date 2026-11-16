"""One-time probe of the OpenAI investigator model before any runs. Costs a fraction of a cent.

Checks: (1) the API key works, (2) the exact model IDs available (to pin a dated snapshot if one
exists), (3) whether temperature=0 is accepted (reasoning models usually reject it), and
(4) what a reply's usage looks like (reasoning tokens).

    tools/cuga-agent/.venv/Scripts/python.exe harness/probe_openai.py
"""
import os
from pathlib import Path

from dotenv import load_dotenv
from openai import BadRequestError, OpenAI

load_dotenv(Path(__file__).resolve().parents[1] / ".env")
model = os.environ.get("MODEL_NAME", "gpt-6-luna")
client = OpenAI()

ids = sorted(m.id for m in client.models.list().data)
family = [i for i in ids if "luna" in i or i.startswith("gpt-6")]
print("Available GPT-6 / Luna model IDs:", family or "(none found)")
print("Configured MODEL_NAME:", model, "| available:", model in ids)

msgs = [{"role": "user", "content": 'Reply with exactly this JSON: {"ok": true}'}]
for label, kwargs in [("temperature=0", {"temperature": 0}), ("no temperature", {})]:
    try:
        r = client.chat.completions.create(model=model, messages=msgs, max_completion_tokens=200, **kwargs)
        u = r.usage
        details = getattr(u, "completion_tokens_details", None)
        print(f"[{label}] OK -> {r.choices[0].message.content!r} | model={r.model} | "
              f"tokens in/out={u.prompt_tokens}/{u.completion_tokens} | "
              f"reasoning={getattr(details, 'reasoning_tokens', None)}")
    except BadRequestError as e:
        print(f"[{label}] REJECTED -> {e.message}")
