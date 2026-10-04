"""Optional remediation advice from an OpenAI-compatible API.

Only finding metadata and the already-redacted snippet are sent. Raw secrets never leave the machine.
"""

from __future__ import annotations

import json
import os
import urllib.request

from .models import Finding

SYSTEM = ("You are an application security engineer helping a developer fix a finding from a defensive scanner. "
          "In at most 3 short sentences explain the risk and the concrete fix for this file. Do not provide exploit steps.")


def available() -> bool:
    return bool(os.environ.get("OPENAI_API_KEY"))


def explain(f: Finding, timeout: float = 30.0) -> str | None:
    key = os.environ.get("OPENAI_API_KEY")
    if not key:
        return None
    prompt = f"Rule: {f.rule_id} {f.title}\nSeverity: {f.severity}\nFile: {f.file}\nMessage: {f.message}\nRedacted snippet: {f.snippet}"
    body = {"model": os.environ.get("OPENAI_MODEL", "gpt-4o-mini"), "temperature": 0.2,
            "messages": [{"role": "system", "content": SYSTEM}, {"role": "user", "content": prompt}]}
    req = urllib.request.Request(os.environ.get("OPENAI_BASE_URL", "https://api.openai.com/v1").rstrip("/") + "/chat/completions",
                                 data=json.dumps(body).encode(), headers={"Authorization": f"Bearer {key}", "Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return json.loads(r.read())["choices"][0]["message"]["content"].strip()
    except Exception as exc:
        return f"(LLM unavailable: {exc.__class__.__name__})"
