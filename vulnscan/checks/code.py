"""Lightweight risky-pattern checks for Python and JavaScript/TypeScript source (no AST, so: hints, not proofs)."""

from __future__ import annotations

import re

from ..models import Finding

PY_RULES = [
    ("CODE001", "Flask/Django debug mode enabled", "medium", re.compile(r"(\.run\(.*debug\s*=\s*True|^\s*DEBUG\s*=\s*True)"), "Disable debug outside local development."),
    ("CODE002", "TLS verification disabled", "high", re.compile(r"verify\s*=\s*False"), "Keep verify=True; point to a CA bundle for private certs."),
    ("CODE003", "Unsafe YAML load", "high", re.compile(r"yaml\.load\((?![^)]*Loader\s*=\s*yaml\.(Safe|CSafe)Loader)"), "Use yaml.safe_load()."),
    ("CODE004", "Unpickling data", "medium", re.compile(r"\b(pickle|cPickle|dill)\.loads?\("), "Never unpickle untrusted data; use JSON."),
    ("CODE005", "Shell command built with shell=True", "medium", re.compile(r"subprocess\.\w+\(.*shell\s*=\s*True"), "Pass an argument list without shell=True."),
    ("CODE006", "eval/exec on dynamic input", "high", re.compile(r"(?<![\w.])(eval|exec)\((?!\s*['\"])"), "Avoid eval/exec; parse explicitly (ast.literal_eval for literals)."),
    ("CODE007", "SQL built with string formatting", "high", re.compile(r"(?i)\.execute\(\s*(f[\"']|[\"'].*%s?[\"']\s*%|[\"'].*[\"']\s*\+|.*\.format\()\s*.*(select|insert|update|delete)"), "Use parameterised queries."),
    ("CODE008", "Weak hash for passwords", "medium", re.compile(r"(?i)hashlib\.(md5|sha1)\(.*pass"), "Use bcrypt/argon2/scrypt for passwords."),
]
JS_RULES = [
    ("CODE101", "eval() / new Function()", "high", re.compile(r"(?<![\w.])eval\(|new Function\("), "Avoid dynamic code evaluation."),  # vulnscan:ignore (rule definition)
    ("CODE102", "TLS verification disabled", "high", re.compile(r"rejectUnauthorized\s*:\s*false|NODE_TLS_REJECT_UNAUTHORIZED\s*=\s*['\"]?0"), "Keep certificate validation on."),
    ("CODE103", "innerHTML assignment", "medium", re.compile(r"\.innerHTML\s*=(?!\s*['\"]\s*['\"])"), "Use textContent or a sanitiser (DOMPurify)."),
    ("CODE104", "child_process.exec with interpolation", "high", re.compile(r"exec(Sync)?\(\s*(`[^`]*\$\{|[^)]*\+)"), "Use execFile/spawn with an argument array."),  # vulnscan:ignore (rule definition)
    ("CODE105", "Permissive CORS", "low", re.compile(r"(Access-Control-Allow-Origin['\"]?\s*[,:]\s*['\"]\*|cors\(\s*\))"), "Restrict allowed origins."),
]


def scan_code(path: str, text: str) -> list[Finding]:
    rules = PY_RULES if path.endswith(".py") else JS_RULES
    out = []
    for i, line in enumerate(text.splitlines(), 1):
        s = line.strip()
        if s.startswith(("#", "//", "*")) or "vulnscan:ignore" in line:
            continue
        for rid, title, sev, pat, fix in rules:
            if pat.search(line):
                out.append(Finding(rid, title, sev, path, i, title, s[:160], fix, "code"))
    return out
