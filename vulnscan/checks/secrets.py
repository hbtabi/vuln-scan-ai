"""Hard-coded secret detection: provider-specific patterns + a generic, entropy-gated assignment rule.

Matches are *always* redacted before they leave this module (terminal, JSON, SARIF, LLM prompt).
"""

from __future__ import annotations

import math
import re
from collections import Counter

from ..models import Finding

_PEM = "-----BEGIN " + r"(?:RSA |EC |DSA |OPENSSH |ENCRYPTED |PGP )?PRIVATE KEY" + "-----"

# (rule_id, title, severity, regex). Patterns follow the providers' documented token formats.
PATTERNS: list[tuple[str, str, str, re.Pattern]] = [
    ("SEC001", "AWS access key ID", "critical", re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b")),
    ("SEC002", "AWS secret access key", "critical", re.compile(r"(?i)aws_?secret_?access_?key[\"']?\s*[:=]\s*[\"']?([A-Za-z0-9/+=]{40})\b")),
    ("SEC003", "GitHub token", "critical", re.compile(r"\b(?:gh[pousr]_[A-Za-z0-9]{36,}|github_pat_[A-Za-z0-9_]{60,})\b")),
    ("SEC004", "Private key", "critical", re.compile(_PEM)),
    ("SEC005", "Slack token", "high", re.compile(r"\bxox[abpors]-[A-Za-z0-9-]{10,}\b")),
    ("SEC006", "Stripe live secret key", "critical", re.compile(r"\b(?:sk|rk)_live_[A-Za-z0-9]{20,}\b")),
    ("SEC007", "Google API key", "high", re.compile(r"\bAIza[0-9A-Za-z_\-]{35}\b")),
    ("SEC008", "OpenAI-style API key", "high", re.compile(r"\bsk-(?:proj-|ant-)?[A-Za-z0-9_\-]{32,}\b")),
    ("SEC009", "JSON Web Token", "medium", re.compile(r"\beyJ[A-Za-z0-9_\-]{10,}\.eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\b")),
    ("SEC010", "Credentials in URL", "high", re.compile(r"\b[a-z][a-z0-9+.\-]*://[^\s:/@\"']+:([^\s:/@\"']{3,})@[^\s/\"']+")),
]
GENERIC = re.compile(
    r"""(?ix)(?P<key>[a-z0-9_.\-]*(?:password|passwd|pwd|secret|token|api[_\-]?key|apikey|access[_\-]?key|client[_\-]?secret|auth)[a-z0-9_.\-]*)
        ["']?\s*(?::|=|:=|=>)\s*["'](?P<val>[^"'\s]{8,})["']"""
)
ENV_LINE = re.compile(r"^\s*(?:export\s+)?(?P<key>[A-Z0-9_]*(?:PASSWORD|SECRET|TOKEN|API_KEY|APIKEY|ACCESS_KEY|PRIVATE_KEY|DSN)[A-Z0-9_]*)\s*=\s*[\"']?(?P<val>[^\"'\s#]+)")
PLACEHOLDER = re.compile(r"(?i)(example|sample|dummy|placeholder|changeme|change_me|your[_\-]|xxx+|\*\*\*|<[^>]+>|\$\{|\{\{|%\(|process\.env|os\.environ|getenv|redacted|test|fake|none|null|todo)")


def entropy(s: str) -> float:
    c = Counter(s)
    return -sum(n / len(s) * math.log2(n / len(s)) for n in c.values()) if s else 0.0


def redact(value: str) -> str:
    if len(value) <= 8:
        return "*" * len(value)
    return f"{value[:4]}{'*' * min(12, len(value) - 6)}{value[-2:]}"


def redact_line(line: str, secret: str) -> str:
    return line.replace(secret, redact(secret)).strip()[:160]


def scan_text(path: str, text: str) -> list[Finding]:
    findings: list[Finding] = []
    is_env = path.rsplit("/", 1)[-1].startswith(".env") and not path.endswith((".example", ".sample", ".template"))
    for lineno, line in enumerate(text.splitlines(), 1):
        if "vulnscan:ignore" in line:
            continue
        hit = False
        for rule_id, title, sev, pat in PATTERNS:
            for m in pat.finditer(line):
                secret = m.group(1) if pat.groups else m.group(0)
                if rule_id != "SEC004" and PLACEHOLDER.search(secret):
                    continue
                hit = True
                findings.append(Finding(rule_id, title, sev, path, lineno, f"{title} hard-coded in source", redact_line(line, secret),
                                        "Revoke/rotate the credential now, remove it from git history (git filter-repo), load it from the environment or a secret manager.",
                                        "secret"))
        if hit:
            continue
        m = (ENV_LINE.match(line) if is_env else None) or GENERIC.search(line)
        if m:
            val = m.group("val")
            if PLACEHOLDER.search(val) or val.lower() in ("true", "false") or (not is_env and entropy(val) < 3.0):
                continue
            findings.append(Finding("SEC100", "Possible hard-coded credential", "high" if is_env else "medium", path, lineno,
                                    f"'{m.group('key')}' is assigned a literal value" + (" in a committed .env file" if is_env else ""),
                                    redact_line(line, val), "Move the value to an untracked .env / secret manager and read it at runtime.", "secret"))
    return findings
