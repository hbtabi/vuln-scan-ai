"""Output formats: coloured text, JSON, Markdown and SARIF 2.1.0 (for GitHub code scanning)."""

from __future__ import annotations

import json

from . import __version__
from .models import RANK
from .scanner import ScanResult

ANSI = {"critical": "1;35", "high": "1;31", "medium": "33", "low": "36", "info": "90"}
SARIF_LEVEL = {"critical": "error", "high": "error", "medium": "warning", "low": "note", "info": "note"}


def _c(s: str, code: str, on: bool) -> str:
    return f"\033[{code}m{s}\033[0m" if on else s


def to_text(res: ScanResult, color: bool = False, explanations: dict[int, str] | None = None) -> str:
    out = [_c(f"vuln-scan-ai: {res.files_scanned} files scanned, {len(res.findings)} finding(s)", "1", color),
           "  " + "  ".join(_c(f"{n} {s}", ANSI[s], color) for s, n in res.counts().items() if n), ""]
    if not res.findings:
        out = out[:1]
    for i, f in enumerate(res.findings):
        out.append(f"{_c(f'[{f.severity.upper():>8}]', ANSI[f.severity], color)} {_c(f.rule_id, '90', color)} {f.title}")
        out.append(f"           {_c(f.location, '4', color)}  {f.message}")
        if f.snippet:
            out.append(_c(f"           > {f.snippet}", "90", color))
        if f.fix:
            out.append(f"           {_c('fix:', '32', color)} {f.fix}")
        if explanations and i in explanations:
            out.append(f"           {_c('ai:', '35', color)} " + explanations[i].replace("\n", "\n                "))
    for n in res.notes:
        out.append(_c(f"note: {n}", "90", color))
    if not res.findings:
        out.append(_c("No issues found. (Absence of findings is not proof of security.)", "32", color))
    return "\n".join(out)


def to_json(res: ScanResult) -> str:
    return json.dumps({"tool": "vuln-scan-ai", "version": __version__, "root": res.root, "files_scanned": res.files_scanned,
                       "counts": res.counts(), "findings": [f.to_dict() for f in res.findings], "notes": res.notes}, indent=2)


def to_markdown(res: ScanResult) -> str:
    rows = ["| Severity | Rule | Location | Issue | Fix |", "|---|---|---|---|---|"]
    for f in res.findings:
        rows.append(f"| {f.severity} | `{f.rule_id}` | `{f.location}` | {f.title}: {f.message} | {f.fix} |".replace("\n", " "))
    counts = ", ".join(f"{n} {s}" for s, n in res.counts().items() if n) or "no findings"
    return f"## vuln-scan-ai report\n\n{res.files_scanned} files scanned: **{counts}**\n\n" + "\n".join(rows) + "\n"


def to_sarif(res: ScanResult) -> str:
    rules = {}
    for f in res.findings:
        rules.setdefault(f.rule_id, {"id": f.rule_id, "name": f.title, "shortDescription": {"text": f.title},
                                     "help": {"text": f.fix or f.title}, "properties": {"category": f.category}})
    results = [{
        "ruleId": f.rule_id, "level": SARIF_LEVEL[f.severity], "message": {"text": f"{f.message}. Fix: {f.fix}"},
        "locations": [{"physicalLocation": {"artifactLocation": {"uri": f.file}, "region": {"startLine": max(f.line, 1)}}}],
        "properties": {"severity": f.severity, "security-severity": str({5: 9.5, 4: 8.0, 3: 5.5, 2: 3.0, 1: 1.0}[RANK[f.severity]])},
    } for f in res.findings]
    return json.dumps({"$schema": "https://json.schemastore.org/sarif-2.1.0.json", "version": "2.1.0",
                       "runs": [{"tool": {"driver": {"name": "vuln-scan-ai", "version": __version__, "informationUri": "https://github.com/hbtabi/vuln-scan-ai",
                                                     "rules": list(rules.values())}}, "results": results}]}, indent=2)
