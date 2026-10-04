"""GitHub Actions workflow checks (script injection, unpinned actions, dangerous triggers)."""

from __future__ import annotations

import re

from ..models import Finding

UNTRUSTED = re.compile(r"\$\{\{\s*github\.(event\.(issue|pull_request|comment|review|discussion)\.(title|body)|event\.pull_request\.head\.ref|head_ref|event\.commits)")


def scan_workflow(path: str, text: str) -> list[Finding]:
    f: list[Finding] = []
    lines = text.splitlines()
    prt = any(re.match(r"^\s*(on:\s*)?\[?.*\bpull_request_target\b", ln) for ln in lines)
    for i, ln in enumerate(lines, 1):
        if UNTRUSTED.search(ln):
            f.append(Finding("CI001", "Script injection in workflow", "high", path, i,
                             "Untrusted event data is expanded directly into a script; an attacker controls it via a PR/issue title",
                             ln.strip(), "Pass it through an env var (env: TITLE: ${{ ... }}) and quote \"$TITLE\" in the script.", "ci"))
        m = re.search(r"uses:\s*([\w.\-]+/[\w.\-/]+)@([\w.\-]+)", ln)
        if m and not m[1].startswith(("actions/", "github/")):
            ref = m[2]
            if ref in ("master", "main", "latest") or not re.fullmatch(r"[0-9a-f]{40}", ref):
                f.append(Finding("CI002", "Third-party action not pinned to a commit", "low" if ref not in ("master", "main") else "medium",
                                 path, i, f"{m[1]}@{ref} can change under you", ln.strip(), "Pin to a full commit SHA (with a version comment).", "ci"))
        if prt and re.search(r"ref:\s*\$\{\{\s*github\.event\.pull_request\.head\.(sha|ref)", ln):
            f.append(Finding("CI003", "pull_request_target checks out untrusted code", "critical", path, i,
                             "Runs fork code with a write token and secrets ('pwn request')", ln.strip(),
                             "Use pull_request for untrusted code, or never check out the PR head in pull_request_target jobs.", "ci"))
        if re.match(r"^\s*permissions:\s*write-all", ln):
            f.append(Finding("CI004", "Workflow token has write-all", "medium", path, i, "GITHUB_TOKEN has every write permission", ln.strip(),
                             "Declare least-privilege permissions per job.", "ci"))
    return f
