"""Walk a project, dispatch files to the right checks, and collect findings."""

from __future__ import annotations

import fnmatch
import os
from dataclasses import dataclass, field
from pathlib import Path

from .checks.ci import scan_workflow
from .checks.code import scan_code
from .checks.deps import osv_lookup, scan_package_json, scan_requirements
from .checks.docker import scan_compose, scan_dockerfile
from .checks.secrets import scan_text
from .models import RANK, Finding

SKIP_DIRS = {".git", "node_modules", ".venv", "venv", "__pycache__", "dist", "build", ".tox", ".mypy_cache", ".ruff_cache", ".pytest_cache", ".next"}
TEXT_EXT = {".py", ".js", ".mjs", ".cjs", ".ts", ".tsx", ".jsx", ".json", ".yml", ".yaml", ".toml", ".ini", ".cfg", ".conf", ".env",
            ".txt", ".sh", ".md", ".properties", ".xml", ".tf", ".rb", ".go", ".java", ".php", ".cs"}
MAX_BYTES = 1_000_000


@dataclass
class ScanResult:
    root: str
    files_scanned: int = 0
    findings: list[Finding] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)

    def counts(self) -> dict[str, int]:
        c = {s: 0 for s in RANK}
        for f in self.findings:
            c[f.severity] += 1
        return c

    def worst(self) -> str | None:
        return max((f.severity for f in self.findings), key=lambda s: RANK[s], default=None)


def _is_text_candidate(p: Path) -> bool:
    name = p.name
    return (p.suffix.lower() in TEXT_EXT or name.startswith(".env") or name in ("Dockerfile", "Containerfile", "Procfile")
            or name.startswith("Dockerfile") or name.endswith(".dockerfile"))


def _load_ignores(root: Path) -> list[str]:
    f = root / ".vulnscanignore"
    if not f.exists():
        return []
    return [ln.strip() for ln in f.read_text().splitlines() if ln.strip() and not ln.startswith("#")]


def iter_files(root: Path):
    ignores = _load_ignores(root)
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
        for fn in filenames:
            p = Path(dirpath) / fn
            rel = p.relative_to(root).as_posix()
            if any(fnmatch.fnmatch(rel, pat) for pat in ignores):
                continue
            if _is_text_candidate(p) and p.stat().st_size <= MAX_BYTES:
                yield p, rel


def scan_file(rel: str, text: str) -> tuple[list[Finding], list]:
    name = rel.rsplit("/", 1)[-1]
    findings: list[Finding] = []
    pkgs: list = []
    findings += scan_text(rel, text)
    if fnmatch.fnmatch(name, "requirements*.txt"):
        f, pkgs = scan_requirements(rel, text)
        findings += f
    elif name == "package.json":
        f, pkgs = scan_package_json(rel, text)
        findings += f
    elif name.startswith(("Dockerfile", "Containerfile")) or name.endswith(".dockerfile"):
        findings += scan_dockerfile(rel, text)
    elif fnmatch.fnmatch(name, "*compose*.y*ml"):
        findings += scan_compose(rel, text)
    elif rel.startswith(".github/workflows/") and name.endswith((".yml", ".yaml")):
        findings += scan_workflow(rel, text)
    if name.endswith((".py", ".js", ".mjs", ".cjs", ".ts", ".tsx", ".jsx")):
        findings += scan_code(rel, text)
    return findings, pkgs


def project_checks(root: Path, rels: set[str]) -> list[Finding]:
    out: list[Finding] = []
    env_files = sorted(r for r in rels if r.rsplit("/", 1)[-1] in (".env", ".env.local", ".env.production", ".env.prod", ".env.development"))
    gitignore = (root / ".gitignore").read_text(errors="replace") if (root / ".gitignore").exists() else ""
    ignored = any(ln.strip() in (".env", ".env*", "*.env", ".env.*", "/.env") for ln in gitignore.splitlines())
    for env in env_files:
        if not ignored:
            out.append(Finding("CONF001", ".env file not git-ignored", "high", env, 0, f"{env} exists and .gitignore doesn't exclude it, so it is one `git add .` away from leaking",
                               "", "Add `.env` to .gitignore and commit a .env.example with empty values instead.", "config"))
    if env_files and not any(r.endswith((".env.example", ".env.sample", ".env.template")) for r in rels):
        out.append(Finding("CONF002", "No .env.example", "info", ".", 0, "Contributors can't tell which variables are required",
                           "", "Commit a .env.example with placeholder values.", "config"))
    return out


def scan_path(root: str | Path, use_osv: bool = False, min_severity: str = "info") -> ScanResult:
    root = Path(root).resolve()
    res = ScanResult(str(root))
    all_pkgs, rels = [], set()
    for p, rel in iter_files(root):
        rels.add(rel)
        try:
            text = p.read_text(encoding="utf-8")
        except (UnicodeDecodeError, OSError):
            continue
        res.files_scanned += 1
        f, pkgs = scan_file(rel, text)
        res.findings += f
        all_pkgs += [(eco, n, v, ln, rel) for eco, n, v, ln in pkgs]
    res.findings += project_checks(root, rels)
    if use_osv and all_pkgs:
        try:
            hits = osv_lookup([p[:4] for p in all_pkgs])
            for _eco, name, ver, ln, rel in all_pkgs:
                ids = hits.get((name, ver), [])
                known = {f.rule_id for f in res.findings if f.file == rel and f.line == ln}
                fresh = [i for i in ids if f"VULN-{i}" not in known]
                if fresh:
                    res.findings.append(Finding("OSV", f"{name} {ver}: {len(fresh)} known vulnerabilit{'y' if len(fresh) == 1 else 'ies'}", "high", rel, ln,
                                                f"osv.dev reports {', '.join(fresh[:6])}{'...' if len(fresh) > 6 else ''}", f"{name}=={ver}",
                                                f"Check https://osv.dev/list?q={name} and upgrade to a fixed version.", "dependency"))
            res.notes.append(f"osv.dev: checked {len(all_pkgs)} pinned package(s)")
        except Exception as exc:  # offline or API change: never fail the scan for this
            res.notes.append(f"osv.dev lookup skipped ({exc.__class__.__name__})")
    res.findings = [f for f in res.findings if RANK[f.severity] >= RANK[min_severity]]
    res.findings.sort(key=lambda f: (-RANK[f.severity], f.file, f.line))
    return res
