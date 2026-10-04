"""Dependency checks for requirements*.txt and package.json: pinning hygiene + known advisories.

The bundled advisory list is a deliberately small offline sample. ``--osv`` queries https://osv.dev for the
real, up-to-date picture.
"""

from __future__ import annotations

import json
import re
import urllib.request
from functools import lru_cache
from importlib.resources import files

from packaging.version import InvalidVersion, Version

from ..models import Finding

REQ_LINE = re.compile(r"^\s*(?P<name>[A-Za-z0-9][A-Za-z0-9._\-]*)\s*(?:\[[^\]]*\])?\s*(?P<spec>[^;#]*)")


@lru_cache(maxsize=1)
def advisories() -> dict:
    return json.loads(files("vulnscan").joinpath("data/advisories.json").read_text())


def _v(s: str) -> Version | None:
    try:
        return Version(s)
    except InvalidVersion:
        return None


def _affected(ecosystem: str, name: str, version: str) -> list[dict]:
    v = _v(version)
    if v is None:
        return []
    out = []
    for adv in advisories().get(ecosystem, {}).get(name.lower(), []):
        ranges = adv.get("ranges") or [["0", adv["fixed"]]]
        for lo, hi in ranges:
            if _v(lo) <= v < _v(hi):
                out.append({**adv, "fixed": hi})  # report the fix for *this* release line
                break
    return out


def scan_requirements(path: str, text: str) -> tuple[list[Finding], list[tuple[str, str, str, int]]]:
    findings, pkgs = [], []
    for lineno, raw in enumerate(text.splitlines(), 1):
        line = raw.strip()
        if not line or line.startswith(("#", "-r", "-c", "--")):
            continue
        if re.match(r"^(git\+|https?://)", line) or " @ " in line:
            findings.append(Finding("DEP003", "Dependency installed from a URL/VCS", "medium", path, lineno,
                                    "Direct URL dependencies bypass the index and are not hash-pinned", line,
                                    "Publish to a private index or pin to an immutable commit with --hash.", "dependency"))
            continue
        m = REQ_LINE.match(line)
        if not m:
            continue
        name, spec = m["name"], m["spec"].strip()
        pinned = re.fullmatch(r"==\s*([\w.\-+!]+)", spec)
        if not pinned:
            findings.append(Finding("DEP001", "Unpinned Python dependency", "low", path, lineno,
                                    f"'{name}' is not pinned ({spec or 'any version'}), so builds are not reproducible", line,
                                    "Pin exact versions (pip-compile / uv pip compile) and update them deliberately.", "dependency"))
            lower = re.search(r">=\s*([\w.\-+!]+)", spec)
            if lower:
                for adv in _affected("pypi", name, lower[1]):
                    findings.append(_adv_finding(path, lineno, line, name, lower[1], adv, maybe=True))
            continue
        version = pinned[1]
        pkgs.append(("PyPI", name, version, lineno))
        for adv in _affected("pypi", name, version):
            findings.append(_adv_finding(path, lineno, line, name, version, adv))
    return findings, pkgs


def scan_package_json(path: str, text: str) -> tuple[list[Finding], list[tuple[str, str, str, int]]]:
    findings, pkgs = [], []
    try:
        data = json.loads(text)
    except json.JSONDecodeError as exc:
        return [Finding("DEP000", "Invalid package.json", "info", path, exc.lineno, str(exc), category="dependency")], []
    lines = text.splitlines()

    def line_of(needle: str) -> int:
        return next((i for i, ln in enumerate(lines, 1) if needle in ln), 0)

    for section in ("dependencies", "devDependencies", "optionalDependencies"):
        for name, spec in (data.get(section) or {}).items():
            ln = line_of(f'"{name}"')
            snippet = f'"{name}": "{spec}"'
            if spec in ("*", "latest", "") or spec.startswith((">", "x")):
                findings.append(Finding("DEP002", "Unbounded npm version", "medium", path, ln,
                                        f"'{name}' accepts any future version ({spec or 'empty'}), a supply-chain risk", snippet,
                                        "Use an exact or caret range and commit package-lock.json.", "dependency"))
                continue
            if re.match(r"^(git|github:|https?:|file:)", spec) or "/" in spec:
                findings.append(Finding("DEP003", "Dependency installed from a URL/VCS", "medium", path, ln,
                                        f"'{name}' comes from {spec}", snippet, "Prefer registry releases or pin to a commit SHA.", "dependency"))
                continue
            base = re.sub(r"^[\^~=v]+", "", spec).split(" ")[0]
            pkgs.append(("npm", name, base, ln))
            for adv in _affected("npm", name, base):
                findings.append(_adv_finding(path, ln, snippet, name, base, adv, maybe=spec[0] in "^~"))
    for hook in ("preinstall", "install", "postinstall"):
        cmd = (data.get("scripts") or {}).get(hook, "")
        if re.search(r"(curl|wget)[^|]*\|\s*(ba)?sh|node\s+-e|base64\s+-d", cmd):
            findings.append(Finding("DEP004", "Suspicious install script", "high", path, line_of(f'"{hook}"'),
                                    f"'{hook}' downloads or decodes and executes code at install time", f'"{hook}": "{cmd}"',
                                    "Remove network-executing lifecycle scripts; vendor what you need.", "dependency"))
    return findings, pkgs


def _adv_finding(path, lineno, line, name, version, adv, maybe=False) -> Finding:
    word = "may resolve to" if maybe else "uses"
    return Finding(f"VULN-{adv['id']}", f"{name} {version}: {adv['id']}", adv["severity"] if not maybe else "medium", path, lineno,
                   f"{name} {word} a version affected by {adv['id']}: {adv['summary']}", line,
                   f"Upgrade {name} to >= {adv['fixed']}.", "dependency")


def osv_lookup(pkgs: list[tuple[str, str, str, int]], timeout: float = 20.0) -> dict[tuple[str, str], list[str]]:
    """Batch-query osv.dev. Returns {(name, version): [vuln ids]}. Raises on network errors (caller decides)."""
    if not pkgs:
        return {}
    queries = [{"package": {"ecosystem": eco, "name": name}, "version": ver} for eco, name, ver, _ in pkgs]
    req = urllib.request.Request("https://api.osv.dev/v1/querybatch", data=json.dumps({"queries": queries}).encode(),
                                 headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        results = json.loads(r.read())["results"]
    return {(p[1], p[2]): [v["id"] for v in res.get("vulns", [])] for p, res in zip(pkgs, results, strict=False)}
