"""Dockerfile and docker-compose hardening checks."""

from __future__ import annotations

import re

import yaml

from ..models import Finding


def _logical_lines(text: str) -> list[tuple[int, str]]:
    """Join backslash-continued lines, keeping the starting line number."""
    out, buf, start = [], "", 0
    for i, line in enumerate(text.splitlines(), 1):
        if not buf:
            start = i
        stripped = line.rstrip()
        if stripped.endswith("\\"):
            buf += stripped[:-1] + " "
            continue
        buf += stripped
        if buf.strip() and not buf.strip().startswith("#"):
            out.append((start, buf.strip()))
        buf = ""
    return out


def scan_dockerfile(path: str, text: str) -> list[Finding]:
    f: list[Finding] = []
    lines = _logical_lines(text)
    users = [(n, ln) for n, ln in lines if re.match(r"(?i)^USER\s+", ln)]
    for n, ln in lines:
        up = ln.upper()
        if up.startswith("FROM "):
            image = ln.split()[1]
            if image.lower() != "scratch" and "@sha256:" not in image and (":" not in image.split("/")[-1] or image.endswith(":latest")):
                f.append(Finding("DOCK001", "Base image not pinned", "medium", path, n, f"'{image}' floats to whatever 'latest' is today", ln,
                                 "Pin a specific tag, ideally with a digest (image:tag@sha256:...).", "docker"))
        elif re.match(r"(?i)^(ENV|ARG)\s+", ln) and re.search(r"(?i)(PASSWORD|SECRET|TOKEN|API_?KEY|PRIVATE_KEY)\w*\s*[= ]\s*\S+", ln):
            f.append(Finding("DOCK002", "Secret baked into image", "high", path, n, "ENV/ARG values persist in image layers and `docker history`",
                             re.sub(r"(?i)((?:PASSWORD|SECRET|TOKEN|API_?KEY|PRIVATE_KEY)\w*\s*[= ]\s*)\S+", r"\1****", ln), "Use BuildKit secrets (--mount=type=secret) or runtime env vars.", "docker"))
        elif re.match(r"(?i)^ADD\s+https?://", ln):
            f.append(Finding("DOCK003", "ADD from remote URL", "medium", path, n, "Remote ADD has no integrity check", ln,
                             "Use curl with a checksum verification, or COPY a vendored file.", "docker"))
        elif re.match(r"(?i)^RUN\s+", ln):
            if re.search(r"(curl|wget)[^|;&]*\|\s*(sudo\s+)?(ba)?sh", ln):
                f.append(Finding("DOCK004", "Pipe-to-shell install", "high", path, n, "Executes remote code without verification", ln,
                                 "Download, verify a checksum/signature, then execute.", "docker"))
            if "apt-get install" in ln and "--no-install-recommends" not in ln:
                f.append(Finding("DOCK005", "apt-get without --no-install-recommends", "low", path, n, "Pulls in extra packages (bigger attack surface)",
                                 ln[:120], "Add --no-install-recommends and clean /var/lib/apt/lists.", "docker"))
            if re.search(r"chmod\s+(-R\s+)?777", ln):
                f.append(Finding("DOCK006", "World-writable permissions", "medium", path, n, "chmod 777 inside the image", ln,
                                 "Grant the minimum permissions to a dedicated user.", "docker"))
        elif re.match(r"(?i)^EXPOSE\s+.*\b22\b", ln):
            f.append(Finding("DOCK007", "SSH port exposed", "medium", path, n, "Containers shouldn't run sshd", ln,
                             "Use `docker exec` / orchestration tooling instead.", "docker"))
    if lines and (not users or re.match(r"(?i)^USER\s+(root|0)\b", users[-1][1])):
        n = users[-1][0] if users else lines[-1][0]
        f.append(Finding("DOCK008", "Container runs as root", "medium", path, n, "No non-root USER is set for the final stage",
                         users[-1][1] if users else "", "Add `RUN useradd -r app` and `USER app` before CMD.", "docker"))
    return f


def scan_compose(path: str, text: str) -> list[Finding]:
    f: list[Finding] = []
    try:
        data = yaml.safe_load(text) or {}
    except yaml.YAMLError:
        return f
    lines = text.splitlines()

    def ln(needle: str) -> int:
        return next((i for i, x in enumerate(lines, 1) if needle in x), 0)

    for name, svc in (data.get("services") or {}).items():
        if not isinstance(svc, dict):
            continue
        if svc.get("privileged"):
            f.append(Finding("COMP001", "Privileged container", "high", path, ln("privileged"), f"service '{name}' runs privileged (full host access)",
                             "privileged: true", "Drop privileged; grant specific cap_add entries if really needed.", "docker"))
        if svc.get("network_mode") == "host":
            f.append(Finding("COMP002", "Host networking", "medium", path, ln("network_mode"), f"service '{name}' shares the host network stack",
                             "network_mode: host", "Use bridge networking and publish only required ports.", "docker"))
        for vol in svc.get("volumes") or []:
            v = vol if isinstance(vol, str) else str(vol.get("source", ""))
            if "docker.sock" in v or re.match(r"^/(:|$)", v):
                f.append(Finding("COMP003", "Sensitive host mount", "high", path, ln("docker.sock") or ln(v), f"service '{name}' mounts {v.split(':')[0]}",
                                 v, "Never mount the Docker socket or host root into an app container.", "docker"))
        for port in svc.get("ports") or []:
            p = str(port)
            if re.search(r"(^|:)(5432|3306|6379|27017|9200)(:|$|/)", p) and not p.startswith("127.0.0.1"):
                f.append(Finding("COMP004", "Database port published on all interfaces", "medium", path, ln(p), f"service '{name}' publishes {p}",
                                 p, "Bind to 127.0.0.1 or keep it on the internal network only.", "docker"))
    return f
