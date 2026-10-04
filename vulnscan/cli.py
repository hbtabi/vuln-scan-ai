"""``vuln-scan-ai scan PATH`` / ``vuln-scan-ai demo``."""

from __future__ import annotations

import argparse
import os
import sys
import tempfile
from pathlib import Path

from . import llm
from .demo import write_demo_project
from .models import RANK, SEVERITIES
from .report import to_json, to_markdown, to_sarif, to_text
from .scanner import scan_path


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="vuln-scan-ai", description="Defensive auditor for secrets, vulnerable deps and risky configs")
    ap.add_argument("--no-color", action="store_true")
    sub = ap.add_subparsers(dest="cmd", required=True)
    s = sub.add_parser("scan", help="scan a project directory")
    s.add_argument("path", nargs="?", default=".")
    s.add_argument("--format", choices=["text", "json", "sarif", "markdown"], default="text")
    s.add_argument("-o", "--output", help="write the report to a file instead of stdout")
    s.add_argument("--min-severity", choices=SEVERITIES, default="info")
    s.add_argument("--fail-on", choices=SEVERITIES[:4], help="exit 1 if a finding at/above this severity exists")
    s.add_argument("--osv", action="store_true", help="also query osv.dev for pinned dependencies (network)")
    s.add_argument("--explain", action="store_true", help="add LLM remediation advice for high/critical findings (needs OPENAI_API_KEY)")
    s.add_argument("--explain-limit", type=int, default=5)
    d = sub.add_parser("demo", help="create a deliberately insecure sample project and scan it")
    d.add_argument("--keep", metavar="DIR", help="write the sample project here instead of a temp dir")
    for p in (s, d):  # accept --no-color after the subcommand too
        p.add_argument("--no-color", action="store_true", default=argparse.SUPPRESS)
    args = ap.parse_args(argv)
    color = (sys.stdout.isatty() or bool(os.environ.get("FORCE_COLOR"))) and not args.no_color and not os.environ.get("NO_COLOR")

    if args.cmd == "demo":
        if args.keep:
            root = write_demo_project(args.keep)
            print(to_text(scan_path(root), color))
            return 0
        with tempfile.TemporaryDirectory() as tmp:
            res = scan_path(write_demo_project(Path(tmp) / "insecure-demo"))
            print(to_text(res, color))
        return 0

    if not Path(args.path).is_dir():
        print(f"not a directory: {args.path}", file=sys.stderr)
        return 2
    res = scan_path(args.path, use_osv=args.osv, min_severity=args.min_severity)
    explanations = {}
    if args.explain:
        if not llm.available():
            res.notes.append("--explain skipped: set OPENAI_API_KEY (and optionally OPENAI_BASE_URL) to enable")
        else:
            todo = [i for i, f in enumerate(res.findings) if RANK[f.severity] >= RANK["high"]][: args.explain_limit]
            explanations = {i: llm.explain(res.findings[i]) or "" for i in todo}
    if args.format == "text":
        out = to_text(res, color and not args.output, explanations)
    else:
        out = {"json": to_json, "sarif": to_sarif, "markdown": to_markdown}[args.format](res)
    if args.output:
        Path(args.output).write_text(out + "\n")
        print(f"wrote {args.output} ({len(res.findings)} findings)")
    else:
        print(out)
    if args.fail_on and any(RANK[f.severity] >= RANK[args.fail_on] for f in res.findings):
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
