import json

from vulnscan.cli import main
from vulnscan.demo import write_demo_project
from vulnscan.scanner import scan_path


def test_demo_project_full_scan(tmp_path):
    res = scan_path(write_demo_project(tmp_path / "demo"))
    rules = {f.rule_id for f in res.findings}
    for expected in ("SEC001", "SEC003", "SEC006", "SEC010", "CONF001", "DOCK002", "COMP001", "CI003", "CODE003", "VULN-CVE-2020-14343"):
        assert expected in rules, expected
    assert res.worst() == "critical"
    assert res.findings == sorted(res.findings, key=lambda f: (-{"critical": 5, "high": 4, "medium": 3, "low": 2, "info": 1}[f.severity], f.file, f.line))


def test_no_raw_secret_in_any_output(tmp_path, capsys):
    root = write_demo_project(tmp_path / "demo")
    secret_line = (root / "app.py").read_text().splitlines()[7]
    secret = secret_line.split('"')[1]
    for fmt in ("text", "json", "sarif", "markdown"):
        main(["--no-color", "scan", str(root), "--format", fmt])
        assert secret not in capsys.readouterr().out, fmt


def test_gitignored_env_is_not_conf001(tmp_path):
    (tmp_path / ".env").write_text("DEBUG=true\n")
    (tmp_path / ".gitignore").write_text(".env\n")
    (tmp_path / ".env.example").write_text("DEBUG=\n")
    assert scan_path(tmp_path).findings == []


def test_skips_node_modules_and_ignore_file(tmp_path):
    (tmp_path / "node_modules" / "x").mkdir(parents=True)
    (tmp_path / "node_modules" / "x" / "a.js").write_text("eval(x)\n")
    (tmp_path / "legacy").mkdir()
    (tmp_path / "legacy" / "old.py").write_text("eval(x)\n")
    (tmp_path / ".vulnscanignore").write_text("legacy/*\n")
    assert scan_path(tmp_path).findings == []


def test_sarif_is_valid_shape(tmp_path, capsys):
    root = write_demo_project(tmp_path / "demo")
    assert main(["scan", str(root), "--format", "sarif"]) == 0
    sarif = json.loads(capsys.readouterr().out)
    run = sarif["runs"][0]
    assert sarif["version"] == "2.1.0" and run["results"] and run["tool"]["driver"]["rules"]
    assert all(r["locations"][0]["physicalLocation"]["region"]["startLine"] >= 1 for r in run["results"])


def test_fail_on_and_min_severity(tmp_path, capsys):
    root = write_demo_project(tmp_path / "demo")
    assert main(["--no-color", "scan", str(root), "--fail-on", "critical"]) == 1
    capsys.readouterr()
    main(["scan", str(root), "--format", "json", "--min-severity", "high"])
    data = json.loads(capsys.readouterr().out)
    assert {f["severity"] for f in data["findings"]} <= {"critical", "high"}


def test_explain_without_key(tmp_path, monkeypatch, capsys):
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    main(["--no-color", "scan", str(write_demo_project(tmp_path / "d")), "--explain"])
    assert "--explain skipped" in capsys.readouterr().out


def test_bad_path():
    assert main(["scan", "/definitely/not/here"]) == 2
