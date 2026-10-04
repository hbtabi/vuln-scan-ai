"""Write a deliberately insecure sample project for demos and tests.

Fake credentials are generated at runtime from a seeded RNG, so this repository never contains
anything that looks like a real secret (and GitHub push protection stays happy).
"""

from __future__ import annotations

import random
import string
from pathlib import Path


def _fake(rng: random.Random, alphabet: str, n: int) -> str:
    return "".join(rng.choice(alphabet) for _ in range(n))


def write_demo_project(dest: str | Path, seed: int = 1337) -> Path:
    rng = random.Random(seed)
    up, alnum = string.ascii_uppercase + string.digits, string.ascii_letters + string.digits
    aws_id = "AKIA" + _fake(rng, up, 16)
    gh_tok = "gh" + "p_" + _fake(rng, alnum, 36)
    db_pass = _fake(rng, alnum, 18)
    stripe = "sk_" + "live_" + _fake(rng, alnum, 24)
    dest = Path(dest)
    files = {
        "requirements.txt": "flask==2.2.2\nrequests==2.19.1\nPyYAML==5.3.1\npillow>=9.0\ngunicorn\n",
        "package.json": ('{\n  "name": "demo-frontend",\n  "version": "1.0.0",\n  "scripts": {\n'
                         '    "postinstall": "curl -s https://example.com/setup.sh | sh"\n  },\n'
                         '  "dependencies": {\n    "lodash": "4.17.15",\n    "axios": "^0.21.0",\n    "left-pad": "*"\n  }\n}\n'),
        "Dockerfile": ("FROM python:latest\nENV DB_PASSWORD=" + db_pass + "\n"
                       "RUN apt-get update && apt-get install -y curl build-essential\n"
                       "RUN curl -fsSL https://example.com/install.sh | bash\n"
                       "ADD https://example.com/tool.tar.gz /opt/\nCOPY . /app\nRUN chmod -R 777 /app\nEXPOSE 22 8000\n"
                       'CMD ["python", "/app/app.py"]\n'),
        "docker-compose.yml": ("services:\n  app:\n    build: .\n    privileged: true\n    volumes:\n      - /var/run/docker.sock:/var/run/docker.sock\n"
                               "  db:\n    image: postgres:16\n    ports:\n      - \"5432:5432\"\n"),
        ".env": f"DATABASE_URL=postgres://admin:{db_pass}@db:5432/app\nSTRIPE_SECRET_KEY={stripe}\nDEBUG=true\n",
        "app.py": ("import pickle\nimport subprocess\n\nimport requests\nimport yaml\nfrom flask import Flask, request\n\n"
                   f'AWS_ACCESS_KEY_ID = "{aws_id}"\nGITHUB_TOKEN = "{gh_tok}"\n\napp = Flask(__name__)\n\n\n'
                   '@app.route("/report")\ndef report():\n    cfg = yaml.load(request.data)\n'
                   '    out = subprocess.check_output("convert " + request.args["file"], shell=True)\n'
                   '    data = requests.get(cfg["url"], verify=False).content\n    return pickle.loads(data)\n\n\n'
                   'if __name__ == "__main__":\n    app.run(host="0.0.0.0", debug=True)\n'),
        "static/app.js": "const q = new URLSearchParams(location.search).get('q');\ndocument.getElementById('out').innerHTML = q;\n",
        ".github/workflows/triage.yml": ("name: triage\non: pull_request_target\npermissions: write-all\njobs:\n  greet:\n    runs-on: ubuntu-latest\n"
                                         "    steps:\n      - uses: actions/checkout@v4\n        with:\n          ref: ${{ github.event.pull_request.head.sha }}\n"
                                         "      - uses: some-org/label-action@main\n"
                                         '      - run: echo "Thanks for: ${{ github.event.pull_request.title }}"\n'),
        ".gitignore": "__pycache__/\nnode_modules/\n",
    }
    for rel, content in files.items():
        p = dest / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(content)
    return dest
