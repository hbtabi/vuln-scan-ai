import string

from vulnscan.checks.secrets import entropy, redact, scan_text

UP = string.ascii_uppercase + string.digits


def ids(findings):
    return [f.rule_id for f in findings]


def test_aws_and_github_tokens(fake):
    aws = fake("AK" + "IA", 16, UP)
    gh = fake("gh" + "p_", 36)
    found = scan_text("app.py", f'KEY = "{aws}"\ntoken = "{gh}"\n')
    assert ids(found) == ["SEC001", "SEC003"]
    assert all(aws not in f.snippet and gh not in f.snippet for f in found), "secrets must be redacted"


def test_private_key_header():
    pem = "-----BEGIN " + "RSA PRIVATE KEY" + "-----"
    assert ids(scan_text("id_rsa.txt", pem + "\nabc\n")) == ["SEC004"]


def test_credentials_in_url(fake):
    pw = fake("", 14)
    f = scan_text("settings.py", f'DB = "postgres://app:{pw}@db.internal:5432/app"')
    assert ids(f) == ["SEC010"] and pw not in f[0].snippet


def test_generic_assignment_needs_entropy(fake):
    assert ids(scan_text("c.py", f'api_key = "{fake("", 24)}"')) == ["SEC100"]
    assert scan_text("c.py", 'password = "aaaaaaaaaaaa"') == []  # low entropy


def test_placeholders_and_env_lookups_ignored():
    text = 'password = "changeme123"\napi_key = os.environ["API_KEY"]\ntoken = "<your-token-here>"\nSECRET = "${SECRET}"\n'
    assert scan_text("c.py", text) == []


def test_env_file_values_flagged_but_example_is_not(fake):
    content = f"DB_PASSWORD={fake('', 16)}\nDEBUG=true\n"
    assert ids(scan_text(".env", content)) == ["SEC100"]
    assert scan_text(".env.example", content) == []


def test_inline_ignore(fake):
    assert scan_text("a.py", f'k = "{fake("AK" + "IA", 16, UP)}"  # vulnscan:ignore') == []


def test_redact_and_entropy():
    assert redact("abcd") == "****"
    r = redact("abcdefghijklmnop")
    assert r.startswith("abcd") and r.endswith("op") and "efgh" not in r
    assert entropy("aaaa") == 0 and entropy("abcd") == 2
