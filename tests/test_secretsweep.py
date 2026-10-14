"""All credentials here are synthetic, offline fixtures."""
import json
import math
from pathlib import Path
import subprocess
import sys
import pytest
from secretsweep.config import Config, load_config
from secretsweep.engine import entropy, entropy_candidate, redact, scan_stdin, scan_text
from secretsweep.license import make_key, valid_key
from secretsweep.rules import FREE_RULES, PAID_RULES
from secretsweep.cli import main, scan_path

MIX = "aB3dE6gH9jK2mN5pQ8sT1vW4yZ7cF0iL"
POSITIVE = {
    "aws-access-key-id": "AKIA" + "ABCDEFGHIJKLMNOP",
    "aws-secret-key": 'aws_secret_access_key="' + MIX + "aB3dE6gH" + '"',
    "generic-api-key": 'api_key="' + MIX + '"',
    "generic-secret": 'secret="' + MIX + '"',
    "generic-token": 'token="' + MIX + '"',
    "generic-password": 'password="' + MIX + '"',
    "private-key": "-----BEGIN RSA PRIVATE KEY-----",
    "slack-token": "xoxb-1234567890-abcdefghijk",
    "jwt": "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.c3ludGhldGljX3NpZ25hdHVyZQ",
    "github-token": "ghp_" + "A" * 36,
    "github-fine-grained-token": "github_pat_" + "A" * 60,
    "gitlab-token": "glpat-" + "A" * 20,
    "google-api-key": "AIza" + "A" * 35,
    "sendgrid-api-key": "SG." + "A" * 22 + "." + "B" * 43,
    "npm-token": "npm_" + "A" * 36,
    "gcp-service-account": '"type": "service_account"',
    "stripe-secret-key": "sk_live_" + "A" * 24,
    "stripe-publishable-key": "pk_live_" + "A" * 24,
}
NEGATIVE = {
    "aws-access-key-id": "AKIA123",
    "aws-secret-key": 'aws_secret_access_key="short"',
    "generic-api-key": 'api_key="example"',
    "generic-secret": 'secret="example"',
    "generic-token": 'token="example"',
    "generic-password": 'password="example"',
    "private-key": "-----BEGIN PUBLIC KEY-----",
    "slack-token": "xoxb-short",
    "jwt": "eyJshort.short.short",
    "github-token": "ghp_short",
    "github-fine-grained-token": "github_pat_short",
    "gitlab-token": "glpat-short",
    "google-api-key": "AIzaShort",
    "sendgrid-api-key": "SG.short.short",
    "npm-token": "npm_short",
    "gcp-service-account": '"type": "user"',
    "stripe-secret-key": "sk_test_" + "A" * 24,
    "stripe-publishable-key": "pk_test_" + "A" * 24,
}
ALL = FREE_RULES + PAID_RULES

@pytest.mark.parametrize("rule", ALL, ids=lambda r: r.name)
def test_rule_true_positive(rule):
    found = scan_text(POSITIVE[rule.name], config=Config(rules=(rule,)))
    assert len(found) == 1
    assert found[0].pattern == rule.name
    assert found[0].severity == rule.severity
    assert "REDACTED" in found[0].snippet

@pytest.mark.parametrize("rule", ALL, ids=lambda r: r.name)
def test_rule_true_negative(rule):
    assert not scan_text(NEGATIVE[rule.name], config=Config(rules=(rule,)))

@pytest.mark.parametrize("rule", ALL, ids=lambda r: r.name)
def test_pattern_allowlist(rule):
    assert not scan_text(POSITIVE[rule.name], config=Config(rules=(rule,), allow_patterns=[rule.name]))

@pytest.mark.parametrize("rule", ALL, ids=lambda r: r.name)
def test_exact_value_allowlist(rule):
    match = rule.regex.search(POSITIVE[rule.name])
    value = match.group("secret" if "secret" in rule.regex.groupindex else 0)
    assert not scan_text(POSITIVE[rule.name], config=Config(rules=(rule,), allow_strings=[value]))

@pytest.mark.parametrize("prefix", ["ghp_", "gho_", "ghu_", "ghs_", "ghr_"])
def test_github_variants(prefix):
    assert scan_text(prefix + "A" * 36)[0].pattern == "github-token"

@pytest.mark.parametrize("prefix", ["xoxb-", "xoxa-", "xoxp-", "xoxr-", "xoxs-"])
def test_slack_variants(prefix):
    assert scan_text(prefix + "a" * 20)[0].pattern == "slack-token"

@pytest.mark.parametrize("kind", ["", "RSA ", "EC ", "OPENSSH ", "ENCRYPTED ", "DSA "])
def test_pem_variants(kind):
    assert scan_text("-----BEGIN " + kind + "PRIVATE KEY-----")[0].snippet == "[REDACTED]"

@pytest.mark.parametrize("name", ["api_key", "apikey", "API_KEY", "secret", "token", "password", "passwd", "pwd"])
def test_assignment_variants(name):
    assert any(f.severity == "HIGH" for f in scan_text(f'"{name}": "{MIX}"'))

@pytest.mark.parametrize("value,expected", [("", 0), ("a", 0), ("aaaa", 0), ("ab", 1), ("abcd", 2), ("aabbccdd", 2), ("😀😁", 1)])
def test_entropy(value, expected):
    assert entropy(value) == expected

@pytest.mark.parametrize("value", ["a" * 60, "0123456789abcdef" * 4, "550e8400-e29b-41d4-a716-446655440000", "data:image/png;base64," + MIX, "https://example.com/" + MIX, "some ordinary English text with spaces", "ABCDEFGHIJKLMNOPQRSTUVWXYZ", "abcdefghijklmnopqrstuvwx", "123456789012345678901234", "abc", MIX * 10])
def test_entropy_exclusions(value):
    assert not entropy_candidate(value, 4.5)

@pytest.mark.parametrize("quote", ['"', "'"])
def test_generic_entropy(quote):
    result = scan_text("value=" + quote + MIX + quote)
    assert len(result) == 1 and result[0].pattern == "high-entropy-string"
    assert result[0].severity == "MEDIUM"
    assert not scan_text(quote + MIX + quote, config=Config(entropy_threshold=6))

@pytest.mark.parametrize("value", ["", "x", "abcd", "12345678901", MIX, "-----BEGIN PRIVATE KEY-----"])
def test_redaction(value):
    redacted = redact(value)
    assert "REDACTED" in redacted
    if value:
        assert value not in redacted

@pytest.mark.parametrize("pattern", ["*.txt", "fixtures/*", "fixtures/safe.txt"])
def test_allow_files(pattern):
    assert not scan_text(POSITIVE["github-token"], "fixtures/safe.txt", Config(allow_files=[pattern]))


def test_multiple_secrets_never_leak():
    first, second = POSITIVE["github-token"], POSITIVE["slack-token"]
    result = scan_text(first + " " + second)
    assert len(result) == 2
    output = json.dumps([f.to_dict() for f in result])
    assert first not in output and second not in output


def test_line_numbers_and_determinism():
    source = "\n\n" + POSITIVE["github-token"]
    assert scan_text(source) == scan_text(source)
    assert scan_text(source)[0].line == 3


def test_known_rule_no_entropy_duplicate():
    assert len(scan_text('token="' + MIX + '"')) == 1


def test_plain_stdin():
    assert scan_stdin(POSITIVE["github-token"])[0].file == "<stdin>"


def test_unified_diff():
    token = POSITIVE["github-token"]
    diff = f"diff --git a/a.py b/a.py\n--- a/a.py\n+++ b/a.py\n@@ -4,2 +4,2 @@\n-{token}\n unchanged\n+{token}\n"
    result = scan_stdin(diff)
    assert len(result) == 1
    assert result[0].file == "a.py" and result[0].line == 5


def test_diff_content_looks_like_header():
    diff = "--- a/f\n+++ b/f\n@@ -0,0 +1 @@\n+++ " + POSITIVE["github-token"]
    assert scan_stdin(diff)[0].file == "f"


def test_diff_multiple_files_and_hunks():
    token = POSITIVE["github-token"]
    diff = f"--- a/a\n+++ b/a\n@@ -0,0 +1 @@\n+{token}\n@@ -3,0 +4 @@\n+{token}\n--- a/b\n+++ b/b\n@@ -0,0 +1 @@\n+{token}\n"
    assert [(f.file, f.line) for f in scan_stdin(diff)] == [("a", 1), ("a", 4), ("b", 1)]

@pytest.mark.parametrize("body", ["@@ bad", "@@ -1 +1 @@\n+okay", "@@ -1 +1 @@\ninvalid"])
def test_malformed_diff(body):
    with pytest.raises(ValueError):
        scan_stdin("--- a/f\n+++ b/f\n" + body)


def write_config(tmp_path, value):
    path = tmp_path / "config.json"
    path.write_text(json.dumps(value), encoding="utf-8")
    return path

@pytest.mark.parametrize("value", [[], None, {"unknown": 1}, {"entropy_threshold": 0}, {"entropy_threshold": 9}, {"entropy_threshold": True}, {"entropy_threshold": float("nan")}, {"allowlist": []}, {"allowlist": {"files": "x"}}, {"allowlist": {"strings": [1]}}, {"allowlist": {"bad": []}}, {"license_key": "invalid"}, {"custom_rules": [{}]}, {"custom_rules": "bad"}])
def test_invalid_config(tmp_path, value):
    with pytest.raises(ValueError, match="Invalid or unreadable"):
        load_config(write_config(tmp_path, value))


def test_licensed_config(tmp_path):
    config = load_config(write_config(tmp_path, {"license_key": make_key("TESTUSER"), "custom_rules": [{"name": "custom", "regex": r"DEMO_[0-9]+"}]}))
    assert len(config.rules) == 19
    assert scan_text("DEMO_12345678901234", config=config)[0].pattern == "custom"
    assert not scan_text(POSITIVE["stripe-secret-key"])
    assert scan_text(POSITIVE["stripe-secret-key"], config=config)

@pytest.mark.parametrize("custom", [{"name": "bad", "regex": "["}, {"name": "bad", "regex": ".*"}, {"name": "github-token", "regex": "foo"}, {"name": "bad", "regex": "foo", "severity": "CRITICAL"}, {"name": "bad name", "regex": "foo"}, {"name": "missing"}])
def test_invalid_custom_rule(tmp_path, custom):
    with pytest.raises(ValueError):
        load_config(write_config(tmp_path, {"license_key": make_key("TESTUSER"), "custom_rules": [custom]}))

@pytest.mark.parametrize("value", [None, "", "SS1-TEST-000000000000", "ss1-test-123456789012", 123])
def test_invalid_license(value):
    assert not valid_key(value)


def test_license_roundtrip():
    assert valid_key(make_key("TESTUSER"))
    with pytest.raises(ValueError):
        make_key("bad")

@pytest.mark.parametrize("source,code", [("hello", 0), ('value="' + MIX + '"', 0), (POSITIVE["github-token"], 1)])
@pytest.mark.parametrize("output", ["text", "json"])
def test_cli_output(tmp_path, capsys, source, code, output):
    path = tmp_path / "source.txt"
    path.write_text(source)
    assert main(["scan", str(path), "--format", output]) == code
    captured = capsys.readouterr()
    assert not captured.err
    if output == "json":
        data = json.loads(captured.out)
        assert set(data) == {"schema_version", "findings", "summary"}
        assert data["schema_version"] == 1
        assert set(data["summary"]) == {"findings", "high", "scanned", "skipped"}
        for f in data["findings"]:
            assert set(f) == {"file", "line", "pattern", "severity", "confidence", "snippet"}
            assert isinstance(f["line"], int)
    if code == 1:
        assert source not in captured.out


def test_cli_missing(tmp_path, capsys):
    assert main(["scan", str(tmp_path / "absent")]) == 2
    assert "scan failed" in capsys.readouterr().err

@pytest.mark.parametrize("threshold", ["0", "9", "nan", "inf", "-1"])
def test_cli_invalid_threshold(tmp_path, threshold):
    assert main(["scan", str(tmp_path), "--entropy-threshold", threshold]) == 2


def test_tree_binary_and_ignored(tmp_path):
    (tmp_path / "a.txt").write_text(POSITIVE["github-token"])
    (tmp_path / "binary").write_bytes(b"\x00" + POSITIVE["github-token"].encode())
    (tmp_path / ".git").mkdir()
    (tmp_path / ".git" / "hidden").write_text(POSITIVE["github-token"])
    (tmp_path / "sub").mkdir()
    (tmp_path / "sub" / "b.txt").write_text("okay")
    found, scanned, skipped = scan_path(tmp_path, Config())
    assert len(found) == 1 and scanned == 2 and skipped == 2


def test_config_autodiscovery(tmp_path, capsys):
    (tmp_path / "a").write_text(POSITIVE["github-token"])
    (tmp_path / ".secretsweeprc.json").write_text(json.dumps({"allowlist": {"patterns": ["github-token"]}}))
    assert main(["scan", str(tmp_path)]) == 0


def test_stdin_subprocess():
    proc = subprocess.run([sys.executable, "-m", "secretsweep", "scan", "-", "--format", "json"], input=POSITIVE["github-token"], text=True, capture_output=True)
    assert proc.returncode == 1
    assert json.loads(proc.stdout)["summary"]["high"] == 1
    assert POSITIVE["github-token"] not in proc.stdout


def test_unreadable_config(tmp_path):
    with pytest.raises(ValueError):
        load_config(tmp_path / "missing")


def test_custom_named_capture(tmp_path):
    config = load_config(write_config(tmp_path, {"license_key": make_key("TESTUSER"), "custom_rules": [{"name": "named", "regex": r"NAME=(?P<secret>[A-Z0-9]+)"}]}))
    assert scan_text("NAME=ABCDEF123456789", config=config)[0].snippet.startswith("ABC")
