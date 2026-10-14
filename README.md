# SecretSweep

A deterministic, offline Python CLI for spotting hardcoded secrets in files, directories, and pasted text or unified diffs. Python 3.10+, **zero runtime dependencies**. No telemetry, network requests, credential validation, or automatic file changes.

## Install and use

```sh
python -m pip install .
secretsweep scan .
secretsweep scan src/settings.py --format json
secretsweep scan . --entropy-threshold 4.7
# Scan only added lines in a staged unified diff:
git diff --cached --no-ext-diff --no-color --unified=0 | secretsweep scan -
# Or paste plain text, then end stdin with your shell's EOF sequence:
secretsweep scan -
```

`python -m secretsweep` also works from the checkout. Exit **0** means no HIGH findings, **1** means at least one HIGH finding, and **2** means an input/configuration/scan error. MEDIUM and LOW findings are reported but do not fail the gate. Handle exit 2 as failure in hooks/CI too. A pipe scans whatever its producer supplies: independently check that `git diff` succeeded (for example use `set -o pipefail` in Bash).

Text output includes file, line, severity, rule name and redacted value. JSON has this stable versioned shape:

```json
{
  "schema_version": 1,
  "findings": [{"file": "settings.py", "line": 3, "pattern": "generic-token", "severity": "HIGH", "confidence": "HIGH", "snippet": "abc…[REDACTED]…xyz"}],
  "summary": {"findings": 1, "high": 1, "scanned": 1, "skipped": 0}
}
```

Only the first/last three characters of a value are shown; values shorter than 12 characters and private-key markers are completely redacted. Surrounding source is never printed. Confidence is categorical, not a calibrated probability. Paths are relative to the directory scanned (or the parent for a single file). Stdin plain text uses `<stdin>`; diffs use new-file paths and new-file line numbers, reporting added lines only. Stdin counts as one scanned input.

## Free fingerprints (15)

| Rule | Detection | Severity |
| --- | --- | --- |
| aws-access-key-id | AKIA/ASIA plus 16 uppercase letters/digits | HIGH |
| aws-secret-key | aws_secret_access_key / aws_secret_key assignments, 40+ characters and entropy >= 3.5 | HIGH |
| generic-api-key | api_key / apikey assignments, 16+ characters and entropy >= 3.5 | HIGH |
| generic-secret | secret assignments, 16+ characters and entropy >= 3.5 | HIGH |
| generic-token | token assignments, 16+ characters and entropy >= 3.5 | HIGH |
| generic-password | password / passwd / pwd assignments, 12+ characters and entropy >= 3.0 | HIGH |
| private-key | PEM private-key begin markers, including RSA, EC, OPENSSH and encrypted keys | HIGH |
| slack-token | xoxb / xoxa / xoxp / xoxr / xoxs token prefixes | HIGH |
| jwt | Three base64url-shaped segments beginning eyJ | MEDIUM |
| github-token | ghp / gho / ghu / ghs / ghr tokens | HIGH |
| github-fine-grained-token | github_pat tokens | HIGH |
| gitlab-token | glpat tokens | HIGH |
| google-api-key | AIza tokens | HIGH |
| sendgrid-api-key | SG tokens | HIGH |
| npm-token | npm_ tokens | HIGH |

JWTs are MEDIUM because public examples and non-secret JWTs are common. Patterns identify shapes, not active credentials. Private-key detection flags the header even if the block is incomplete, avoiding the need to retain or print the key body.

### Generic entropy detection

`high-entropy-string` (MEDIUM) scores single-line quoted strings using Shannon entropy in bits/character. The default threshold is **4.5**, with length **24–256**, and lowercase, uppercase and digits all required. Pure hexadecimal/hyphen strings (including normal hashes and UUIDs), URLs, data URIs and whitespace-containing values are excluded. These exclusions apply only to the entropy heuristic, not explicit fingerprints. Known-rule matches suppress overlapping entropy duplicates. `--entropy-threshold` changes the generic heuristic only; assignment-rule entropy floors stay fixed.

This favors fewer alerts on normal code, sacrificing recall for short secrets, hex secrets, long blobs and passphrases. Regex source, mixed-case identifiers and ordinary base64 can still trigger. A hash in a named secret assignment can still trigger that assignment rule. Lowering the threshold increases noise and does not disable the other exclusions.

## Configuration and allowlists

By default, SecretSweep reads `.secretsweeprc.json` from the scan directory, the parent of a scanned file, or the working directory for stdin. It does not merge or discover ancestor configs. Override with `--config path/to/config.json`.

```json
{
  "entropy_threshold": 4.5,
  "allowlist": {
    "strings": ["an-exact-known-safe-example-value"],
    "files": ["tests/fixtures/*", "docs/examples/*"],
    "patterns": ["jwt"]
  }
}
```

Strings match the **entire extracted secret value**, not a substring or an entire source line. Pattern entries are exact rule names. File entries use case-sensitive Python `fnmatch` globs on forward-slash relative paths; `*` can span directories. A matching directory is pruned. Broad allowlists can conceal real leaks. Local configuration is gitignored and the default config filename is skipped during file scanning; an explicitly named config with a different filename is scanned normally if inside the target. Avoid storing real secrets in allowlists.

Traversal is sorted, skips symbolic links, `.git`, `.venv`, `venv`, `__pycache__`, `.pytest_cache`, `node_modules`, and files containing NUL bytes. Skipped counts include pruned directories as one item, not their descendants. Other bytes are decoded as UTF-8 with replacement. Read/permission errors fail the scan with exit 2, without printing sensitive exception contents.

## Extended rules and local license gate

A checksum-valid local key enables these additional rules and custom regexes:

| Rule | Detection | Severity |
| --- | --- | --- |
| gcp-service-account | JSON `"type": "service_account"` marker | MEDIUM |
| stripe-secret-key | sk_live_ plus 24+ alphanumeric characters | HIGH |
| stripe-publishable-key | pk_live_ plus 24+ alphanumeric characters | LOW |

A GCP service-account marker identifies a potentially sensitive document; it does not prove a private key is present. PEM keys in GCP JSON are also detected by the free private-key rule. Stripe publishable keys are intentionally public and therefore LOW. Free entropy detection may independently flag values matching paid formats; the gate controls explicit rules, not exclusive detection.

This is **MVP feature gating, not payment integration or tamper-resistant licensing**. Anyone with this open-source code can generate a key. The format is `SS1-CUSTOMER-CHECKSUM`; the checksum is the first 12 uppercase hexadecimal characters of SHA-256 over `SecretSweep-v1:CUSTOMER`. Customer IDs contain 4–32 uppercase letters/digits. Generate a development key locally:

```sh
python -c "from secretsweep.license import make_key; print(make_key('LOCALDEMO'))"
```

Put the generated string in the config's `license_key` field. Invalid keys or unlicensed custom rules fail closed with exit 2. Example configuration (replace the placeholder):

```json
{
  "license_key": "REPLACE-WITH-GENERATED-KEY",
  "custom_rules": [
    {"name": "internal-key", "regex": "INTERNAL_[A-Za-z0-9]{32}", "severity": "HIGH"}
  ]
}
```

Custom rules use Python regex syntax and run per line. A named capture `(?P<secret>...)` specifies the sensitive value; otherwise the full match is redacted. Names must be unique lowercase letters/digits/hyphens, starting with a letter, at most 64 characters. Severity is HIGH (default), MEDIUM or LOW. Empty-string matches are rejected. **Only load trusted config**: pathological regexes can consume excessive CPU; stdlib `re` has no timeout.

## Development and CI

```sh
python -m pip install -e ".[test]"
python -m pytest --cov=secretsweep --cov-report=term-missing --cov-fail-under=90
```

Tests use synthetic credentials only. GitHub Actions tests Python 3.10 and 3.12 on Ubuntu and Windows. Runtime installation needs no third-party libraries; setuptools is a build dependency, and pytest/pytest-cov are development dependencies.

## Limitations

- Heuristics produce false positives and false negatives. No result verifies that a credential works. A clean scan is not a security guarantee.
- No language parser, escape decoding, concatenation analysis, environment expansion, archive scanning, historical Git scanning, or detection of encoded/obfuscated secrets. Assignment matching supports common simple ASCII values, not every legal password character.
- Quoted-string analysis is single-line. PEM detection finds headers, not full validated blocks. Unified diffs must have standard hunk counts; combined/word diffs and quoted/escaped Git filenames are not fully supported. Use ordinary unified diffs; removed/context lines are not scanned.
- Skipped files/directories and invalid UTF-8/UTF-16 can hide secrets. No ignore-file integration, incremental cache or streaming: each file and stdin are read into memory. Very large files and untrusted regexes can exhaust resources.
- Output deliberately reveals a small value prefix/suffix and file locations. Treat reports as sensitive metadata. There is no unredacted output option.
- This tool does not rotate secrets, revoke access, encrypt configuration or replace a secrets manager. If a real secret was committed, remove it and rotate/revoke it; deleting the line alone is insufficient.

MIT licensed. See [LICENSE](LICENSE).
