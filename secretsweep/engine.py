"""Pure detection, entropy heuristics, and unified diff line mapping."""
from collections import Counter
from dataclasses import asdict, dataclass
from fnmatch import fnmatchcase
import math
import re
from .config import Config

@dataclass(frozen=True)
class Finding:
    file: str
    line: int
    pattern: str
    severity: str
    confidence: str
    snippet: str

    def to_dict(self):
        return asdict(self)


def entropy(value):
    if not value:
        return 0.0
    return -sum((n / len(value)) * math.log2(n / len(value)) for n in Counter(value).values())


def redact(value):
    # Short values and PEM markers are completely hidden.
    if len(value) < 12 or value.startswith("-----BEGIN"):
        return "[REDACTED]"
    return value[:3] + "…[REDACTED]…" + value[-3:]


def entropy_candidate(value, threshold):
    if not 24 <= len(value) <= 256 or any(c.isspace() for c in value):
        return False
    if value.lower().startswith(("data:", "http:", "https:", "urn:")):
        return False
    if re.fullmatch(r"[0-9a-fA-F-]+", value):
        return False
    classes = sum((any(c.islower() for c in value), any(c.isupper() for c in value), any(c.isdigit() for c in value)))
    return classes == 3 and entropy(value) >= threshold


def file_allowed(file, config):
    normalized = file.replace("\\", "/")
    return any(fnmatchcase(normalized, p) for p in config.allow_files)


def scan_text(text, file="<stdin>", config=None, start_line=1):
    config = config or Config()
    if file_allowed(file, config):
        return []
    findings = []
    for number, line in enumerate(text.splitlines(), start_line):
        occupied = []
        for rule in config.rules:
            for match in rule.regex.finditer(line):
                group = "secret" if "secret" in rule.regex.groupindex else 0
                value = match.group(group)
                if not value or entropy(value) < rule.min_entropy:
                    continue
                occupied.append(match.span(group))
                if value in config.allow_strings or rule.name in config.allow_patterns:
                    continue
                findings.append(Finding(file, number, rule.name, rule.severity,
                                        "HIGH" if rule.severity == "HIGH" else "MEDIUM", redact(value)))
        for match in re.finditer(r'''(["'])(?P<value>(?:\\.|(?!\1)[^\\])*)\1''', line):
            value = match.group("value")
            lo, hi = match.span("value")
            if any(lo < end and hi > begin for begin, end in occupied):
                continue
            if value in config.allow_strings or "high-entropy-string" in config.allow_patterns:
                continue
            if entropy_candidate(value, config.entropy_threshold):
                findings.append(Finding(file, number, "high-entropy-string", "MEDIUM", "MEDIUM", redact(value)))
    return findings


def scan_stdin(text, config=None):
    lines = text.splitlines()
    is_diff = any(line.startswith("diff --git ") for line in lines) or any(
        line.startswith("--- ") and i + 1 < len(lines) and lines[i + 1].startswith("+++ ")
        for i, line in enumerate(lines))
    if not is_diff:
        return scan_text(text, config=config)
    file = "<stdin>"
    number = None
    old_left = new_left = 0
    findings = []
    for line in lines:
        if old_left or new_left:
            if line.startswith("\\ No newline"):
                continue
            if line.startswith("+") and new_left:
                findings.extend(scan_text(line[1:], file, config, number))
                number += 1
                new_left -= 1
            elif line.startswith("-") and old_left:
                old_left -= 1
            elif line.startswith(" ") and old_left and new_left:
                number += 1
                old_left -= 1
                new_left -= 1
            else:
                raise ValueError("Malformed or truncated unified diff")
            continue
        if line.startswith("+++ "):
            file = line[4:].split("\t")[0]
            if file.startswith("b/"):
                file = file[2:]
        elif line.startswith("@@"):
            match = re.match(r"@@ -(\d+)(?:,(\d+))? \+(\d+)(?:,(\d+))? @@", line)
            if not match:
                raise ValueError("Malformed unified diff hunk")
            old_left = int(match[2] or 1)
            number = int(match[3])
            new_left = int(match[4] or 1)
    if old_left or new_left:
        raise ValueError("Malformed or truncated unified diff")
    return findings
