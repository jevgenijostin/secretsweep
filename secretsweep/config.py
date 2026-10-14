"""Validated JSON configuration. Paths are relative to scan root."""
from dataclasses import dataclass, field
import json
import math
from pathlib import Path
import re
from .license import valid_key
from .rules import FREE_RULES, PAID_RULES, rule

@dataclass
class Config:
    entropy_threshold: float = 4.5
    allow_strings: list = field(default_factory=list)
    allow_files: list = field(default_factory=list)
    allow_patterns: list = field(default_factory=list)
    rules: tuple = FREE_RULES


def load_config(path=None):
    if path is None:
        return Config()
    try:
        data = json.loads(Path(path).read_text(encoding="utf-8-sig"))
        if not isinstance(data, dict):
            raise ValueError()
        if set(data) - {"entropy_threshold", "allowlist", "license_key", "custom_rules"}:
            raise ValueError()
        threshold = data.get("entropy_threshold", 4.5)
        if isinstance(threshold, bool) or not isinstance(threshold, (int, float)) or not math.isfinite(threshold) or not 0 < threshold <= 8:
            raise ValueError()
        allow = data.get("allowlist", {})
        if not isinstance(allow, dict) or set(allow) - {"strings", "files", "patterns"}:
            raise ValueError()
        for values in allow.values():
            if not isinstance(values, list) or any(not isinstance(v, str) or not v for v in values):
                raise ValueError()
        licensed = valid_key(data.get("license_key"))
        if "license_key" in data and not licensed:
            raise ValueError()
        custom = data.get("custom_rules", [])
        if not isinstance(custom, list) or (custom and not licensed):
            raise ValueError()
        rules = list(FREE_RULES + (PAID_RULES if licensed else ()))
        names = {r.name for r in rules} | {"high-entropy-string"}
        for item in custom:
            if not isinstance(item, dict) or set(item) - {"name", "regex", "severity"}:
                raise ValueError()
            name, expression = item["name"], item["regex"]
            severity = item.get("severity", "HIGH")
            if not isinstance(name, str) or not re.fullmatch(r"[a-z][a-z0-9-]{0,63}", name) or name in names:
                raise ValueError()
            if not isinstance(expression, str) or not expression or severity not in {"HIGH", "MEDIUM", "LOW"}:
                raise ValueError()
            candidate = rule(name, expression, severity)
            if candidate.regex.search(""):
                raise ValueError()
            rules.append(candidate)
            names.add(name)
        return Config(threshold, allow.get("strings", []), allow.get("files", []), allow.get("patterns", []), tuple(rules))
    except (OSError, ValueError, TypeError, KeyError, re.error):
        # Never echo configuration contents (which can themselves contain secrets).
        raise ValueError("Invalid or unreadable SecretSweep configuration") from None
