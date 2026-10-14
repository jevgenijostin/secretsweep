"""Auditable fingerprint rules; no network validation."""
from dataclasses import dataclass
import re

@dataclass(frozen=True)
class Rule:
    name: str
    regex: re.Pattern
    severity: str = "HIGH"
    min_entropy: float = 0.0


def rule(name, expression, severity="HIGH", min_entropy=0.0):
    return Rule(name, re.compile(expression), severity, min_entropy)


def assignment(names, length):
    return rf'''(?i)\b(?:{names})\b["']?\s*[:=]\s*["']?(?P<secret>[A-Za-z0-9_+/=.!@#$%^&*~-]{{{length},}})'''

FREE_RULES = (
    rule("aws-access-key-id", r"\b(?:AKIA|ASIA)[A-Z0-9]{16}\b"),
    rule("aws-secret-key", assignment("aws_secret_access_key|aws_secret_key", 40), min_entropy=3.5),
    rule("generic-api-key", assignment("api_key|apikey", 16), min_entropy=3.5),
    rule("generic-secret", assignment("secret", 16), min_entropy=3.5),
    rule("generic-token", assignment("token", 16), min_entropy=3.5),
    rule("generic-password", assignment("password|passwd|pwd", 12), min_entropy=3.0),
    rule("private-key", r"-----BEGIN (?:[A-Z0-9]+ )*PRIVATE KEY-----"),
    rule("slack-token", r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b"),
    rule("jwt", r"\beyJ[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b", "MEDIUM"),
    rule("github-token", r"\bgh[pousr]_[A-Za-z0-9]{36}\b"),
    rule("github-fine-grained-token", r"\bgithub_pat_[A-Za-z0-9_]{60,}\b"),
    rule("gitlab-token", r"\bglpat-[A-Za-z0-9_-]{20,}\b"),
    rule("google-api-key", r"\bAIza[A-Za-z0-9_-]{35}\b"),
    rule("sendgrid-api-key", r"\bSG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}\b"),
    rule("npm-token", r"\bnpm_[A-Za-z0-9]{36}\b"),
)
PAID_RULES = (
    rule("gcp-service-account", r'"type"\s*:\s*"(?P<secret>service_account)"', "MEDIUM"),
    rule("stripe-secret-key", r"\bsk_live_[A-Za-z0-9]{24,}\b"),
    rule("stripe-publishable-key", r"\bpk_live_[A-Za-z0-9]{24,}\b", "LOW"),
)
