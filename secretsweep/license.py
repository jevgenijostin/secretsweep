"""Local checksum gate, deliberately not payment or cryptographic licensing."""
import hashlib
import hmac
import re


def make_key(customer):
    if not re.fullmatch(r"[A-Z0-9]{4,32}", customer):
        raise ValueError("customer must contain 4-32 uppercase letters or digits")
    checksum = hashlib.sha256(("SecretSweep-v1:" + customer).encode()).hexdigest()[:12].upper()
    return f"SS1-{customer}-{checksum}"


def valid_key(value):
    if not isinstance(value, str) or not re.fullmatch(r"SS1-[A-Z0-9]{4,32}-[A-F0-9]{12}", value):
        return False
    return hmac.compare_digest(value, make_key(value.split("-")[1]))
