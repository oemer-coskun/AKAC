"""Identifier and shape checks (spec: identifiers, closed record shapes)."""
import re

from .js import safe_integer, safe_number, utf16_length

_ID = re.compile(r"[a-zA-Z0-9][a-zA-Z0-9._:-]{0,127}")
RESERVED = ("constructor", "prototype", "__proto__")


def valid_id(s):
    return isinstance(s, str) and _ID.fullmatch(s) is not None and s not in RESERVED


def exact_keys(value, required, optional=()):
    return isinstance(value, dict) and all(k in value for k in required) and all(k in required or k in optional for k in value)


def safe_text(s, maximum):
    return isinstance(s, str) and 0 < utf16_length(s) <= maximum


__all__ = ["valid_id", "exact_keys", "safe_text", "safe_number", "safe_integer"]
