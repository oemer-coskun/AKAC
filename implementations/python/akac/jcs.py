"""RFC 8785 JSON Canonicalization Scheme for the JSON subset AKAC evidence uses.

null, booleans, safe integers, well-formed strings, arrays and objects with string
keys. Fractions, non-finite numbers, unsafe integers, lone surrogates and nesting
deeper than 32 are rejected (ValueError) rather than approximated. Within this subset
JCS is: members sorted by the UTF-16 code units of their names, no whitespace,
strings escaped as ECMAScript JSON.stringify does, integers in shortest form (-0 as 0).
"""
import json

from .js import safe_integer, utf16_key

DEPTH = 32


def _well_formed(s):
    return not any(0xD800 <= ord(c) <= 0xDFFF for c in s)


def _string(s):
    if not _well_formed(s):
        raise ValueError("JCS: string is not well-formed Unicode")
    return json.dumps(s, ensure_ascii=False)


def _encode(value, depth):
    if depth > DEPTH:
        raise ValueError("JCS: nesting too deep")
    if value is None:
        return "null"
    if value is True:
        return "true"
    if value is False:
        return "false"
    if type(value) in (int, float):
        if not safe_integer(value):
            raise ValueError("JCS subset: only safe integers")
        return str(int(value))
    if isinstance(value, str):
        return _string(value)
    if isinstance(value, list):
        return "[" + ",".join(_encode(v, depth + 1) for v in value) + "]"
    if isinstance(value, dict):
        if not all(isinstance(k, str) for k in value):
            raise ValueError("JCS: keys must be strings")
        keys = sorted(value, key=utf16_key)
        return "{" + ",".join(_string(k) + ":" + _encode(value[k], depth + 1) for k in keys) + "}"
    raise ValueError(f"JCS: unsupported {type(value).__name__}")


def canonicalize(value):
    return _encode(value, 0)


def canonical_bytes(value):
    return canonicalize(value).encode("utf-8")
