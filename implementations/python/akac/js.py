"""JSON data model with the value semantics of the specification's reference language.

AKAC records are JSON. The decision rules are stated over JSON values, and two
implementations only agree when they read the same JSON the same way. This module
fixes the points where a naive Python reading differs:

* numbers: JSON has one number type. ``1``, ``1.0`` and ``1e0`` are the same
  value; ``loads`` returns an ``int`` for every integral finite number (review
  finding #14), a ``float`` otherwise. ``NaN``/``Infinity`` literals are not JSON
  and are rejected.
* absent versus null: a missing member is ``UNDEF``, distinct from JSON ``null``
  (``None``). Rules such as "absent means unrestricted" depend on it.
* strict equality, truthiness, array membership, relational comparison and string
  length (UTF-16 code units) follow the ECMAScript definitions the specification's
  reference implementation uses, so malformed records fail the same way.

A type error raised here is caught where the specification says a rule "cannot be
established" and becomes the same deny or defer as in every other implementation.
"""
import json
import math
import re

MAX_SAFE = 9007199254740991


class _Undefined:
    __slots__ = ()

    def __bool__(self):
        return False

    def __repr__(self):
        return "undefined"


UNDEF = _Undefined()


def _number(text):
    value = float(text)
    if math.isfinite(value) and value == int(value):
        return int(value)
    return value


def _constant(name):
    raise ValueError(f"{name} is not JSON")


def loads(text):
    """Parses JSON: integral numbers become int (1.0 == 1), non-JSON constants are rejected."""
    return json.loads(text, parse_float=_number, parse_constant=_constant)


def load(stream):
    return loads(stream.read())


def dumps(value):
    return json.dumps(value, ensure_ascii=False, separators=(",", ":"))


def is_number(x):
    return type(x) in (int, float)


def safe_integer(x):
    if type(x) is int:
        return -MAX_SAFE <= x <= MAX_SAFE
    if type(x) is float:
        return math.isfinite(x) and x == int(x) and abs(x) <= MAX_SAFE
    return False


def safe_number(x):
    return safe_integer(x) and x >= 0


def truthy(x):
    if x is None or x is UNDEF or x is False:
        return False
    if type(x) in (int, float):
        return x != 0 and not (type(x) is float and math.isnan(x))
    if isinstance(x, str):
        return len(x) > 0
    return True


def strict_eq(a, b):
    if a is UNDEF or b is UNDEF:
        return a is b
    if a is None or b is None:
        return a is None and b is None
    if type(a) is bool or type(b) is bool:
        return type(a) is bool and type(b) is bool and a == b
    if is_number(a) or is_number(b):
        return is_number(a) and is_number(b) and a == b
    if isinstance(a, str) or isinstance(b, str):
        return isinstance(a, str) and isinstance(b, str) and a == b
    return a is b


def same_value_zero(a, b):
    if type(a) is float and type(b) is float and math.isnan(a) and math.isnan(b):
        return True
    return strict_eq(a, b)


def key(x):
    """Hashable key with Set/Map (SameValueZero) identity."""
    if x is UNDEF:
        return ("u",)
    if x is None:
        return ("null",)
    if type(x) is bool:
        return ("b", x)
    if is_number(x):
        return ("n", "nan") if type(x) is float and math.isnan(x) else ("n", x + 0)
    if isinstance(x, str):
        return ("s", x)
    return ("o", id(x))


def utf16_length(s):
    return len(s.encode("utf-16-le", "surrogatepass")) // 2


def utf16_key(s):
    return s.encode("utf-16-be", "surrogatepass")


def prop(obj, name):
    """Property read: TypeError on null/undefined, undefined for a missing member."""
    if obj is None or obj is UNDEF:
        raise TypeError(f"Cannot read properties of {obj!r} (reading {name!r})")
    if isinstance(obj, dict):
        return obj.get(name, UNDEF)
    if isinstance(obj, list) and name == "length":
        return len(obj)
    if isinstance(obj, str) and name == "length":
        return utf16_length(obj)
    return UNDEF


def opt(obj, name):
    """Optional chaining (obj?.name)."""
    return UNDEF if obj is None or obj is UNDEF else prop(obj, name)


def coalesce(x, default):
    """x ?? default."""
    return default if x is None or x is UNDEF else x


def is_array(x):
    return isinstance(x, list)


def is_plain(x):
    return isinstance(x, dict)


def to_string(x):
    if isinstance(x, str):
        return x
    if x is None:
        return "null"
    if x is UNDEF:
        return "undefined"
    if type(x) is bool:
        return "true" if x else "false"
    if type(x) is int:
        return str(x)
    if type(x) is float:
        if math.isnan(x):
            return "NaN"
        if math.isinf(x):
            return "Infinity" if x > 0 else "-Infinity"
        return repr(x)
    if isinstance(x, list):
        return ",".join("" if v is None or v is UNDEF else to_string(v) for v in x)
    return "[object Object]"


def to_number(x):
    if type(x) is bool:
        return 1 if x else 0
    if is_number(x):
        return x
    if x is None:
        return 0
    if isinstance(x, str):
        text = x.strip()
        if not text:
            return 0
        try:
            if re.fullmatch(r"[+-]?(\d+\.?\d*([eE][+-]?\d+)?|\.\d+([eE][+-]?\d+)?|Infinity)", text):
                return float(text)
            if re.fullmatch(r"0[xX][0-9a-fA-F]+", text):
                return int(text, 16)
        except ValueError:
            pass
        return math.nan
    if isinstance(x, list):
        return to_number(to_string(x))
    return math.nan


def _compare(a, b):
    """Abstract relational comparison: -1, 0, 1 or None (undefined)."""
    if isinstance(a, list) or isinstance(a, dict):
        a = to_string(a)
    if isinstance(b, list) or isinstance(b, dict):
        b = to_string(b)
    if isinstance(a, str) and isinstance(b, str):
        ka, kb = utf16_key(a), utf16_key(b)
        return (ka > kb) - (ka < kb)
    na, nb = to_number(a) if a is not UNDEF else math.nan, to_number(b) if b is not UNDEF else math.nan
    if (type(na) is float and math.isnan(na)) or (type(nb) is float and math.isnan(nb)):
        return None
    return (na > nb) - (na < nb)


def lt(a, b):
    c = _compare(a, b)
    return c is not None and c < 0


def le(a, b):
    c = _compare(a, b)
    return c is not None and c <= 0


def gt(a, b):
    return lt(b, a)


def ge(a, b):
    return le(b, a)


def iterate(x):
    """for (... of x): arrays and strings are iterable, anything else throws."""
    if isinstance(x, list):
        return list(x)
    if isinstance(x, str):
        return list(x)
    raise TypeError("not iterable")


def includes(container, value):
    """Array.prototype.includes (SameValueZero) or String.prototype.includes (substring)."""
    if isinstance(container, list):
        return any(same_value_zero(item, value) for item in container)
    if isinstance(container, str):
        return to_string(value) in container
    raise TypeError("includes is not a function")


def index_of(container, value):
    if isinstance(container, list):
        for i, item in enumerate(container):
            if strict_eq(item, value):
                return i
        return -1
    raise TypeError("indexOf is not a function")


def every(arr, fn):
    if not isinstance(arr, list):
        raise TypeError("every is not a function")
    return all(fn(x) for x in arr)


def some(arr, fn):
    if not isinstance(arr, list):
        raise TypeError("some is not a function")
    return any(fn(x) for x in arr)


def values(obj):
    """Object.values."""
    if obj is None or obj is UNDEF:
        raise TypeError("Cannot convert undefined or null to object")
    if isinstance(obj, dict):
        return list(obj.values())
    if isinstance(obj, list):
        return list(obj)
    if isinstance(obj, str):
        return list(obj)
    return []


def entries(obj):
    if obj is None or obj is UNDEF:
        raise TypeError("Cannot convert undefined or null to object")
    if isinstance(obj, dict):
        return list(obj.items())
    if isinstance(obj, list):
        return [(str(i), v) for i, v in enumerate(obj)]
    return []


def has_own(obj, name):
    """Object.hasOwn: TypeError on null/undefined."""
    if obj is None or obj is UNDEF:
        raise TypeError("Cannot convert undefined or null to object")
    if isinstance(obj, dict):
        return name in obj
    return False


def index(obj, name):
    """Plain member access obj[name] (the name converted to a property key)."""
    if obj is None or obj is UNDEF:
        raise TypeError("Cannot read properties of undefined")
    if isinstance(obj, dict):
        return obj.get(to_string(name), UNDEF)
    return prop(obj, to_string(name))


def get(records, name):
    """Own-property lookup: record ids never resolve to inherited members."""
    if not isinstance(name, str):
        return UNDEF
    return records[name] if has_own(records, name) else UNDEF


def flat_map(arr, fn):
    if not isinstance(arr, list):
        raise TypeError("flatMap is not a function")
    out = []
    for x in arr:
        v = fn(x)
        if isinstance(v, list):
            out.extend(v)
        else:
            out.append(v)
    return out


def unique(items):
    """[...new Set(items)] in insertion order."""
    seen, out = set(), []
    for x in items:
        k = key(x)
        if k not in seen:
            seen.add(k)
            out.append(x)
    return out


def sort_default(items):
    """Array.prototype.sort() without comparator: by string form, UTF-16 code units; undefined last."""
    defined = [x for x in items if x is not UNDEF]
    return sorted(defined, key=lambda x: utf16_key(to_string(x))) + [x for x in items if x is UNDEF]


def string_key_sort(items):
    return sorted(items, key=utf16_key)
