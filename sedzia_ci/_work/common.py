"""Strict serialization and finite numbers. No network, activation or credentials."""
import hashlib
import json
import math


def canonical(value):
    return json.dumps(value, sort_keys=True, ensure_ascii=False, separators=(",", ":"),
                      allow_nan=False).encode("utf-8")


def sha(value):
    return hashlib.sha256(value if isinstance(value, bytes) else canonical(value)).hexdigest()


def strict_loads(raw):
    def pairs(items):
        result = {}
        for k, v in items:
            if k in result:
                raise ValueError("DUPLICATE_KEY:" + k)
            result[k] = v
        return result
    def bad(x):
        raise ValueError("NONFINITE_JSON:" + x)
    return json.loads(raw, object_pairs_hook=pairs, parse_constant=bad)


def finite(value, lo=None, hi=None):
    if type(value) not in (int, float) or not math.isfinite(value):
        raise ValueError("NONFINITE_OR_NOT_NUMBER")
    if lo is not None and value < lo or hi is not None and value > hi:
        raise ValueError("OUT_OF_RANGE")
    return float(value)


def result(status, reason, **fields):
    return dict(status=status, reason=reason, **fields)
