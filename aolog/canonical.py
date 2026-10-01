"""Canonical JSON encoding for audit log values.

The wire value is normalized UTF-8 JSON.  Object members are sorted by their
Unicode code points and duplicate keys are rejected so the same JSON value has
exactly one accepted byte representation.
"""

from __future__ import annotations

import json
from typing import Any


class CanonicalJSONError(ValueError):
    """Raised when a value cannot be represented as canonical JSON."""


class _DuplicateKeyDetector(dict):
    def __setitem__(self, key: str, value: Any) -> None:
        if key in self:
            raise CanonicalJSONError(f"duplicate JSON object key: {key!r}")
        super().__setitem__(key, value)


def object_pairs_hook(pairs: list[tuple[str, Any]]) -> _DuplicateKeyDetector:
    result = _DuplicateKeyDetector()
    for key, value in pairs:
        result[key] = value
    return result


def canonicalize(value: Any) -> bytes:
    """Return the deterministic UTF-8 JSON bytes for *value*."""

    def check(item: Any) -> None:
        if isinstance(item, dict):
            for key, child in item.items():
                if not isinstance(key, str):
                    raise CanonicalJSONError("JSON object keys must be strings")
                check(child)
        elif isinstance(item, list):
            for child in item:
                check(child)
        elif isinstance(item, float):
            # json.dumps emits non-finite tokens which are not JSON.
            if item != item or item in (float("inf"), float("-inf")):
                raise CanonicalJSONError("non-finite numbers cannot be encoded")
        elif item is None or isinstance(item, (bool, int, str)):
            return
        else:
            raise CanonicalJSONError(f"unsupported JSON value type: {type(item)!r}")

    check(value)
    text = json.dumps(
        value,
        ensure_ascii=False,
        allow_nan=False,
        sort_keys=True,
        separators=(",", ":"),
    )
    # Python strings should not contain surrogate pairs after strict decoding.
    # Encode without the default surrogatepass behavior to enforce that.
    try:
        return text.encode("utf-8", errors="strict")
    except UnicodeEncodeError as exc:
        raise CanonicalJSONError("value contains invalid Unicode surrogates") from exc


def canonicalize_input(data: str | bytes) -> bytes:
    """Parse JSON input and return its normalized byte representation."""

    if isinstance(data, bytes):
        text = data.decode("utf-8", errors="strict")
    else:
        # Round-trip through UTF-8 to reject lone Unicode surrogates.
        data.encode("utf-8", errors="strict")
        text = data
    parsed = json.loads(text, object_pairs_hook=object_pairs_hook)
    return canonicalize(parsed)
