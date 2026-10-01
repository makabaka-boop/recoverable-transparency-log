"""Independent proof verification used by the audit command.

These functions deliberately accept raw service data and derive every hash
and proof path themselves.  The service never supplies a boolean result; it
supplies hashes, which must reconstruct an advertised tree head.
"""

from __future__ import annotations

import hmac

from .canonical import canonicalize
from .tree import (
    EMPTY_HASH,
    HASH_SIZE,
    consistency_ranges,
    fold_perfect,
    inclusion_ranges,
    leaf_hash,
)


class ProofError(ValueError):
    pass


def _check_hash(value: bytes, what: str) -> None:
    if not isinstance(value, bytes) or len(value) != HASH_SIZE:
        raise ProofError(f"{what} must be {HASH_SIZE} raw bytes")


def verify_inclusion(
    *,
    record_value: object,
    index: int,
    size: int,
    root: bytes,
    proof: list[bytes],
) -> None:
    if not isinstance(index, int) or isinstance(index, bool):
        raise ProofError("index must be an integer")
    if not isinstance(size, int) or isinstance(size, bool) or size < 0:
        raise ProofError("tree size must be a non-negative integer")
    _check_hash(root, "root")
    if size == 0:
        raise ProofError("an empty tree cannot contain a record")
    ranges = inclusion_ranges(index, size)
    if len(proof) != len(ranges):
        raise ProofError("inclusion proof has the wrong number of hashes")

    normalized = canonicalize(record_value)
    if not ranges:
        if size != 1 or index != 0:
            raise ProofError("invalid empty inclusion proof")
        calculated = leaf_hash(normalized)
    else:
        parts: list[tuple[int, int, bytes]] = [(index, 1, leaf_hash(normalized))]
        for proof_index, (start, length) in enumerate(ranges):
            if start <= index < start + length:
                raise ProofError("inclusion proof must not contain the leaf itself")
            value = proof[proof_index]
            _check_hash(value, "proof hash")
            parts.append((start, length, value))
        parts.sort()
        calculated = fold_perfect(parts)
    if not hmac.compare_digest(calculated, root):
        raise ProofError("inclusion proof does not verify against root")


def _parts_from_consistency(
    old_size: int,
    new_size: int,
    proof: list[bytes],
) -> list[tuple[int, int, bytes]]:
    if len(proof) != len(consistency_ranges(old_size, new_size)):
        raise ProofError("consistency proof has the wrong number of hashes")
    parts = []
    pos = 0
    old_seen = 0
    for (start, length), value in zip(consistency_ranges(old_size, new_size), proof):
        _check_hash(value, "proof hash")
        if start != pos:
            raise ProofError("consistency proof ranges are not contiguous")
        pos = start + length
        if start < old_size:
            old_seen += min(length, old_size - start)
        parts.append((start, length, value))
    if new_size and pos != new_size:
        raise ProofError("consistency proof does not cover the new tree")
    if old_seen != old_size:
        raise ProofError("consistency proof does not cover the old prefix")
    return parts


def verify_consistency(
    *,
    old_size: int,
    new_size: int,
    old_root: bytes,
    new_root: bytes,
    proof: list[bytes],
) -> None:
    if not isinstance(old_size, int) or isinstance(old_size, bool):
        raise ProofError("old size must be an integer")
    if not isinstance(new_size, int) or isinstance(new_size, bool):
        raise ProofError("new size must be an integer")
    if not 0 <= old_size <= new_size:
        raise ProofError("invalid consistency size relationship")
    _check_hash(old_root, "old root")
    _check_hash(new_root, "new root")

    if old_size == new_size:
        if proof:
            raise ProofError("equal-sized consistency proof must be empty")
        if not hmac.compare_digest(old_root, new_root):
            raise ProofError("equal-sized tree heads have different roots")
        return
    if old_size == 0:
        if proof:
            raise ProofError("empty-old consistency proof must be empty")
        if not hmac.compare_digest(old_root, EMPTY_HASH):
            raise ProofError("old size zero must use the empty tree root")
        return

    parts = _parts_from_consistency(old_size, new_size, proof)
    calculated_new = fold_perfect(parts)
    if not hmac.compare_digest(calculated_new, new_root):
        raise ProofError("consistency proof does not verify the new root")

    old_parts = [
        (start, min(length, old_size - start), value)
        for start, length, value in parts
        if start < old_size
    ]
    calculated_old = fold_perfect(old_parts)
    if not hmac.compare_digest(calculated_old, old_root):
        raise ProofError("consistency proof does not verify the old root")
