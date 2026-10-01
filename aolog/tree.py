"""RFC 6962-style binary Merkle tree used by the append-only log.

Leaf and interior hashing use distinct one-byte domain prefixes:
  leaf:     SHA256(0x00 || record_bytes)
  interior: SHA256(0x01 || left_hash || right_hash)

The consistency proof in this module is represented solely by hashes.  The
ordered perfect-subtree ranges needed by the verifier are a deterministic
function of (old_size, new_size), so an untrusted server cannot choose which
ranges the supplied hashes represent.
"""

from __future__ import annotations

import hashlib
from collections.abc import Iterable, Sequence

LEAF_PREFIX = b"\x00"
NODE_PREFIX = b"\x01"
EMPTY_HASH = hashlib.sha256(b"").digest()
HASH_SIZE = 32


def leaf_hash(record: bytes) -> bytes:
    return hashlib.sha256(LEAF_PREFIX + record).digest()


def node_hash(left: bytes, right: bytes) -> bytes:
    if len(left) != HASH_SIZE or len(right) != HASH_SIZE:
        raise ValueError("Merkle hashes must be 32 bytes")
    return hashlib.sha256(NODE_PREFIX + left + right).digest()


def split_point(n: int) -> int:
    """Return the largest power of two not greater than n."""
    if n < 2:
        raise ValueError("cannot split a tree with fewer than two leaves")
    return 1 << ((n - 1).bit_length() - 1)


def root_from_leaves(leaves: Sequence[bytes]) -> bytes:
    """Independent, deliberately simple O(n log n) root implementation."""
    if not leaves:
        return EMPTY_HASH
    if len(leaves) == 1:
        return leaves[0]
    k = split_point(len(leaves))
    return node_hash(root_from_leaves(leaves[:k]), root_from_leaves(leaves[k:]))


class MerkleTree:
    """Append-only cache supporting leaves, ranges, inclusion, and ranges."""

    def __init__(self, leaves: Iterable[bytes] = ()) -> None:
        self.leaves: list[bytes] = []
        self._nodes: dict[tuple[int, int], bytes] = {}
        for item in leaves:
            self.append(item)

    def __len__(self) -> int:
        return len(self.leaves)

    def append(self, value: bytes) -> None:
        if len(value) != HASH_SIZE:
            raise ValueError("leaf hash must be 32 bytes")
        self.leaves.append(value)
        self._nodes[(len(self.leaves) - 1, 1)] = value

    def root(self, size: int | None = None) -> bytes:
        if size is None:
            size = len(self.leaves)
        if size < 0 or size > len(self.leaves):
            raise IndexError("tree size is out of range")
        return self.range_hash(0, size)

    def range_hash(self, start: int, length: int) -> bytes:
        if length == 0:
            return EMPTY_HASH
        key = (start, length)
        cached = self._nodes.get(key)
        if cached is not None:
            return cached
        if length == 1:
            value = self.leaves[start]
        else:
            if length & (length - 1) == 0:
                value = node_hash(
                    self.range_hash(start, length // 2),
                    self.range_hash(start + length // 2, length // 2),
                )
            else:
                chunks = _perfect_chunks(start, length)
                value = fold_perfect(
                    [
                        (chunk_start, chunk_len, self.range_hash(chunk_start, chunk_len))
                        for chunk_start, chunk_len in chunks
                    ]
                )
        self._nodes[key] = value
        return value


def _perfect_chunks(start: int, length: int) -> Iterable[tuple[int, int]]:
    """Split [start,start+length) into maximal aligned perfect subtrees."""
    pos = start
    end = start + length
    remaining = length
    while remaining:
        block = 1 << ((end - pos).bit_length() - 1)
        while block > remaining or pos % block:
            block //= 2
        yield pos, block
        pos += block
        remaining -= block


def fold_perfect(parts: Sequence[tuple[int, int, bytes]]) -> bytes:
    """Fold hashes of ordered perfect chunks into a Merkle root.

    Each item is ``(start, length, hash)``.  Equal-sized adjacent chunks are
    hashed as siblings; trailing smaller chunks then fold from the right.
    """
    stack: list[tuple[int, int, bytes]] = []
    for start, length, value in parts:
        if length <= 0 or (length & (length - 1)) or start % length:
            raise ValueError("proof part is not an aligned perfect subtree")
        cur_start, cur_len, cur_hash = start, length, value
        while stack and stack[-1][1] == cur_len:
            left_start, _, left_hash = stack.pop()
            if left_start + cur_len != cur_start:
                raise ValueError("proof parts are not contiguous")
            cur_start = left_start
            cur_len *= 2
            cur_hash = node_hash(left_hash, cur_hash)
        stack.append((cur_start, cur_len, cur_hash))

    if not stack:
        return EMPTY_HASH
    _, _, result = stack.pop()
    while stack:
        _, _, left = stack.pop()
        result = node_hash(left, result)
    return result


def inclusion_ranges(index: int, size: int) -> list[tuple[int, int]]:
    """Derive ordered perfect-subtree ranges for an inclusion proof.

    The order is the verifier-friendly sorted range order; a verifier folds
    the leaf and these perfect chunks rather than relying on a supplied path.
    """
    if not (0 <= index < size):
        raise IndexError("inclusion index is out of range")
    result: list[tuple[int, int]] = []

    def walk(start: int, length: int, target: int) -> None:
        if length == 1:
            return
        k = split_point(length)
        if target < k:
            for chunk_start, chunk_length in _perfect_chunks(start + k, length - k):
                result.append((chunk_start, chunk_length))
            walk(start, k, target)
        else:
            if start != target or k != 1:
                result.append((start, k))
            walk(start + k, length - k, target - k)

    walk(0, size, index)
    return sorted(set(result))


def consistency_ranges(old_size: int, new_size: int) -> list[tuple[int, int]]:
    """Return ordered perfect-subtree proof ranges for prefix consistency."""
    if not 0 <= old_size <= new_size:
        raise ValueError("invalid consistency sizes")
    if old_size in (0, new_size):
        return []

    result: list[tuple[int, int]] = []

    def walk(start: int, length: int) -> None:
        # The proof consists of perfect chunks shared with, or sibling to,
        # chunks in the old prefix.
        if start >= old_size:
            # An entire perfect subtree absent from the old prefix.
            result.append((start, length))
            return
        if start + length <= old_size:
            # An entire perfect subtree belonging to both prefixes.
            result.append((start, length))
            return
        if length == 1:
            raise AssertionError("a length-one range cannot cross the boundary")
        half = length // 2
        if length & (length - 1) == 0:
            # Perfect interior subtree crossed by old_size.
            walk(start, half)
            walk(start + half, half)
        else:
            k = split_point(length)
            walk(start, k)
            walk(start + k, length - k)

    for start, length in _perfect_chunks(0, new_size):
        walk(start, length)
    return sorted(set(result))
