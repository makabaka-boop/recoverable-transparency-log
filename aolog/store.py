"""Durable file-backed storage for the append-only audit log."""

from __future__ import annotations

import hashlib
import json
import os
import struct
import threading
import zlib
from pathlib import Path
from typing import Any

from .canonical import canonicalize
from .tree import (
    EMPTY_HASH,
    MerkleTree,
    consistency_ranges,
    inclusion_ranges,
    leaf_hash,
)

MAGIC = b"AOL1"
VERSION = 1
HEADER_SIZE = 16
MAX_PAYLOAD = 16 * 1024 * 1024
# magic(4), version(1), flags(1), reserved(2), payload_length(4),
# header_crc32(4). The CRC protects the first 12 bytes.
_HEADER = struct.Struct(">4sBBHII")


class LogCorruptionError(RuntimeError):
    """A complete frame in the middle/tail is structurally bad."""


class TreeHeadConflictError(RuntimeError):
    """A persisted tree head does not match the durable log."""


def _fsync_directory(path: Path) -> None:
    flags = os.O_RDONLY
    if hasattr(os, "O_DIRECTORY"):
        flags |= os.O_DIRECTORY
    fd = os.open(os.fspath(path.parent), flags)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def _pack_header(payload_length: int) -> bytes:
    packed = _HEADER.pack(
        MAGIC,
        VERSION,
        0,  # flags
        0,  # reserved
        payload_length,
        0,  # CRC placeholder
    )
    crc = zlib.crc32(packed[:12]) & 0xFFFFFFFF
    return _HEADER.pack(MAGIC, VERSION, 0, 0, payload_length, crc)


def _frame(record: bytes) -> bytes:
    if len(record) > MAX_PAYLOAD:
        raise ValueError("record is too large")
    header = _pack_header(len(record))
    checksum = hashlib.sha256(header + record).digest()
    return header + record + checksum


class AppendOnlyStore:
    """Thread-safe durable store with crash recovery and tree-head publishing."""

    def __init__(self, directory: str | os.PathLike[str], *, crash_at: str | None = None) -> None:
        self.directory = Path(directory)
        self.directory.mkdir(parents=True, exist_ok=True)
        self.log_path = self.directory / "log.aol"
        self.head_path = self.directory / "tree-head.json"
        self.tmp_head_path = self.directory / ".tree-head.json.tmp"
        self._lock = threading.RLock()
        self._crash_at = crash_at or os.environ.get("AOLOG_CRASH")

        flags = os.O_RDWR | os.O_CREAT
        self._fd = os.open(os.fspath(self.log_path), flags, 0o600)
        self.records: list[bytes] = []
        self.offsets: list[int] = []
        self._next_offset = 0
        self.tree = MerkleTree()
        self.published_size = 0

        self._recover()

    def close(self) -> None:
        with self._lock:
            os.close(self._fd)

    def __enter__(self) -> "AppendOnlyStore":
        return self

    def __exit__(self, exc_type: object, exc: object, tb: object) -> None:
        self.close()

    def _recover(self) -> None:
        size = os.fstat(self._fd).st_size
        pos = 0
        records: list[bytes] = []
        offsets: list[int] = []
        truncate_at: int | None = None

        while pos < size:
            header = os.pread(self._fd, HEADER_SIZE, pos)
            if not header:
                break
            if len(header) < HEADER_SIZE:
                # A torn fixed-size header is the only permitted truncation.
                truncate_at = pos
                break
            try:
                magic, version, flags, reserved, payload_length, crc = _HEADER.unpack(header)
            except struct.error as exc:
                raise LogCorruptionError(f"invalid frame header at offset {pos}") from exc
            expected_crc = zlib.crc32(header[:12]) & 0xFFFFFFFF
            if (
                magic != MAGIC
                or version != VERSION
                or flags != 0
                or reserved != 0
                or payload_length > MAX_PAYLOAD
                or crc != expected_crc
            ):
                raise LogCorruptionError(f"invalid frame header at offset {pos}")

            frame_end = pos + HEADER_SIZE + payload_length + 32
            if frame_end > size:
                # Header was complete and valid, but payload/checksum did not
                # finish: this is an unfinished tail record.
                truncate_at = pos
                break

            payload = os.pread(self._fd, payload_length, pos + HEADER_SIZE)
            checksum = os.pread(self._fd, 32, pos + HEADER_SIZE + payload_length)
            if len(payload) != payload_length or len(checksum) != 32:
                truncate_at = pos
                break
            actual_checksum = hashlib.sha256(header + payload).digest()
            if actual_checksum != checksum:
                raise LogCorruptionError(f"checksum mismatch at offset {pos}")

            offsets.append(pos)
            records.append(payload)
            pos = frame_end

        if truncate_at is not None:
            os.ftruncate(self._fd, truncate_at)
            os.fsync(self._fd)
            _fsync_directory(self.log_path)

        for payload in records:
            self.tree.append(leaf_hash(payload))
        self.records = records
        self.offsets = offsets
        self._next_offset = truncate_at if truncate_at is not None else pos

        physical_root = self.tree.root(len(records))
        if not self.head_path.exists():
            self.published_size = len(records)
            self._write_head_locked(len(records), physical_root)
            return

        try:
            head = json.loads(self.head_path.read_bytes().decode("utf-8"))
            head_size = int(head["tree_size"])
            head_root = bytes.fromhex(head["root_hash"])
        except (OSError, UnicodeError, KeyError, TypeError, ValueError) as exc:
            raise TreeHeadConflictError("published tree head is malformed") from exc
        if not 0 <= head_size <= len(records) or len(head_root) != 32:
            raise TreeHeadConflictError("published tree head has invalid bounds")
        if head_size == 0:
            head_calculated = EMPTY_HASH
        else:
            head_calculated = self.tree.root(head_size)
        if head_root != head_calculated:
            raise TreeHeadConflictError("published tree root does not match log")

        self.published_size = head_size
        if head_size < len(records):
            # The log was fully written and fsynced, but publishing had not
            # completed. Re-publish instead of hiding those records.
            self._write_head_locked(len(records), physical_root)
            self.published_size = len(records)

    def _write_head_locked(self, size: int, root: bytes) -> None:
        body = canonicalize({"tree_size": size, "root_hash": root.hex()})
        with open(self.tmp_head_path, "wb") as f:
            f.write(body)
            f.flush()
            os.fsync(f.fileno())
        os.replace(self.tmp_head_path, self.head_path)
        _fsync_directory(self.head_path)

    def current_head(self) -> dict[str, Any]:
        with self._lock:
            return {
                "tree_size": self.published_size,
                "root_hash": self.tree.root(self.published_size).hex(),
            }

    def get_record(self, index: int) -> bytes:
        with self._lock:
            if not 0 <= index < self.published_size:
                raise IndexError("record sequence number is outside the published tree")
            return self.records[index]

    def published_records(self) -> list[bytes]:
        with self._lock:
            return list(self.records[: self.published_size])

    def root_hex(self, size: int) -> str:
        with self._lock:
            if not 0 <= size <= self.published_size:
                raise IndexError("requested tree size has not been published")
            return self.tree.root(size).hex()

    def inclusion_proof(self, index: int, size: int) -> dict[str, Any]:
        with self._lock:
            if not 0 <= size <= self.published_size:
                raise IndexError("requested tree size has not been published")
            ranges = inclusion_ranges(index, size)
            return {
                "index": index,
                "tree_size": size,
                "root_hash": self.tree.root(size).hex(),
                "hashes": [
                    self.tree.range_hash(start, length).hex()
                    for start, length in ranges
                ],
            }

    def consistency_proof(self, old_size: int, new_size: int) -> dict[str, Any]:
        with self._lock:
            if not 0 <= old_size <= new_size <= self.published_size:
                raise IndexError("requested tree sizes have not been published")
            ranges = consistency_ranges(old_size, new_size)
            return {
                "old_size": old_size,
                "new_size": new_size,
                "old_root_hash": self.tree.root(old_size).hex(),
                "new_root_hash": self.tree.root(new_size).hex(),
                "hashes": [
                    self.tree.range_hash(start, length).hex()
                    for start, length in ranges
                ],
            }

    def append_batch(self, records: list[bytes]) -> list[int]:
        """Append complete records; all become visible under one tree head."""
        if not records:
            return []
        for item in records:
            if not isinstance(item, bytes):
                raise TypeError("records must be canonical bytes")
        with self._lock:
            start = len(self.records)
            # Validate every frame before touching the log so deterministic
            # input errors cannot leave a partially accepted batch.
            frames = [_frame(item) for item in records]
            try:
                next_offset = self._next_offset
                new_offsets: list[int] = []
                for item, frame in zip(records, frames):
                    new_offsets.append(next_offset)
                    written = 0
                    # pwrite uses the exact computed offset; the lock orders
                    # concurrent appenders and prevents overlapping writes.
                    while written < len(frame):
                        written += os.pwrite(
                            self._fd, frame[written:], next_offset + written
                        )
                    next_offset += len(frame)
                os.fsync(self._fd)
                if self._crash_at == "after_records":
                    os._exit(91)
                for item, offset in zip(records, new_offsets):
                    self.records.append(item)
                    self.offsets.append(offset)
                    self.tree.append(leaf_hash(item))
                self._next_offset = next_offset
                new_size = len(self.records)
                self._write_head_locked(new_size, self.tree.root(new_size))
                self.published_size = new_size
            except BaseException:
                # Normal process exceptions are raised; do not make an
                # unpublishable frame look successful.
                raise
            return list(range(start, start + len(records)))
