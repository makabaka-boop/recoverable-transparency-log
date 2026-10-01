import concurrent.futures
import json
import os
import subprocess
import sys
import tempfile
import unittest

from aolog.canonical import canonicalize
from aolog.store import (
    HEADER_SIZE,
    AppendOnlyStore,
    LogCorruptionError,
    TreeHeadConflictError,
    _pack_header,
)


def make_record(i):
    return canonicalize({"sequence": i, "payload": "x" * (i % 23)})


class StoreTest(unittest.TestCase):
    def setUp(self):
        self.tempdir = tempfile.TemporaryDirectory()
        self.path = self.tempdir.name

    def tearDown(self):
        self.tempdir.cleanup()

    def log_path(self):
        from pathlib import Path
        return Path(self.path) / "log.aol"

    def test_batch_append_and_unique_concurrent_order(self):
        store = AppendOnlyStore(self.path)
        batch_a = [make_record(i) for i in range(10)]
        batch_b = [make_record(i + 100) for i in range(7)]

        with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
            futures = [
                pool.submit(store.append_batch, batch_a),
                pool.submit(store.append_batch, batch_b),
            ]
            first, second = sorted((f.result() for f in futures), key=lambda x: x[0])

        self.assertEqual(first, list(range(0, 10)))
        self.assertEqual(second, list(range(10, 17)))
        self.assertEqual(store.current_head()["tree_size"], 17)
        store.close()

        reopened = AppendOnlyStore(self.path)
        self.assertEqual(reopened.current_head()["tree_size"], 17)
        reopened.close()

    def test_torn_tail_is_truncated_but_middle_corruption_errors(self):
        path = self.log_path()
        store = AppendOnlyStore(self.path)
        records = [make_record(i) for i in range(3)]
        store.append_batch(records)
        store.close()

        original_size = path.stat().st_size
        with open(path, "ab") as f:
            f.write(b"torn-tail")
        reopened = AppendOnlyStore(self.path)
        self.assertEqual(reopened.current_head()["tree_size"], 3)
        reopened.close()
        self.assertEqual(path.stat().st_size, original_size)

        with open(path, "r+b") as f:
            f.seek(HEADER_SIZE + len(records[0]))
            value = bytearray(f.read(1))
            value[0] ^= 0x01
            f.seek(HEADER_SIZE + len(records[0]))
            f.write(value)
        with self.assertRaises(LogCorruptionError):
            AppendOnlyStore(self.path)

    def test_torn_payload_of_last_record_is_removed(self):
        path = self.log_path()
        first = make_record(0)
        store = AppendOnlyStore(self.path)
        store.append_batch([first])
        store.close()
        good_size = path.stat().st_size

        second = make_record(1)
        header = _pack_header(len(second))
        with open(path, "ab") as f:
            f.write(header + second[:3])
        reopened = AppendOnlyStore(self.path)
        self.assertEqual(reopened.current_head()["tree_size"], 1)
        self.assertEqual(reopened.get_record(0), first)
        reopened.close()
        self.assertEqual(path.stat().st_size, good_size)

    def test_crash_between_records_and_tree_head_republishes(self):
        initial = AppendOnlyStore(self.path)
        initial.append_batch([make_record(0)])
        initial.close()

        code = f"""
from aolog.canonical import canonicalize
from aolog.store import AppendOnlyStore
s = AppendOnlyStore({self.path!r}, crash_at='after_records')
s.append_batch([canonicalize({{'after': 'crash'}})])
"""
        env = dict(os.environ, PYTHONPATH="/workspace")
        crashed = subprocess.run([sys.executable, "-c", code], env=env)
        self.assertEqual(crashed.returncode, 91)

        head = json.loads((self.log_path().parent / "tree-head.json").read_bytes())
        self.assertEqual(head["tree_size"], 1)

        reopened = AppendOnlyStore(self.path)
        self.assertEqual(reopened.current_head()["tree_size"], 2)
        self.assertEqual(json.loads(reopened.get_record(1)), {"after": "crash"})
        reopened.close()

    def test_conflicting_published_head_is_an_error(self):
        store = AppendOnlyStore(self.path)
        store.append_batch([make_record(0)])
        store.close()
        head_path = self.log_path().parent / "tree-head.json"
        head = json.loads(head_path.read_bytes())
        head["root_hash"] = "00" * 32
        head_path.write_text(json.dumps(head), encoding="utf-8")
        with self.assertRaises(TreeHeadConflictError):
            AppendOnlyStore(self.path)

    def test_invalid_header_in_tail_is_not_silently_truncated(self):
        store = AppendOnlyStore(self.path)
        store.append_batch([make_record(0)])
        store.close()
        with open(self.log_path(), "ab") as f:
            f.write(b"X" * HEADER_SIZE)
        with self.assertRaises(LogCorruptionError):
            AppendOnlyStore(self.path)


if __name__ == "__main__":
    unittest.main()
