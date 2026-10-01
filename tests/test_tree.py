import unittest

from aolog.canonical import canonicalize
from aolog.tree import (
    EMPTY_HASH,
    MerkleTree,
    consistency_ranges,
    inclusion_ranges,
    leaf_hash,
    root_from_leaves,
)
from aolog.verifier import ProofError, verify_consistency, verify_inclusion


def records(n):
    return [canonicalize({"i": i, "name": f"record-{i}"}) for i in range(n)]


def leaves(n):
    return [leaf_hash(record) for record in records(n)]


def value(index):
    return {"i": index, "name": f"record-{index}"}


class MerkleTreeTest(unittest.TestCase):
    def test_empty_root_and_small_tree_cross_check(self):
        self.assertEqual(MerkleTree().root(), EMPTY_HASH)
        for n in range(1, 65):
            got = MerkleTree(leaves(n)).root()
            # Independent deliberately simple recursive builder.
            self.assertEqual(got, root_from_leaves(leaves(n)))

    def test_inclusion_proof_verifies_and_tampering_fails(self):
        n = 13
        tree = MerkleTree(leaves(n))
        root = tree.root(n)
        for index in range(n):
            ranges = inclusion_ranges(index, n)
            proof = [tree.range_hash(start, length) for start, length in ranges]
            verify_inclusion(
                record_value=value(index),
                index=index,
                size=n,
                root=root,
                proof=proof,
            )
            target = proof[0] if proof else leaf_hash(records(n)[index])
            bad = bytearray(target)
            bad[0] ^= 1
            bad_proof = [bytes(bad)] + proof[1:]
            with self.assertRaises(ProofError):
                verify_inclusion(
                    record_value=value(index),
                    index=index,
                    size=n,
                    root=root,
                    proof=bad_proof,
                )

    def test_consistency_for_all_small_prefixes(self):
        n = 37
        tree = MerkleTree(leaves(n))
        for old_size in range(0, n + 1):
            ranges = consistency_ranges(old_size, n)
            proof = [tree.range_hash(start, length) for start, length in ranges]
            verify_consistency(
                old_size=old_size,
                new_size=n,
                old_root=tree.root(old_size),
                new_root=tree.root(n),
                proof=proof,
            )

    def test_consistency_rejects_nonprefix_root(self):
        n = 8
        tree = MerkleTree(leaves(n))
        proof = [tree.range_hash(s, l) for s, l in consistency_ranges(3, n)]
        with self.assertRaises(ProofError):
            verify_consistency(
                old_size=3,
                new_size=n,
                old_root=leaf_hash(b"different-root"),
                new_root=tree.root(n),
                proof=proof,
            )

    def test_wrong_proof_length_rejected(self):
        n = 5
        tree = MerkleTree(leaves(n))
        ranges = inclusion_ranges(2, n)
        proof = [tree.range_hash(s, l) for s, l in ranges[:-1]]
        with self.assertRaises(ProofError):
            verify_inclusion(
                record_value=value(2),
                index=2,
                size=n,
                root=tree.root(n),
                proof=proof,
            )


if __name__ == "__main__":
    unittest.main()
