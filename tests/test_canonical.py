import json
import unittest

from aolog.canonical import CanonicalJSONError, canonicalize, canonicalize_input


class CanonicalJSONTest(unittest.TestCase):
    def test_sorts_and_normalizes(self):
        self.assertEqual(
            canonicalize_input('{"b":1,"a":[true,null,"é"]}'),
            b'{"a":[true,null,"\xc3\xa9"],"b":1}',
        )

    def test_rejects_duplicate_keys(self):
        with self.assertRaises(CanonicalJSONError):
            canonicalize_input('{"a":1,"a":2}')

    def test_rejects_invalid_utf8_and_surrogates(self):
        with self.assertRaises(UnicodeDecodeError):
            canonicalize_input(b'{"a":"\xff"}')
        with self.assertRaises((UnicodeEncodeError, CanonicalJSONError)):
            canonicalize({"a": "\ud800"})


if __name__ == "__main__":
    unittest.main()
