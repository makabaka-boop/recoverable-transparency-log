import json
import threading
import urllib.error
import urllib.request
import unittest
from unittest import mock

from aolog.client import main
from aolog.server import build_server


class ClientServerTest(unittest.TestCase):
    def setUp(self):
        import tempfile
        self.tempdir = tempfile.TemporaryDirectory()
        self.server = build_server(self.tempdir.name, "127.0.0.1", 0)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        host, port = self.server.server_address
        self.base = f"http://{host}:{port}"

    def tearDown(self):
        self.server.shutdown()
        self.thread.join()
        self.server.store.close()
        self.server.server_close()
        self.tempdir.cleanup()

    def request(self, method, path, body=None):
        data = body if isinstance(body, bytes) or body is None else json.dumps(body).encode()
        req = urllib.request.Request(self.base + path, data=data, method=method)
        if data is not None:
            req.add_header("Content-Type", "application/json")
        try:
            with urllib.request.urlopen(req) as response:
                return response.status, response.read()
        except urllib.error.HTTPError as exc:
            return exc.code, exc.read()

    def test_api_batch_proofs_and_independent_audit_cli(self):
        records = [{"i": i, "kind": "demo", "unicode": "审计"} for i in range(7)]
        status, raw = self.request("POST", "/v1/append",
                                   json.dumps({"records": records}).encode("utf-8"))
        self.assertEqual(status, 200, raw)
        appended = json.loads(raw)
        self.assertEqual(appended["sequence_numbers"], list(range(7)))

        status, head_raw = self.request("GET", "/v1/head")
        self.assertEqual(status, 200)
        self.assertEqual(json.loads(head_raw)["tree_size"], 7)

        status, raw = self.request("GET", "/v1/proof?index=3&size=7")
        self.assertEqual(status, 200)
        self.assertIn("hashes", json.loads(raw))

        status, raw = self.request("GET", "/v1/consistency?old_size=2&new_size=7")
        self.assertEqual(status, 200)
        self.assertIn("hashes", json.loads(raw))

        state = self.tempdir.name + "/audit-state.json"
        self.assertEqual(main(["audit", "--base", self.base, "--state", state]), 0)
        self.assertEqual(main(["audit", "--base", self.base, "--state", state]), 0)
        with open(state, encoding="utf-8") as state_file:
            saved = json.loads(state_file.read())
        self.assertEqual(saved["tree_size"], 7)

        more = [{"i": 10}, {"i": 11}]
        self.request("POST", "/v1/append", json.dumps({"records": more}).encode())
        self.assertEqual(main(["audit", "--base", self.base, "--state", state]), 0)
        with open(state, encoding="utf-8") as state_file:
            saved = json.loads(state_file.read())
        self.assertEqual(saved["tree_size"], 9)

    def test_audit_detects_tampered_record_supplied_by_service(self):
        state = self.tempdir.name + "/audit-state.json"
        self.request("POST", "/v1/append",
                     json.dumps({"records": [{"v": 1}]}).encode())
        self.assertEqual(main(["audit", "--base", self.base, "--state", state]), 0)
        self.request("POST", "/v1/append",
                     json.dumps({"records": [{"v": 2}]}).encode())

        original_request = __import__("aolog.client", fromlist=["_request"])._request

        def malicious_request(base, method, path, body=None):
            status, raw = original_request(base, method, path, body)
            if path == "/v1/records/1":
                raw = b'{"v":999}'
            return status, raw

        with mock.patch("aolog.client._request", malicious_request):
            self.assertEqual(main(["audit", "--base", self.base, "--state", state]), 1)

        # State must not advance after failed verification.
        self.assertEqual(main(["audit", "--base", self.base, "--state", state]), 0)

    def test_bad_proof_size_rejected(self):
        self.request("POST", "/v1/append",
                     json.dumps({"records": [{"x": 1}]}).encode())
        status, raw = self.request("GET", "/v1/proof?index=0&size=99")
        self.assertEqual(status, 400)


if __name__ == "__main__":
    unittest.main()
