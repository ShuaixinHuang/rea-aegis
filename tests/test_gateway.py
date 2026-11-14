import http.client
import json
import os
import secrets
import shutil
import subprocess
import tempfile
import threading
import unittest
from pathlib import Path

from rea_aegis.artifacts import ArtifactError
from rea_aegis.gateway import (
    GatewayServer,
    RequestGuard,
    export_client,
    issue_token,
    verify_token,
    serve,
)


class GatewayTests(unittest.TestCase):
    def test_bad_server_key_fails_before_loading_handler(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            handler, marker = root / "handler.py", root / "executed"
            handler.write_text(
                f'from pathlib import Path\nPath({str(marker)!r}).write_text("executed")\ndef evaluate(value): return value\n'
            )
            with self.assertRaises(OSError):
                serve(root / "missing.key", f"{handler}:evaluate", 8765)
            self.assertFalse(marker.exists())

    def test_short_master_key_is_rejected(self):
        with self.assertRaises(ArtifactError):
            issue_token(b"short", "user")

    def test_capabilities_are_expiring_signed_and_audience_bound(self):
        key = secrets.token_bytes(32)
        token = issue_token(key, "student", ttl=5, now=100)
        self.assertEqual(verify_token(key, token, now=104)["sub"], "student")
        for candidate, secret, now in [
            (token, key, 105),
            (token, secrets.token_bytes(32), 101),
            (token + "x", key, 101),
            (token, key, 99),
        ]:
            with self.assertRaises(ArtifactError):
                verify_token(secret, candidate, now)

    def test_live_replay_records_and_subject_windows_are_never_evicted_for_capacity(
        self,
    ):
        guard = RequestGuard(capacity=2)
        self.assertTrue(guard.claim("a", "1", 100, 1))
        self.assertTrue(guard.claim("b", "2", 100, 1))
        self.assertFalse(guard.claim("c", "3", 100, 2))
        self.assertFalse(guard.claim("a", "1", 100, 2))
        short = RequestGuard(capacity=1)
        self.assertTrue(short.claim("a", "1", 2, 1))
        self.assertFalse(short.claim("b", "2", 100, 3))
        self.assertTrue(short.claim("b", "2", 100, 62))

    def test_rate_limit_is_per_subject(self):
        guard = RequestGuard(requests_per_minute=1)
        self.assertTrue(guard.claim("a", "first", 100, 1))
        self.assertFalse(guard.claim("a", "second", 100, 2))
        self.assertTrue(guard.claim("b", "third", 100, 2))

    def test_client_export_requires_tls_for_external_hosts(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "client.mjs"
            for url in [
                "http://example.com/v1/evaluate",
                "https://user:pass@example.com/",
                "file:///private",
            ]:
                with self.assertRaises(ArtifactError):
                    export_client(url, output)
            export_client("https://api.example.com/v1/evaluate", output)
            self.assertIn("https://api.example.com/v1/evaluate", output.read_text())
            with self.assertRaises(FileExistsError):
                export_client("https://other.example.com/v1/evaluate", output)

    def test_real_http_auth_replay_and_body_limits(self):
        key = secrets.token_bytes(32)
        called = []

        def handler(value):
            called.append(value)
            return {"total": value["amount"] * 7}

        server = GatewayServer(("127.0.0.1", 0), key, handler)
        thread = threading.Thread(target=server.serve_forever)
        thread.start()
        try:

            def request(headers, body):
                conn = http.client.HTTPConnection(*server.server_address, timeout=3)
                try:
                    conn.request("POST", "/v1/evaluate", body, headers)
                    response = conn.getresponse()
                    return response.status, json.loads(response.read())
                finally:
                    conn.close()

            token = issue_token(key, "student")
            headers = {"Authorization": "Bearer " + token}
            data = json.dumps({"nonce": "a" * 32, "input": {"amount": 6}})
            self.assertEqual(request({}, data)[0], 401)
            status, result = request(headers, data)
            self.assertEqual((status, result), (200, {"result": {"total": 42}}))
            self.assertEqual(request(headers, data)[0], 429)
            self.assertEqual(len(called), 1)
            self.assertEqual(request(headers, "x" * 8193)[0], 413)
            self.assertEqual(request(headers, '{"nonce":"a","input":NaN}')[0], 400)
        finally:
            server.shutdown()
            server.server_close()
            thread.join(5)
        self.assertFalse(thread.is_alive())

    @unittest.skipUnless(shutil.which("node"), "Node client runtime required")
    def test_real_generated_client_calls_server_without_shipping_handler_or_key(self):
        key = secrets.token_bytes(32)
        private_rule = "server-only-73491"
        private_policy = {private_rule: 7}

        def evaluate(value):
            return {"result": value * private_policy[private_rule]}

        server = GatewayServer(("127.0.0.1", 0), key, evaluate)
        thread = threading.Thread(target=server.serve_forever)
        thread.start()
        try:
            with tempfile.TemporaryDirectory() as directory:
                output = Path(directory) / "client.mjs"
                export_client(
                    f"http://127.0.0.1:{server.server_address[1]}/v1/evaluate", output
                )
                code = output.read_text()
                self.assertNotIn(private_rule, code)
                self.assertNotIn(key.hex(), code)
                token = issue_token(key, "test")
                program = 'import {evaluate} from "./client.mjs"; console.log(JSON.stringify(await evaluate(6)));'
                result = subprocess.run(
                    [shutil.which("node"), "--input-type=module", "-e", program],
                    cwd=directory,
                    env={**os.environ, "REA_AEGIS_TOKEN": token},
                    capture_output=True,
                    text=True,
                    timeout=15,
                )
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(json.loads(result.stdout), {"result": 42})
        finally:
            server.shutdown()
            server.server_close()
            thread.join(5)
