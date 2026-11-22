import json
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


class CliTests(unittest.TestCase):
    def test_native_separator_forwards_flags_and_empty_arguments_verbatim(self):
        from rea_aegis.cli import main

        with patch("rea_aegis.cli.run_native") as run:
            self.assertEqual(
                main(
                    [
                        "run-native",
                        "program.aegis",
                        "--key-file",
                        "master.key",
                        "--",
                        "--key-file",
                        "",
                        "hello",
                    ]
                ),
                0,
            )
        run.assert_called_once_with(
            Path("program.aegis"), Path("master.key"), ["--key-file", "", "hello"]
        )

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)

    def cli(self, *args):
        return subprocess.run(
            [sys.executable, "-m", "rea_aegis", *map(str, args)],
            cwd=ROOT,
            capture_output=True,
            text=True,
            timeout=20,
        )

    def test_real_cli_audit_harden_verify_and_tamper(self):
        source = ROOT / "examples/demo"
        report = self.cli("audit", source, "--format", "json")
        self.assertEqual(report.returncode, 1, report.stderr)
        self.assertTrue(
            any(
                r["rule"] == "embedded-source"
                for r in json.loads(report.stdout)["findings"]
            )
        )
        output = self.root / "protected"
        protected = self.cli("harden", source, output, "--remove-source-maps")
        self.assertEqual(protected.returncode, 0, protected.stderr)
        receipt_hash = json.loads(protected.stdout)["receipt_sha256"]
        checked = self.cli("verify", output, "--receipt-sha256", receipt_hash)
        self.assertEqual(checked.returncode, 0, checked.stderr)
        after = self.cli("audit", output, "--format", "json")
        self.assertEqual(after.returncode, 0, after.stderr)
        self.assertNotIn(
            "embedded-source", [r["rule"] for r in json.loads(after.stdout)["findings"]]
        )
        self.assertIn(
            "source-map-reference",
            [r["rule"] for r in json.loads(after.stdout)["findings"]],
        )
        (output / "main.js").write_text("changed")
        self.assertEqual(self.cli("verify", output).returncode, 2)

    @unittest.skipUnless(
        shutil.which("node"), "Node.js required for the real runtime smoke test"
    )
    def test_real_node_output_before_and_after_is_identical(self):
        source = ROOT / "examples/demo"
        output = self.root / "protected"
        result = self.cli("harden", source, output, "--remove-source-maps")
        self.assertEqual(result.returncode, 0, result.stderr)

        def run(directory):
            return subprocess.run(
                [shutil.which("node"), "main.js"],
                cwd=directory,
                capture_output=True,
                check=True,
                timeout=10,
            ).stdout

        before, after = run(source), run(output)
        self.assertEqual(before, after)
        self.assertEqual(json.loads(after), {"total": 13.5})

    def test_text_report_shows_byte_offset_without_matching_value(self):
        path = self.root / "release.txt"
        marker = "-----BEGIN PRIVATE KEY-----"
        path.write_bytes(b"hi " + marker.encode())
        result = self.cli("audit", path)
        self.assertEqual(result.returncode, 1, result.stderr)
        self.assertIn('"release.txt" (byte 3)', result.stdout)
        self.assertNotIn(marker, result.stdout)

    def test_incomplete_is_distinct_from_no_high_findings(self):
        path = self.root / "file"
        path.write_bytes(b"a" * 10)
        result = self.cli("audit", path, "--max-file-bytes", "1", "--format", "sarif")
        self.assertEqual(result.returncode, 2)
        report = json.loads(result.stdout)
        self.assertFalse(report["runs"][0]["invocations"][0]["executionSuccessful"])

    def test_audit_passes_all_configured_budgets_to_the_report(self):
        result = self.cli(
            "audit",
            ROOT / "examples/demo",
            "--format",
            "json",
            "--max-entries",
            "2",
            "--max-file-bytes",
            "0",
            "--max-total-bytes",
            "0",
            "--max-archive-bytes",
            "30",
            "--max-header-bytes",
            "20",
        )
        self.assertEqual(result.returncode, 2, result.stderr)
        report = json.loads(result.stdout)
        self.assertEqual(report["examined_bytes"], 0)
        self.assertEqual(report["members"], 2)
        self.assertEqual(
            report["limits"],
            {
                "files": 2,
                "file_bytes": 0,
                "total_bytes": 0,
                "archive_bytes": 30,
                "header_bytes": 20,
            },
        )

    def test_invalid_arguments_and_missing_file_are_errors(self):
        self.assertEqual(
            self.cli("audit", self.root, "--max-file-bytes", "-1").returncode, 2
        )
        self.assertEqual(self.cli("audit", self.root / "missing").returncode, 2)
        self.assertEqual(self.cli("harden", self.root, self.root / "out").returncode, 2)

    def test_missing_receipt_and_invalid_json_have_structured_errors(self):
        self.assertEqual(self.cli("verify", self.root).returncode, 2)
        (self.root / ".rea-aegis.json").write_text("{")
        result = self.cli("verify", self.root)
        self.assertEqual(result.returncode, 2)
        self.assertFalse(json.loads(result.stderr)["ok"])

    def test_operator_key_capability_and_client_cli_workflow(self):
        from rea_aegis.gateway import verify_token
        from rea_aegis.protect import read_key

        key = self.root / "operator" / "master.key"
        generated = self.cli("keygen", key)
        self.assertEqual(generated.returncode, 0, generated.stderr)
        issued = self.cli(
            "gateway-token", "--key-file", key, "--subject", "ci-user", "--ttl", "60"
        )
        self.assertEqual(issued.returncode, 0, issued.stderr)
        claims = verify_token(read_key(key), json.loads(issued.stdout)["token"])
        self.assertEqual(claims["sub"], "ci-user")
        client = self.root / "client.mjs"
        exported = self.cli(
            "gateway-client", "https://api.example.com/v1/evaluate", client
        )
        self.assertEqual(exported.returncode, 0, exported.stderr)
        self.assertFalse(json.loads(exported.stdout)["server_logic_shipped"])
        self.assertNotIn(read_key(key).hex(), client.read_text())


if __name__ == "__main__":
    unittest.main()
