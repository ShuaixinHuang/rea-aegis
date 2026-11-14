import json
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


class CliTests(unittest.TestCase):
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

    def test_incomplete_is_distinct_from_no_high_findings(self):
        path = self.root / "file"
        path.write_bytes(b"a" * 10)
        result = self.cli("audit", path, "--max-file-bytes", "1", "--format", "sarif")
        self.assertEqual(result.returncode, 2)
        report = json.loads(result.stdout)
        self.assertFalse(report["runs"][0]["invocations"][0]["executionSuccessful"])

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


if __name__ == "__main__":
    unittest.main()
