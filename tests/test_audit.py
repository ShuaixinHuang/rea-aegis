import json
import os
import struct
import tempfile
import unittest
import warnings
import zipfile
from dataclasses import replace
from pathlib import Path

from rea_aegis.artifacts import Limits
from rea_aegis.audit import audit, exit_status, sarif


def source_map():
    return json.dumps(
        {
            "version": 3,
            "sources": ["private.ts"],
            "mappings": "AAAA",
            "sourcesContent": ["export const algorithm = 42;"],
        }
    ).encode()


def asar(tree, payload=b""):
    text = json.dumps(tree).encode()
    padding = b"\0" * (-len(text) % 4)
    inner = 4 + len(text) + len(padding)
    return struct.pack("<4I", 4, inner + 4, inner, len(text)) + text + padding + payload


class AuditTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)

    def test_embedded_sources_and_reference_are_separate_evidence(self):
        (self.root / "main.js.map").write_bytes(source_map())
        (self.root / "main.js").write_text(
            "console.log(42);\n//# sourceMappingURL=main.js.map\n"
        )
        report = audit(self.root)
        self.assertEqual(report["coverage"], "complete")
        self.assertEqual(
            {r["rule"] for r in report["findings"]},
            {"source-map", "embedded-source", "source-map-reference"},
        )
        self.assertEqual(exit_status(report, "high"), 1)

    def test_sensitive_matches_never_enter_json_or_sarif(self):
        secret = "ghp_" + "a" * 36
        (self.root / "config").write_text(secret + "\n-----BEGIN PRIVATE KEY-----\n")
        report = audit(self.root)
        for encoded in [json.dumps(report), json.dumps(sarif(report))]:
            self.assertNotIn(secret, encoded)
            self.assertNotIn("BEGIN PRIVATE KEY", encoded)
        self.assertEqual(
            {r["rule"] for r in report["findings"]},
            {"credential-candidate", "private-key"},
        )

    def test_nonstandard_or_duplicate_json_is_not_admitted_as_a_map(self):
        path = self.root / "bad.map"
        for data in [
            b'{"version":3,"mappings":"","extra":NaN}',
            b'{"version":3,"version":3,"mappings":""}',
        ]:
            path.write_bytes(data)
            report = audit(path)
            self.assertEqual(report["coverage"], "partial")
            self.assertNotIn("source-map", [row["rule"] for row in report["findings"]])

    def test_partial_scan_cannot_pass_ci_even_without_findings(self):
        (self.root / "large").write_bytes(b"a" * 100)
        report = audit(self.root, replace(Limits(), file_bytes=3))
        self.assertEqual(report["examined_bytes"], 3)
        self.assertEqual(report["coverage"], "partial")
        self.assertEqual(exit_status(report, "critical"), 2)

    def test_total_budget_is_shared_by_members(self):
        for name in ("a", "b", "c"):
            (self.root / name).write_bytes(b"x" * 20)
        report = audit(self.root, replace(Limits(), total_bytes=25))
        self.assertEqual(report["examined_bytes"], 25)
        self.assertEqual(report["coverage"], "partial")

    def test_hidden_environment_file_is_not_ignored(self):
        (self.root / ".env").write_text("HOST=localhost\n")
        (self.root / ".env.example").write_text("HOST=localhost\n")
        rows = [
            r for r in audit(self.root)["findings"] if r["rule"] == "environment-file"
        ]
        self.assertEqual([r["path"] for r in rows], [".env"])

    def test_duplicate_zip_names_keep_both_occurrences(self):
        path = self.root / "app.zip"
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", UserWarning)
            with zipfile.ZipFile(path, "w") as z:
                z.writestr("app.js.map", b"{}")
                z.writestr("app.js.map", source_map())
        report = audit(path)
        self.assertEqual(report["members"], 2)
        self.assertTrue(
            any(
                r["rule"] == "embedded-source" and r["path"].startswith("zip[1]")
                for r in report["findings"]
            )
        )
        self.assertEqual(report["coverage"], "partial")

    def test_zip_directory_is_admitted_before_library_expansion(self):
        path = self.root / "many.zip"
        with zipfile.ZipFile(path, "w") as z:
            z.writestr("a", "")
            z.writestr("b", "")
        report = audit(path, replace(Limits(), files=1))
        self.assertEqual(report["members"], 0)
        self.assertTrue(report["errors"])

    def test_zip_end_record_cannot_underdeclare_actual_member_count(self):
        path = self.root / "underdeclared.zip"
        with zipfile.ZipFile(path, "w") as z:
            z.writestr("a", "")
            z.writestr("b", "")
        data = bytearray(path.read_bytes())
        struct.pack_into("<HH", data, len(data) - 22 + 8, 1, 1)
        path.write_bytes(data)
        report = audit(path)
        self.assertEqual(report["members"], 0)
        self.assertTrue(report["errors"])

    def test_invalid_zip_and_nested_archive_are_explicitly_incomplete(self):
        path = self.root / "bad.zip"
        path.write_bytes(b"not a zip")
        self.assertEqual(exit_status(audit(path), "critical"), 2)
        with zipfile.ZipFile(path, "w") as z:
            z.writestr("nested.zip", b"PK\x03\x04")
        report = audit(path)
        self.assertEqual(report["coverage"], "partial")
        self.assertTrue(any(r["rule"] == "nested-archive" for r in report["findings"]))

    def test_zip_crc_failure_is_a_structured_incomplete_result(self):
        path = self.root / "broken.zip"
        with zipfile.ZipFile(path, "w", compression=zipfile.ZIP_STORED) as z:
            z.writestr("payload", "original")
        data = bytearray(path.read_bytes())
        payload = data.index(b"original")
        data[payload] = ord("X")
        path.write_bytes(data)
        report = audit(path)
        self.assertTrue(report["errors"])
        self.assertEqual(report["coverage"], "partial")

    def test_zip_symlink_is_not_read(self):
        path = self.root / "link.zip"
        link = zipfile.ZipInfo("secret")
        link.create_system = 3
        link.external_attr = 0o120777 << 16
        with zipfile.ZipFile(path, "w") as z:
            z.writestr(link, "../../secret")
        report = audit(path)
        self.assertEqual(report["examined_bytes"], 0)
        self.assertEqual(report["coverage"], "partial")

    def test_asar_file_range_and_unpacked_coverage(self):
        data = source_map()
        path = self.root / "app.asar"
        path.write_bytes(
            asar(
                {
                    "files": {
                        "main.js.map": {"offset": "0", "size": len(data)},
                        "native.node": {"size": 4, "unpacked": True},
                    }
                },
                data,
            )
        )
        report = audit(path)
        self.assertEqual(report["members"], 2)
        self.assertEqual(report["coverage"], "partial")
        self.assertTrue(any(r["rule"] == "embedded-source" for r in report["findings"]))

    def test_asar_out_of_bounds_and_unsafe_name_are_rejected(self):
        path = self.root / "app.asar"
        for tree in [
            {"files": {"a": {"offset": "0", "size": 1}}},
            {"files": {"../a": {"offset": "0", "size": 0}}},
            {"size": 0, "offset": "0"},
            {"files": {}, "link": "elsewhere"},
        ]:
            path.write_bytes(asar(tree))
            report = audit(path)
            self.assertTrue(report["errors"])
            self.assertEqual(report["coverage"], "partial")

    @unittest.skipIf(os.name == "nt", "Requires POSIX symlink creation")
    def test_directory_links_are_not_followed(self):
        with tempfile.TemporaryDirectory() as outside:
            (Path(outside) / "private").write_text("-----BEGIN PRIVATE KEY-----")
            (self.root / "link").symlink_to(outside, target_is_directory=True)
            report = audit(self.root)
        self.assertEqual(report["examined_bytes"], 0)
        self.assertEqual(report["coverage"], "partial")

    def test_sarif_escapes_artifact_names(self):
        (self.root / "a #.ts").write_text("const n = 1;")
        report = sarif(audit(self.root))
        uri = report["runs"][0]["results"][0]["locations"][0]["physicalLocation"][
            "artifactLocation"
        ]["uri"]
        self.assertEqual(uri, "a%20%23.ts")


if __name__ == "__main__":
    unittest.main()
