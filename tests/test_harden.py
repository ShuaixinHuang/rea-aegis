import hashlib
import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from rea_aegis.artifacts import ArtifactError, Limits
from rea_aegis.harden import RECEIPT, canonical, harden, verify


class HardenTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.source, self.output = self.root / "input", self.root / "output"
        self.source.mkdir()
        (self.source / "main.js").write_text("console.log(42);\n")
        (self.source / "main.js.map").write_text(
            json.dumps({"version": 3, "mappings": ""})
        )

    def harden(self):
        return harden(self.source, self.output, remove_maps=True)

    def test_copy_removes_only_opted_in_map_and_preserves_input(self):
        result = self.harden()
        self.assertEqual(result["removed_files"], 1)
        self.assertEqual(
            (self.output / "main.js").read_bytes(),
            (self.source / "main.js").read_bytes(),
        )
        self.assertTrue((self.source / "main.js.map").exists())
        self.assertFalse((self.output / "main.js.map").exists())
        self.assertTrue(verify(self.output, result["receipt_sha256"])["receipt_pinned"])

    def test_explicit_omit_is_exact_not_glob(self):
        (self.source / ".env").write_text("HOST=localhost")
        result = harden(self.source, self.output, omit=[".env"])
        self.assertEqual(result["removed_files"], 1)
        self.assertTrue((self.output / "main.js.map").exists())

    def test_empty_directories_are_preserved_and_verified(self):
        (self.source / "cache" / "empty").mkdir(parents=True)
        self.harden()
        self.assertTrue((self.output / "cache/empty").is_dir())
        (self.output / "cache/empty").rmdir()
        with self.assertRaises(ArtifactError):
            verify(self.output)

    def test_no_overwrite_or_nested_output(self):
        self.output.mkdir()
        (self.output / "sentinel").write_text("original")
        with self.assertRaises(FileExistsError):
            self.harden()
        self.assertEqual((self.output / "sentinel").read_text(), "original")
        for output in [self.source, self.source / "nested", self.root]:
            with self.assertRaises(ArtifactError):
                harden(self.source, output, remove_maps=True)

    def test_hardening_at_entry_limit_allows_one_generated_receipt(self):
        def tiny_limits(**kwargs):
            return Limits(**({"files": 2} | kwargs))

        (self.source / "main.js.map").rename(self.source / "metadata.json")
        with patch("rea_aegis.harden.Limits", side_effect=tiny_limits):
            result = self.harden()
            self.assertEqual(result["kept_files"], 2)
            self.assertTrue(verify(self.output, result["receipt_sha256"])["ok"])
            (self.source / ".env").write_text("HOST=localhost")
            with self.assertRaisesRegex(ArtifactError, "Entry limit"):
                harden(self.source, self.root / "extra", omit=[".env"])

    def test_reserved_receipt_directory_is_rejected_before_copying(self):
        (self.source / RECEIPT).mkdir()
        with patch("rea_aegis.harden.file_digest") as digest:
            with self.assertRaisesRegex(ArtifactError, "reserved receipt path"):
                self.harden()
        digest.assert_not_called()
        self.assertFalse(self.output.exists())

    def test_uninterpretable_maps_are_not_deleted_by_suffix(self):
        (self.source / "main.js.map").write_text("runtime lookup table")
        with self.assertRaises(ArtifactError):
            self.harden()
        self.assertFalse(self.output.exists())

    def test_reproducible_receipt_without_ambient_paths_or_timestamps(self):
        first = self.harden()
        other = self.root / "other"
        second = harden(self.source, other, remove_maps=True)
        self.assertEqual(first["receipt_sha256"], second["receipt_sha256"])
        self.assertNotIn(str(self.root), (other / RECEIPT).read_text())

    def test_modified_missing_or_unexpected_files_fail(self):
        self.harden()
        original = (self.output / "main.js").read_bytes()
        (self.output / "main.js").write_bytes(b"tampered")
        with self.assertRaises(ArtifactError):
            verify(self.output)
        (self.output / "main.js").write_bytes(original)
        (self.output / "extra").write_bytes(b"")
        with self.assertRaises(ArtifactError):
            verify(self.output)
        (self.output / "extra").unlink()
        (self.output / "main.js").unlink()
        with self.assertRaises(ArtifactError):
            verify(self.output)

    def test_receipt_is_not_its_own_trust_anchor(self):
        result = self.harden()
        value = json.loads((self.output / RECEIPT).read_bytes())
        replacement = b"tampered"
        (self.output / "main.js").write_bytes(replacement)
        value["files"][0].update(
            sha256=hashlib.sha256(replacement).hexdigest(), bytes=len(replacement)
        )
        (self.output / RECEIPT).write_bytes(canonical(value))
        self.assertTrue(verify(self.output)["ok"])
        with self.assertRaises(ArtifactError):
            verify(self.output, result["receipt_sha256"])

    def test_receipt_paths_cannot_escape_output(self):
        self.harden()
        value = json.loads((self.output / RECEIPT).read_text())
        for path in ["../secret", "/absolute", "a/../b", "a\\b", "C:/file", "a//b"]:
            value["files"][0]["path"] = path
            (self.output / RECEIPT).write_bytes(canonical(value))
            with self.assertRaises(ArtifactError):
                verify(self.output)

    def test_oversized_receipt_is_rejected_before_copying(self):
        with patch("rea_aegis.harden.RECEIPT_LIMIT", 10):
            with self.assertRaisesRegex(ArtifactError, "Receipt exceeds"):
                self.harden()
        self.assertFalse(self.output.exists())

    def test_hardening_does_not_return_a_digest_for_a_replaced_receipt(self):
        def replace_and_verify(root):
            path = root / RECEIPT
            path.write_bytes(path.read_bytes() + b" ")
            return verify(root)

        with patch("rea_aegis.harden.verify", side_effect=replace_and_verify):
            with self.assertRaisesRegex(ArtifactError, "Receipt changed"):
                self.harden()
        self.assertFalse(self.output.exists())

    def test_copy_failure_removes_only_new_output(self):
        from rea_aegis.harden import file_digest

        def fail_copy(path, destination=None):
            if destination is not None:
                raise OSError("controlled write failure")
            return file_digest(path)

        with patch("rea_aegis.harden.file_digest", side_effect=fail_copy):
            with self.assertRaises(OSError):
                self.harden()
        self.assertFalse(self.output.exists())
        self.assertTrue((self.source / "main.js").exists())

    def test_source_map_changed_after_hash_is_not_silently_removed(self):
        from rea_aegis.harden import file_digest

        changed = False

        def replace_after_hash(path, destination=None):
            nonlocal changed
            result = file_digest(path, destination)
            if path.name.endswith(".map") and not changed:
                changed = True
                path.write_text(json.dumps({"version": 3, "mappings": "AAAA"}))
            return result

        with patch("rea_aegis.harden.file_digest", side_effect=replace_after_hash):
            with self.assertRaisesRegex(ArtifactError, "changed while classifying"):
                self.harden()
        self.assertFalse(self.output.exists())

    @unittest.skipIf(os.name == "nt", "POSIX executable mode")
    def test_executable_mode_is_preserved_and_checked(self):
        (self.source / "main.js").chmod(0o755)
        self.harden()
        self.assertTrue(os.access(self.output / "main.js", os.X_OK))
        (self.output / "main.js").chmod(0o644)
        with self.assertRaises(ArtifactError):
            verify(self.output)

    @unittest.skipIf(os.name == "nt", "Requires POSIX symlink creation")
    def test_link_input_is_refused_even_when_omitted(self):
        (self.source / "link").symlink_to("main.js")
        with self.assertRaises(ArtifactError):
            harden(self.source, self.output, omit=["link"])
        self.assertFalse(self.output.exists())


if __name__ == "__main__":
    unittest.main()
