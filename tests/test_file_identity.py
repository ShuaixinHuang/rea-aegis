import os
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from rea_aegis.artifacts import ArtifactError, regular_file


class FileIdentityTests(unittest.TestCase):
    def test_path_and_handle_timestamps_are_tracked_in_their_own_representation(self):
        with tempfile.TemporaryDirectory() as root:
            path = Path(root) / "file"
            path.write_bytes(b"selected")
            original = os.fstat

            def different_time(fd):
                row = original(fd)
                values = {
                    key: getattr(row, key)
                    for key in (
                        "st_dev",
                        "st_ino",
                        "st_size",
                        "st_mode",
                        "st_mtime_ns",
                        "st_ctime_ns",
                    )
                }
                values["st_ctime_ns"] += 1234
                return SimpleNamespace(**values)

            with patch("rea_aegis.artifacts.os.fstat", side_effect=different_time):
                with regular_file(path) as stream:
                    self.assertEqual(stream.read(), b"selected")

    def test_changed_descriptor_is_still_rejected(self):
        with tempfile.TemporaryDirectory() as root:
            path = Path(root) / "file"
            path.write_bytes(b"selected")
            with self.assertRaises(ArtifactError):
                with regular_file(path) as stream:
                    self.assertEqual(stream.read(), b"selected")
                    path.write_bytes(b"changed contents")

    def test_foreign_handle_is_refused_before_any_read(self):
        with tempfile.TemporaryDirectory() as root:
            path, other = Path(root) / "selected", Path(root) / "other"
            path.write_bytes(b"selected")
            other.write_bytes(b"foreign!")
            original = os.open
            with patch(
                "rea_aegis.artifacts.os.open",
                side_effect=lambda _path, flags: original(other, flags),
            ):
                with self.assertRaises(ArtifactError):
                    with regular_file(path):
                        self.fail("Foreign handle must not reach its consumer")
