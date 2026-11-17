import tempfile
import unittest
from contextlib import contextmanager
from pathlib import Path
from unittest.mock import patch

from rea_aegis.artifacts import ArtifactError, Limits, directory_members
from rea_aegis.audit import audit, exit_status


class LimitTests(unittest.TestCase):
    def test_limits_reject_values_that_could_disable_read_bounds(self):
        for name in Limits.__dataclass_fields__:
            for value in (-1, True, 1.5, "10", None):
                with self.subTest(name=name, value=value):
                    with self.assertRaisesRegex(ArtifactError, name):
                        Limits(**{name: value})

    def test_zero_limits_support_inventory_only_reads(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "file").write_bytes(b"payload")
            rows = list(directory_members(root, Limits(file_bytes=0, total_bytes=0)))
            self.assertEqual([(row.size, row.data) for row in rows], [(7, b"")])

    def test_oversized_directory_stops_enumeration_and_closes_scandir(self):
        consumed = []
        closed = []

        @contextmanager
        def scandir(_path):
            def entries():
                for index in range(1000):
                    consumed.append(index)
                    yield object()

            try:
                yield entries()
            finally:
                closed.append(True)

        with tempfile.TemporaryDirectory() as directory:
            with patch("rea_aegis.artifacts.os.scandir", scandir):
                report = audit(Path(directory), Limits(files=3))
        self.assertEqual(len(consumed), 4)
        self.assertEqual(closed, [True])
        self.assertEqual(report["members"], 0)
        self.assertEqual(exit_status(report, "critical"), 2)
        self.assertIn("Entry limit exceeded (3)", report["errors"])

    def test_entry_budget_is_shared_across_directories(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "nested").mkdir()
            (root / "nested" / "child").touch()
            (root / "top").touch()
            report = audit(root, Limits(files=2))
            self.assertEqual(exit_status(report, "critical"), 2)
            rows = list(directory_members(root, Limits(files=3)))
            self.assertEqual(
                [row.path for row in rows], ["nested", "top", "nested/child"]
            )

    def test_zero_entry_budget_accepts_only_empty_directories(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self.assertEqual(list(directory_members(root, Limits(files=0))), [])
            (root / "file").touch()
            with self.assertRaises(ArtifactError):
                list(directory_members(root, Limits(files=0)))
