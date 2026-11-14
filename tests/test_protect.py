import base64
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from rea_aegis.artifacts import ArtifactError
from rea_aegis.protect import RUNTIME, crypto_operation, keygen, protect, read_key

ROOT = Path(__file__).resolve().parents[1]


@unittest.skipUnless(shutil.which("node"), "Node crypto runtime required")
class ProtectionTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.release = self.root / "release"
        self.release.mkdir()
        self.key = self.root / "operator" / "master.key"
        keygen(self.key)

    def test_real_commonjs_exports_and_output_survive_encryption(self):
        source = self.root / "module.cjs"
        source.write_text('module.exports = x => "private-rule-73491:" + (x * 7);')
        output = self.release / "protected.cjs"
        protected = subprocess.run(
            [
                sys.executable,
                "-m",
                "rea_aegis",
                "protect-js",
                str(source),
                str(output),
                "--key-file",
                str(self.key),
            ],
            cwd=ROOT,
            capture_output=True,
            text=True,
            timeout=15,
        )
        self.assertEqual(protected.returncode, 0, protected.stderr)
        report = json.loads(protected.stdout)
        published = output.read_bytes()
        self.assertNotIn(b"private-rule-73491", published)
        self.assertNotIn(base64.b64encode(read_key(self.key)), published)
        self.assertFalse(report["key_embedded"])
        result = subprocess.run(
            [
                shutil.which("node"),
                "-e",
                "console.log(require(process.argv[1])(6))",
                str(output),
            ],
            env={**os.environ, "REA_AEGIS_KEY_FILE": str(self.key)},
            capture_output=True,
            text=True,
            timeout=10,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout.strip(), "private-rule-73491:42")

    def test_missing_and_wrong_key_do_not_run_the_application(self):
        source = self.root / "main.cjs"
        source.write_text('console.log("application-executed");')
        output = self.release / "protected.cjs"
        protect(source, output, self.key, "commonjs")
        wrong = self.root / "wrong.key"
        keygen(wrong)
        for env in [
            {k: v for k, v in os.environ.items() if k != "REA_AEGIS_KEY_FILE"},
            {**os.environ, "REA_AEGIS_KEY_FILE": str(wrong)},
        ]:
            result = subprocess.run(
                [shutil.which("node"), str(output)],
                env=env,
                capture_output=True,
                timeout=10,
            )
            self.assertNotEqual(result.returncode, 0)
            self.assertNotIn(b"application-executed", result.stdout)

    def test_tamper_and_cross_purpose_fail_before_plaintext_output(self):
        source = self.root / "source.cjs"
        source.write_text('module.exports = "hidden";')
        key = read_key(self.key)
        encoded = crypto_operation(
            {
                "operation": "encrypt",
                "metadata": {
                    "format": "rea-aegis/envelope/v1",
                    "kind": "commonjs",
                    "name": "input",
                },
                "plaintext": base64.b64encode(source.read_bytes()).decode(),
            },
            key,
        )
        envelope = json.loads(encoded)
        with self.assertRaises(ArtifactError):
            crypto_operation(
                {"operation": "decrypt", "kind": "linux-elf", "envelope": envelope}, key
            )
        data = bytearray(base64.b64decode(envelope["ciphertext"]))
        data[0] ^= 1
        envelope["ciphertext"] = base64.b64encode(data).decode()
        with self.assertRaises(ArtifactError):
            crypto_operation(
                {"operation": "decrypt", "kind": "commonjs", "envelope": envelope}, key
            )
        result = subprocess.run(
            [shutil.which("node"), str(RUNTIME)],
            input=json.dumps(
                {
                    "operation": "decrypt",
                    "kind": "commonjs",
                    "envelope": envelope,
                    "key": base64.b64encode(key).decode(),
                }
            ).encode(),
            capture_output=True,
            timeout=10,
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(result.stdout, b"")

    def test_key_separation_and_no_overwrite(self):
        source = self.root / "input.cjs"
        source.write_text("module.exports = 42;")
        output = self.release / "protected.cjs"
        bad_key = self.release / "embedded.key"
        keygen(bad_key)
        with self.assertRaises(ArtifactError):
            protect(source, output, bad_key, "commonjs")
        protect(source, output, self.key, "commonjs")
        before = output.read_bytes()
        with self.assertRaises(FileExistsError):
            protect(source, output, self.key, "commonjs")
        self.assertEqual(output.read_bytes(), before)
        with self.assertRaises(FileExistsError):
            keygen(self.key)

    def test_protection_parses_without_executing_source_and_refuses_esm(self):
        source = self.root / "input.cjs"
        source.write_text('throw new Error("must not execute during encryption");')
        protect(source, self.release / "throw.cjs", self.key, "commonjs")
        source.write_text("export const value = 42;")
        with self.assertRaises(ArtifactError):
            protect(source, self.release / "esm.cjs", self.key, "commonjs")
        self.assertFalse((self.release / "esm.cjs").exists())

    @unittest.skipUnless(
        sys.platform.startswith("linux") and shutil.which("cc"),
        "Linux C producer required",
    )
    def test_real_elf_encrypts_and_runs_from_memory_with_arguments(self):
        code = self.root / "owned.c"
        code.write_text(
            '#include <stdio.h>\nint main(int n,char**v){printf("native-rule-73491:%s\\n",n>1?v[1]:"none");return 0;}'
        )
        binary, output = self.root / "owned", self.release / "owned.aegis"
        subprocess.run(
            [shutil.which("cc"), str(code), "-o", str(binary)], check=True, timeout=20
        )
        protect(binary, output, self.key, "linux-elf")
        self.assertNotIn(b"native-rule-73491", output.read_bytes())
        result = subprocess.run(
            [
                sys.executable,
                "-m",
                "rea_aegis",
                "run-native",
                str(output),
                "--key-file",
                str(self.key),
                "--",
                "hello",
            ],
            cwd=ROOT,
            capture_output=True,
            text=True,
            timeout=15,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout.strip(), "native-rule-73491:hello")
