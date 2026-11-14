"""Key-separated JS and Linux ELF protection. Keys stay outside release output."""

from __future__ import annotations

import base64
import hashlib
import json
import os
import re
import secrets
import shutil
import stat
import subprocess
import sys
from pathlib import Path

from .artifacts import ArtifactError, parse_json, regular_file
from .harden import canonical

PAYLOAD_BYTES = 16 * 1024 * 1024
ENVELOPE_BYTES = 24 * 1024 * 1024
RUNTIME = Path(__file__).parent / "assets" / "crypto.cjs"


def keygen(path: Path) -> dict:
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    with os.fdopen(
        os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), "wb"
    ) as output:
        output.write(secrets.token_bytes(32))
    return {"key_file": str(path), "bytes": 32}


def read_key(path: Path) -> bytes:
    with regular_file(path) as source:
        if os.name != "nt" and os.fstat(source.fileno()).st_mode & 0o077:
            raise ArtifactError("Key file must have owner-only permissions (chmod 600)")
        key = source.read(33)
    if len(key) != 32:
        raise ArtifactError("A protection key must contain exactly 32 raw bytes")
    return key


def crypto_operation(request: dict, key: bytes) -> bytes:
    node = shutil.which("node")
    if node is None:
        raise ArtifactError("Node.js 20+ is required for authenticated protection")
    try:
        version = subprocess.run(
            [node, "--version"], capture_output=True, timeout=5, check=True
        )
    except (subprocess.SubprocessError, OSError) as error:
        raise ArtifactError("Could not identify the Node.js crypto runtime") from error
    match = re.fullmatch(rb"v([0-9]+)\.[0-9]+\.[0-9]+\s*", version.stdout)
    if match is None or int(match[1]) < 20:
        raise ArtifactError("Node.js 20+ is required for authenticated protection")
    # Keys go over the private stdin pipe, never command-line arguments or logs.
    data = canonical({**request, "key": base64.b64encode(key).decode("ascii")})
    try:
        result = subprocess.run(
            [node, str(RUNTIME)], input=data, capture_output=True, timeout=30
        )
    except subprocess.TimeoutExpired as error:
        raise ArtifactError("Authenticated protection operation timed out") from error
    if result.returncode:
        raise ArtifactError(
            "Authenticated protection failed: check the key and envelope"
        )
    return result.stdout


def protect(source: Path, output: Path, key_file: Path, kind: str) -> dict:
    if key_file.resolve().is_relative_to(output.parent.resolve()):
        raise ArtifactError("Keep the key outside the release output directory")
    key = read_key(key_file)
    with regular_file(source) as stream:
        data = stream.read(PAYLOAD_BYTES + 1)
        mode = stat.S_IMODE(os.fstat(stream.fileno()).st_mode) & 0o777
    if len(data) > PAYLOAD_BYTES:
        raise ArtifactError("Payload exceeds the 16 MiB protection limit")
    if kind == "commonjs":
        if output.suffix.lower() != ".cjs":
            raise ArtifactError(
                "Use a .cjs output so package-level ESM settings cannot change loader semantics"
            )
        data.decode("utf-8", errors="strict")
        if source.suffix.lower() not in (".js", ".cjs"):
            raise ArtifactError("Bundle JS/TS into CommonJS .cjs/.js before protection")
    elif kind == "linux-elf":
        if len(data) < 52 or data[:4] != b"\x7fELF" or data[4] not in (1, 2):
            raise ArtifactError("Native protection requires a Linux ELF payload")
    else:
        raise ArtifactError("Unknown protection kind")
    metadata = {"format": "rea-aegis/envelope/v1", "kind": kind, "name": source.name}
    raw = crypto_operation(
        {
            "operation": "encrypt",
            "metadata": metadata,
            "plaintext": base64.b64encode(data).decode("ascii"),
        },
        key,
    )
    envelope = parse_json(raw)
    if kind == "commonjs":
        runtime = RUNTIME.read_text()
        loader = """
const fs = require("node:fs");
const keyPath = process.env.REA_AEGIS_KEY_FILE;
if (!keyPath) throw new Error("Set REA_AEGIS_KEY_FILE to an external 32-byte key file");
const before = fs.lstatSync(keyPath);
if (!before.isFile() || (process.platform !== "win32" && (before.mode & 0o077))) {
  throw new Error("Use a regular owner-only key file");
}
const fd = fs.openSync(keyPath, fs.constants.O_RDONLY | (fs.constants.O_NOFOLLOW || 0));
let key;
try {
  const opened = fs.fstatSync(fd);
  if (opened.dev !== before.dev || opened.ino !== before.ino || opened.size !== 32) {
    throw new Error("Key file changed or has an invalid size");
  }
  key = Buffer.alloc(32);
  let offset = 0;
  while (offset < 32) {
    const count = fs.readSync(fd, key, offset, 32 - offset, null);
    if (!count) throw new Error("Key file is truncated");
    offset += count;
  }
} finally { fs.closeSync(fd); }
let plaintext;
try { plaintext = runtime.decrypt(envelope, key, "commonjs"); }
finally { key.fill(0); }
try { module._compile(plaintext.toString("utf8"), __filename); }
finally { plaintext.fill(0); }
"""
        # Isolated module scope prevents the helper CLI from running in the loader.
        payload = (
            '"use strict";\nconst runtime = (() => { const module = {exports:{}};\n'
            + runtime
            + "\nreturn module.exports; })();\nconst envelope = "
            + json.dumps(envelope, ensure_ascii=True)
            + ";\n"
            + loader
        ).encode()
    else:
        payload = canonical(envelope)
    with os.fdopen(
        os.open(output, os.O_WRONLY | os.O_CREAT | os.O_EXCL, mode or 0o600), "wb"
    ) as destination:
        destination.write(payload)
    return {
        "output": str(output),
        "kind": kind,
        "algorithm": "AES-256-GCM/HKDF-SHA256",
        "bytes": len(payload),
        "sha256": hashlib.sha256(payload).hexdigest(),
        "key_embedded": False,
    }


def run_native(path: Path, key_file: Path, arguments: list[str]) -> None:
    if not sys.platform.startswith("linux") or not hasattr(os, "memfd_create"):
        raise ArtifactError("In-memory ELF launch requires Linux memfd support")
    with regular_file(path) as stream:
        raw = stream.read(ENVELOPE_BYTES + 1)
    if len(raw) > ENVELOPE_BYTES:
        raise ArtifactError("Native envelope exceeds 24 MiB")
    envelope = parse_json(raw)
    plaintext = crypto_operation(
        {"operation": "decrypt", "envelope": envelope, "kind": "linux-elf"},
        read_key(key_file),
    )
    if len(plaintext) > PAYLOAD_BYTES or plaintext[:4] != b"\x7fELF":
        raise ArtifactError("Authenticated payload is not an admitted ELF")
    descriptor = os.memfd_create("rea-aegis", os.MFD_CLOEXEC)
    try:
        with os.fdopen(os.dup(descriptor), "wb") as stream:
            stream.write(plaintext)
        os.fchmod(descriptor, 0o700)
        executable = f"/proc/self/fd/{descriptor}"
        os.stat(executable)
        os.execve(executable, [str(path), *arguments], dict(os.environ))
    finally:
        os.close(descriptor)
