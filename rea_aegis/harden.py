"""Explicit directory-copy hardening with externally pinnable hash receipts."""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import stat
from pathlib import Path, PurePosixPath

from . import __version__
from .artifacts import (
    ArtifactError,
    Limits,
    directory_members,
    regular_file,
    parse_json,
)
from .audit import source_map

RECEIPT = ".rea-aegis.json"
RECEIPT_LIMIT = 4 * 1024 * 1024


def canonical(value: object) -> bytes:
    return (
        json.dumps(
            value,
            ensure_ascii=True,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        )
        + "\n"
    ).encode()


def safe_relative(value: str) -> str:
    if (
        not value
        or "\\" in value
        or ":" in value
        or "\0" in value
        or any(part in ("", ".", "..") for part in value.split("/"))
        or PurePosixPath(value).is_absolute()
    ):
        raise ArtifactError(f"Not a portable relative file path: {value!r}")
    return value


def file_digest(path: Path, destination: Path | None = None) -> dict:
    digest = hashlib.sha256()
    size = 0
    with regular_file(path) as source:
        mode = stat.S_IMODE(os.fstat(source.fileno()).st_mode) & 0o777
        output = None
        try:
            if destination is not None:
                destination.parent.mkdir(parents=True, exist_ok=True)
                output = destination.open("xb")
            while chunk := source.read(1024 * 1024):
                size += len(chunk)
                digest.update(chunk)
                if output is not None:
                    output.write(chunk)
        finally:
            if output is not None:
                output.close()
        if destination is not None:
            destination.chmod(mode)
    return {
        "sha256": digest.hexdigest(),
        "bytes": size,
        "executable": bool(mode & 0o111),
    }


def tree_inventory(
    root: Path, *, includes_receipt: bool = False
) -> tuple[list[str], list[str]]:
    paths, directories = [], []
    # Only inventory here; byte hashing/copying is streamed separately.
    defaults = Limits()
    limits = Limits(
        files=defaults.files + int(includes_receipt), file_bytes=0, total_bytes=0
    )
    for item in directory_members(root, limits):
        if item.kind == "directory":
            directories.append(safe_relative(item.path))
            continue
        if item.kind != "file":
            raise ArtifactError(
                f"Hardening/verification refuses {item.kind}: {item.path}"
            )
        paths.append(safe_relative(item.path))
    return sorted(paths), sorted(directories)


def harden(
    source: Path,
    output: Path,
    *,
    remove_maps: bool = False,
    omit: list[str] | None = None,
) -> dict:
    if not remove_maps and not omit:
        raise ArtifactError(
            "Select --remove-source-maps or at least one explicit --omit file"
        )
    source, output = source.absolute(), output.absolute()
    if source.is_symlink() or not source.is_dir():
        raise ArtifactError(
            "Hardening requires a regular directory, not a symlink/archive"
        )
    # Resolve existing parents before deciding containment, including parent aliases.
    resolved_source, resolved_output = source.resolve(), output.resolve()
    if resolved_output.is_relative_to(
        resolved_source
    ) or resolved_source.is_relative_to(resolved_output):
        raise ArtifactError("Input and output must be disjoint directories")
    names, directories = tree_inventory(source)
    if RECEIPT in names or RECEIPT in directories:
        raise ArtifactError(
            "Input already uses the reserved receipt path; use the original release directory"
        )
    omitted = {safe_relative(name) for name in (omit or [])}
    if not omitted.issubset(names):
        raise ArtifactError("Every --omit must name an existing regular input file")
    removed, kept, before = [], [], {}
    for name in names:
        path = source / name
        facts = file_digest(path)
        # Refuse deleting a large/uninterpretable .map based on its suffix alone.
        is_map = False
        if remove_maps and name.lower().endswith(".map") and name not in omitted:
            with regular_file(path) as stream:
                data = stream.read(Limits().file_bytes + 1)
            if len(data) > Limits().file_bytes or source_map(data) is None:
                raise ArtifactError(
                    f"Cannot classify map for automatic removal: {name}"
                )
            if hashlib.sha256(data).hexdigest() != facts["sha256"]:
                raise ArtifactError(
                    f"Input changed while classifying source map: {name}"
                )
            is_map = True
        before[name] = facts
        if name in omitted or is_map:
            removed.append(
                {
                    "path": name,
                    **before[name],
                    "reason": "explicit-omit" if name in omitted else "source-map",
                }
            )
        else:
            kept.append({"path": name, **facts})
    receipt = {
        "schema_version": 1,
        "tool_version": __version__,
        "files": kept,
        "directories": directories,
        "removed": removed,
        "policy": {"remove_source_maps": remove_maps, "omit": sorted(omitted)},
    }
    encoded = canonical(receipt)
    if len(encoded) > RECEIPT_LIMIT:
        raise ArtifactError("Receipt exceeds 4 MiB")
    # Exclusive directory creation; never overwrite an existing output.
    output.mkdir(mode=0o700)
    output_info = output.stat()
    try:
        for directory in directories:
            (output / directory).mkdir(parents=True, exist_ok=True)
        removed_names = {row["path"] for row in removed}
        for name in names:
            if name not in removed_names:
                facts = file_digest(source / name, output / name)
                if facts != before[name]:
                    raise ArtifactError(f"Input changed during copy: {name}")
        if tree_inventory(source) != (names, directories):
            raise ArtifactError("Input inventory changed during hardening")
        for name in names:
            if file_digest(source / name) != before[name]:
                raise ArtifactError(f"Input changed during hardening: {name}")
        with (output / RECEIPT).open("xb") as stream:
            stream.write(encoded)
        return {
            "output": str(output),
            "kept_files": len(kept),
            "removed_files": len(removed),
            "receipt_sha256": hashlib.sha256(encoded).hexdigest(),
            "verification": verify(output),
        }
    except BaseException:
        # Only remove the exact directory created by this invocation.
        current = output.lstat()
        if (current.st_dev, current.st_ino) == (output_info.st_dev, output_info.st_ino):
            shutil.rmtree(output)
        raise


def verify(root: Path, expected_receipt: str | None = None) -> dict:
    if root.is_symlink() or not root.is_dir():
        raise ArtifactError("Verification requires a regular directory")
    with regular_file(root / RECEIPT) as stream:
        data = stream.read(RECEIPT_LIMIT + 1)
    if len(data) > RECEIPT_LIMIT:
        raise ArtifactError("Receipt exceeds 4 MiB")
    digest = hashlib.sha256(data).hexdigest()
    if expected_receipt is not None and digest != expected_receipt:
        raise ArtifactError("Receipt does not match the externally pinned SHA-256")
    receipt = parse_json(data)
    if (
        not isinstance(receipt, dict)
        or type(receipt.get("schema_version")) is not int
        or receipt["schema_version"] != 1
        or not isinstance(receipt.get("files"), list)
        or not isinstance(receipt.get("directories"), list)
    ):
        raise ArtifactError("Unsupported receipt schema")
    expected = {}
    for row in receipt["files"]:
        if (
            not isinstance(row, dict)
            or not isinstance(row.get("path"), str)
            or type(row.get("bytes")) is not int
            or row["bytes"] < 0
            or not isinstance(row.get("sha256"), str)
            or type(row.get("executable")) is not bool
        ):
            raise ArtifactError("Invalid file receipt")
        name = safe_relative(row["path"])
        if name == RECEIPT or name in expected:
            raise ArtifactError("Duplicate or reserved receipt file path")
        expected[name] = {key: row[key] for key in ("sha256", "bytes", "executable")}
    directories = receipt["directories"]
    if any(not isinstance(name, str) for name in directories) or len(
        set(directories)
    ) != len(directories):
        raise ArtifactError("Invalid directory receipt")
    for name in directories:
        safe_relative(name)
    names, actual_directories = tree_inventory(root, includes_receipt=True)
    if set(names) != set(expected) | {RECEIPT}:
        raise ArtifactError("Output inventory differs: missing or unexpected files")
    if actual_directories != sorted(directories):
        raise ArtifactError("Output directory inventory differs")
    for name, facts in expected.items():
        actual = file_digest(root / name)
        # Windows does not preserve POSIX executable mode semantics.
        keys = (
            ("sha256", "bytes")
            if os.name == "nt"
            else ("sha256", "bytes", "executable")
        )
        if any(actual[key] != facts[key] for key in keys):
            raise ArtifactError(f"Output file differs from receipt: {name}")
    if tree_inventory(root, includes_receipt=True) != (names, actual_directories):
        raise ArtifactError("Output inventory changed during verification")
    return {
        "ok": True,
        "files": len(expected),
        "receipt_sha256": digest,
        "receipt_pinned": expected_receipt is not None,
        "scope": "file bytes and inventory; not runtime equivalence or a digital signature",
    }
