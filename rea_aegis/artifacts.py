"""Bounded, read-only artifact views. Archive members are never extracted."""

from __future__ import annotations

import json
import os
import re
import stat
import struct
import zipfile
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import BinaryIO, Iterator


class ArtifactError(ValueError):
    pass


@dataclass(frozen=True)
class Limits:
    files: int = 10_000
    file_bytes: int = 2 * 1024 * 1024
    total_bytes: int = 64 * 1024 * 1024
    archive_bytes: int = 32 * 1024 * 1024
    header_bytes: int = 4 * 1024 * 1024

    def __post_init__(self):
        for name in self.__dataclass_fields__:
            value = getattr(self, name)
            if type(value) is not int or value < 0:
                raise ArtifactError(f"{name} must be a nonnegative integer")


@dataclass(frozen=True)
class Member:
    path: str
    size: int
    data: bytes
    kind: str = "file"


def identity(info: os.stat_result) -> tuple:
    return info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns, info.st_ctime_ns


@contextmanager
def regular_file(path: Path) -> Iterator[BinaryIO]:
    before = path.lstat()
    if not stat.S_ISREG(before.st_mode):
        raise ArtifactError(f"Not a regular file: {path}")
    flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
    with os.fdopen(os.open(path, flags), "rb") as stream:
        opened = os.fstat(stream.fileno())
        # Path and descriptor APIs can expose different timestamp semantics.
        # Bind object identity, then track each API's metadata against itself.
        if (before.st_dev, before.st_ino, before.st_size) != (
            opened.st_dev,
            opened.st_ino,
            opened.st_size,
        ):
            changed = ", ".join(
                name
                for name in ("st_dev", "st_ino", "st_size")
                if getattr(before, name) != getattr(opened, name)
            )
            raise ArtifactError(f"File changed before reading ({changed}): {path}")
        yield stream
        if identity(opened) != identity(os.fstat(stream.fileno())):
            raise ArtifactError(f"File changed while reading: {path}")
        if identity(before) != identity(path.lstat()):
            raise ArtifactError(f"File path changed while reading: {path}")


def directory_members(root: Path, limits: Limits) -> Iterator[Member]:
    """No implicit ignore list: hidden files and .git are also inspected."""
    count = 0
    remaining = limits.total_bytes
    pending = [root]
    while pending:
        directory = pending.pop()
        # Refuse links again at traversal time, including directory replacements.
        if not stat.S_ISDIR(directory.lstat().st_mode):
            raise ArtifactError(f"Directory changed during traversal: {directory}")
        with os.scandir(directory) as entries:
            children = []
            for item in entries:
                # Bound allocation before sorting, including entries already
                # visited in other directories. Never materialize an entire
                # oversized directory just to discover it exceeds the budget.
                if count + len(children) >= limits.files:
                    raise ArtifactError(f"Entry limit exceeded ({limits.files})")
                children.append(item)
            children.sort(key=lambda item: item.name)
        for item in children:
            count += 1
            path = Path(item.path)
            relative = path.relative_to(root).as_posix()
            info = path.lstat()
            if stat.S_ISLNK(info.st_mode):
                yield Member(relative, info.st_size, b"", "symlink")
            elif stat.S_ISDIR(info.st_mode):
                yield Member(relative, 0, b"", "directory")
                pending.append(path)
            elif not stat.S_ISREG(info.st_mode):
                yield Member(relative, info.st_size, b"", "special")
            else:
                with regular_file(path) as stream:
                    data = stream.read(min(info.st_size, limits.file_bytes, remaining))
                remaining -= len(data)
                yield Member(relative, info.st_size, data)


def _zip_preflight(stream: BinaryIO, size: int, limits: Limits) -> int:
    stream.seek(max(0, size - 65557))
    tail = stream.read(65557)
    at = tail.rfind(b"PK\x05\x06")
    if at < 0 or len(tail) - at < 22:
        raise ArtifactError("ZIP end record is missing")
    _, disk, central_disk, on_disk, count, width, offset, comment = struct.unpack_from(
        "<4s4H2IH", tail, at
    )
    if len(tail) - at != 22 + comment:
        raise ArtifactError("ZIP end record is ambiguous or has trailing bytes")
    if disk or central_disk or on_disk != count:
        raise ArtifactError("Multi-disk ZIP is unsupported")
    if count == 0xFFFF or width == 0xFFFFFFFF or offset == 0xFFFFFFFF:
        raise ArtifactError("ZIP64 is unsupported in this release")
    if count > limits.files or width > limits.header_bytes:
        raise ArtifactError("ZIP directory exceeds the entry/header limit")
    end_record = max(0, size - 65557) + at
    if offset + width != end_record:
        raise ArtifactError(
            "ZIP directory extent is inconsistent; prefixed/ZIP64 layouts are unsupported"
        )
    # Admit actual record framing before ZipFile allocates its member objects.
    stream.seek(offset)
    directory = stream.read(width)
    cursor = 0
    for _ in range(count):
        if cursor + 46 > width or directory[cursor : cursor + 4] != b"PK\x01\x02":
            raise ArtifactError("ZIP directory record count or framing is invalid")
        name, extra, comment_width = struct.unpack_from("<3H", directory, cursor + 28)
        cursor += 46 + name + extra + comment_width
        if cursor > width:
            raise ArtifactError("ZIP directory record exceeds its extent")
    if cursor != width:
        raise ArtifactError(
            "ZIP directory contains undeclared records or trailing data"
        )
    return count


def zip_members(path: Path, limits: Limits) -> Iterator[Member]:
    with regular_file(path) as stream:
        size = os.fstat(stream.fileno()).st_size
        if size > limits.archive_bytes:
            raise ArtifactError("ZIP exceeds the archive byte limit")
        count = _zip_preflight(stream, size, limits)
        stream.seek(0)
        remaining = limits.total_bytes
        with zipfile.ZipFile(stream) as archive:
            members = archive.infolist()
            if len(members) != count:
                raise ArtifactError("ZIP directory count disagrees with end record")
            for index, item in enumerate(members):
                if item.is_dir():
                    continue
                # Ordinals preserve duplicate names instead of overwriting evidence.
                label = f"zip[{index}]/{item.filename}"
                mode = item.external_attr >> 16
                if stat.S_ISLNK(mode):
                    yield Member(label, item.file_size, b"", "symlink")
                elif item.flag_bits & 1:
                    yield Member(label, item.file_size, b"", "encrypted")
                else:
                    with archive.open(item) as source:
                        data = source.read(
                            min(item.file_size, limits.file_bytes, remaining)
                        )
                    remaining -= len(data)
                    yield Member(label, item.file_size, data)


def unique_object(pairs: list[tuple[str, object]]) -> dict:
    result = {}
    for key, value in pairs:
        if key in result:
            raise ArtifactError("Duplicate JSON object key")
        result[key] = value
    return result


def parse_json(data: bytes) -> object:
    def reject_constant(_value: str):
        raise ArtifactError("Non-finite values are not JSON numbers")

    return json.loads(
        data, object_pairs_hook=unique_object, parse_constant=reject_constant
    )


def asar_members(path: Path, limits: Limits) -> Iterator[Member]:
    with regular_file(path) as stream:
        size = os.fstat(stream.fileno()).st_size
        fixed = stream.read(16)
        if len(fixed) != 16:
            raise ArtifactError("ASAR header is truncated")
        marker, width, payload, text_size = struct.unpack("<4I", fixed)
        if (
            marker != 4
            or width != payload + 4
            or payload % 4
            or payload != (text_size + 7) // 4 * 4
            or text_size > limits.header_bytes
            or 8 + width > size
        ):
            raise ArtifactError("ASAR pickle header is invalid or exceeds the limit")
        tree = parse_json(stream.read(text_size))
        if not isinstance(tree, dict) or "files" not in tree:
            raise ArtifactError("ASAR root must declare a directory")
        base = 8 + width
        pending = [("", tree)]
        count = 0
        remaining = limits.total_bytes
        while pending:
            name, node = pending.pop()
            if not isinstance(node, dict):
                raise ArtifactError("ASAR entry must be an object")
            if "files" in node and any(
                key in node for key in ("link", "offset", "size")
            ):
                raise ArtifactError(
                    "ASAR entry has conflicting directory/file identities"
                )
            count += 1
            if count > limits.files:
                raise ArtifactError("ASAR entry limit exceeded")
            if "files" in node:
                children = node["files"]
                if not isinstance(children, dict):
                    raise ArtifactError("ASAR directory is invalid")
                for child, entry in reversed(list(children.items())):
                    if child in ("", ".", "..") or "/" in child or "\\" in child:
                        raise ArtifactError(
                            "ASAR member name is not one path component"
                        )
                    pending.append((f"{name}/{child}".lstrip("/"), entry))
            elif "link" in node or node.get("unpacked") is True:
                yield Member(name, 0, b"", "symlink" if "link" in node else "external")
            else:
                offset, length = node.get("offset"), node.get("size")
                if (
                    not isinstance(offset, str)
                    or not re.fullmatch(r"[0-9]+", offset)
                    or type(length) is not int
                    or length < 0
                ):
                    raise ArtifactError("ASAR file extent is invalid")
                offset = int(offset)
                if offset > size - base or length > size - base - offset:
                    raise ArtifactError("ASAR member exceeds its carrier")
                stream.seek(base + offset)
                data = stream.read(min(length, limits.file_bytes, remaining))
                if len(data) != min(length, limits.file_bytes, remaining):
                    raise ArtifactError("ASAR member is truncated")
                remaining -= len(data)
                yield Member(name, length, data)


def members(path: Path, limits: Limits) -> Iterator[Member]:
    if path.is_dir() and not path.is_symlink():
        yield from directory_members(path, limits)
    elif path.suffix.lower() == ".zip":
        yield from zip_members(path, limits)
    elif path.suffix.lower() == ".asar":
        yield from asar_members(path, limits)
    else:
        with regular_file(path) as stream:
            size = os.fstat(stream.fileno()).st_size
            yield Member(
                path.name,
                size,
                stream.read(min(size, limits.file_bytes, limits.total_bytes)),
            )
