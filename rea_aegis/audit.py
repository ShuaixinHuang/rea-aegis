"""Evidence-oriented rules: observations are not claims of exploitability."""

from __future__ import annotations

import lzma
import re
import zipfile
import zlib
from dataclasses import asdict
from pathlib import Path, PurePosixPath
from urllib.parse import quote

from . import __version__
from .artifacts import Limits, Member, members, parse_json

SEVERITY = {"note": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
RULES = {
    "source-map": ("medium", "Source map exposes source names and mappings."),
    "embedded-source": ("high", "Source map contains embedded original source text."),
    "source-map-reference": (
        "medium",
        "A sourceMappingURL marker is present; its target was not fetched.",
    ),
    "private-key": (
        "critical",
        "Private-key material marker found. Rotate real keys before publishing.",
    ),
    "credential-candidate": (
        "high",
        "Credential-shaped value found; validity was not tested.",
    ),
    "environment-file": (
        "high",
        "Environment configuration is shipped. Review it for credentials.",
    ),
    "source-attachment": (
        "low",
        "Source-language file is shipped; it may also be required at runtime.",
    ),
    "debug-sidecar": ("medium", "Debug sidecar exposes analysis metadata."),
    "unexamined": ("note", "Member content was not fully examined."),
    "nested-archive": ("note", "Nested archive content was not recursively inspected."),
}
PRIVATE_KEY = re.compile(
    rb"-----BEGIN (?:RSA |EC |DSA |OPENSSH |ENCRYPTED )?PRIVATE KEY-----"
)
TOKEN = re.compile(rb"\b(?:AKIA[A-Z0-9]{16}|gh[pousr]_[A-Za-z0-9]{36,255})\b")
REFERENCE = re.compile(rb"[#@][ \t]*sourceMappingURL[ \t]*=")


def source_map(data: bytes) -> dict | None:
    try:
        value = parse_json(data)
    except (ValueError, UnicodeError, RecursionError):
        return None
    if (
        isinstance(value, dict)
        and type(value.get("version")) is int
        and value["version"] == 3
        and (
            isinstance(value.get("mappings"), str)
            or isinstance(value.get("sections"), list)
        )
    ):
        return value
    return None


def embedded_source(value: dict) -> bool:
    pending = [value]
    while pending:
        item = pending.pop()
        content = item.get("sourcesContent")
        if isinstance(content, list) and any(isinstance(s, str) and s for s in content):
            return True
        for section in (
            item.get("sections", []) if isinstance(item.get("sections"), list) else []
        ):
            if isinstance(section, dict) and isinstance(section.get("map"), dict):
                pending.append(section["map"])
    return False


def inspect(member: Member) -> list[dict]:
    findings = []

    def add(rule: str, detail: str | None = None, offset: int | None = None):
        severity, message = RULES[rule]
        row = {
            "rule": rule,
            "severity": severity,
            "path": member.path,
            "message": detail or message,
        }
        if offset is not None:
            row["byte_offset"] = offset
        findings.append(row)

    if member.kind == "directory":
        return findings
    if member.kind != "file":
        add("unexamined", f"{member.kind} member was not followed or read.")
        return findings
    if len(member.data) != member.size:
        add(
            "unexamined",
            f"Only {len(member.data)} of {member.size} bytes were examined.",
        )
    name = PurePosixPath(member.path).name.lower()
    if name.endswith(".map"):
        parsed = source_map(member.data)
        if parsed is not None:
            add("source-map")
            if embedded_source(parsed):
                add("embedded-source")
        else:
            add(
                "unexamined",
                "Map-named member could not be interpreted as a v3 source map.",
            )
    for expression, rule in [
        (PRIVATE_KEY, "private-key"),
        (TOKEN, "credential-candidate"),
        (REFERENCE, "source-map-reference"),
    ]:
        match = expression.search(member.data)
        if match:
            # No matched values/snippets: sensitive content never enters a report.
            add(rule, offset=match.start())
    if name == ".env" or (
        name.startswith(".env.")
        and not name.endswith((".example", ".sample", ".template"))
    ):
        add("environment-file")
    if name.endswith((".ts", ".tsx", ".py", ".c", ".cpp", ".rs", ".go")):
        add("source-attachment")
    if name.endswith((".pdb", ".debug", ".dwarf", ".dsym")) or any(
        part.lower().endswith(".dsym") for part in PurePosixPath(member.path).parts
    ):
        add("debug-sidecar")
    if name.endswith((".zip", ".asar", ".tar", ".gz", ".7z", ".apk", ".whl")):
        add("nested-archive")
    return findings


def audit(path: Path, limits: Limits = Limits()) -> dict:
    findings, errors = [], []
    count = size = examined = 0
    try:
        for member in members(path, limits):
            count += 1
            size += member.size
            examined += len(member.data)
            findings.extend(inspect(member))
    except (
        OSError,
        ValueError,
        RuntimeError,
        EOFError,
        NotImplementedError,
        zipfile.BadZipFile,
        zlib.error,
        lzma.LZMAError,
    ) as error:
        errors.append(str(error))
    partial = bool(errors) or any(
        row["rule"] in ("unexamined", "nested-archive") for row in findings
    )
    return {
        "schema_version": 1,
        "tool": {"name": "rea-aegis", "version": __version__},
        "artifact": str(path),
        "coverage": "partial" if partial else "complete",
        "members": count,
        "declared_bytes": size,
        "examined_bytes": examined,
        "limits": asdict(limits),
        "findings": findings,
        "errors": errors,
    }


def exit_status(report: dict, fail_on: str) -> int:
    if report["coverage"] != "complete":
        return 2
    return int(
        any(
            SEVERITY[row["severity"]] >= SEVERITY[fail_on] for row in report["findings"]
        )
    )


def sarif(report: dict) -> dict:
    levels = {
        "critical": "error",
        "high": "error",
        "medium": "warning",
        "low": "note",
        "note": "note",
    }
    return {
        "version": "2.1.0",
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "rea-aegis",
                        "version": __version__,
                        "rules": [
                            {"id": name, "shortDescription": {"text": message}}
                            for name, (_, message) in RULES.items()
                        ],
                    }
                },
                "invocations": [
                    {
                        "executionSuccessful": report["coverage"] == "complete",
                        "toolExecutionNotifications": [
                            {"level": "error", "message": {"text": message}}
                            for message in report["errors"]
                        ],
                    }
                ],
                "properties": {"coverage": report["coverage"]},
                "results": [
                    {
                        "ruleId": row["rule"],
                        "level": levels[row["severity"]],
                        "message": {"text": row["message"]},
                        "locations": [
                            {
                                "physicalLocation": {
                                    "artifactLocation": {
                                        "uri": quote(row["path"], safe="/")
                                    }
                                }
                            }
                        ],
                    }
                    for row in report["findings"]
                ],
            }
        ],
    }
