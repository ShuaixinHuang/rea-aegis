"""Public CLI. Exit 0=pass, 1=threshold finding, 2=incomplete/error."""

from __future__ import annotations

import argparse
import json
import sys
from dataclasses import replace
from pathlib import Path

from . import __version__
from .artifacts import Limits
from .audit import SEVERITY, audit, exit_status, sarif
from .harden import harden, verify


def positive(value: str) -> int:
    if not value.isascii() or not value.isdecimal() or int(value) <= 0:
        raise argparse.ArgumentTypeError("Expected a positive decimal integer")
    return int(value)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="rea-aegis", description="Audit → harden → verify release exposure."
    )
    parser.add_argument("--version", action="version", version=__version__)
    commands = parser.add_subparsers(dest="command", required=True)
    scan = commands.add_parser(
        "audit", help="Read-only inspection of a directory, ZIP, ASAR, or file"
    )
    scan.add_argument("artifact", type=Path)
    scan.add_argument("--format", choices=["text", "json", "sarif"], default="text")
    scan.add_argument("--fail-on", choices=list(SEVERITY), default="high")
    scan.add_argument("--max-file-bytes", type=positive, default=Limits().file_bytes)
    scan.add_argument("--max-total-bytes", type=positive, default=Limits().total_bytes)
    protect = commands.add_parser(
        "harden", help="Create a new, disjoint directory; never modify the input"
    )
    protect.add_argument("source", type=Path)
    protect.add_argument("output", type=Path)
    protect.add_argument(
        "--remove-source-maps",
        action="store_true",
        help="Omit interpretable .map files (explicit opt-in)",
    )
    protect.add_argument(
        "--omit",
        action="append",
        default=[],
        metavar="RELATIVE_FILE",
        help="Omit this exact file, not a glob; repeatable",
    )
    check = commands.add_parser(
        "verify", help="Verify output inventory and file bytes against its receipt"
    )
    check.add_argument("directory", type=Path)
    check.add_argument(
        "--receipt-sha256",
        metavar="TRUSTED_DIGEST",
        help="Pin a receipt hash recorded outside the output",
    )
    args = parser.parse_args(argv)
    try:
        if args.command == "audit":
            limits = replace(
                Limits(),
                file_bytes=args.max_file_bytes,
                total_bytes=args.max_total_bytes,
            )
            report = audit(args.artifact, limits)
            if args.format == "text":
                print(
                    f"REAegis {__version__} | coverage={report['coverage']} | members={report['members']}"
                )
                for row in report["findings"]:
                    # JSON quoting prevents terminal controls in malicious filenames.
                    print(
                        f"{row['severity'].upper():8} {row['rule']:24} {json.dumps(row['path'])}: {row['message']}"
                    )
                for error in report["errors"]:
                    print(f"ERROR {json.dumps(error)}")
            else:
                print(
                    json.dumps(
                        sarif(report) if args.format == "sarif" else report, indent=2
                    )
                )
            return exit_status(report, args.fail_on)
        result = (
            harden(
                args.source,
                args.output,
                remove_maps=args.remove_source_maps,
                omit=args.omit,
            )
            if args.command == "harden"
            else verify(args.directory, args.receipt_sha256)
        )
        print(json.dumps(result, indent=2))
        return 0
    except (OSError, ValueError, RuntimeError) as error:
        print(json.dumps({"ok": False, "error": str(error)}), file=sys.stderr)
        return 2
