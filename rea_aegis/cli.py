"""Public CLI. Exit 0=pass, 1=threshold finding, 2=incomplete/error."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from . import __version__
from .artifacts import Limits
from .audit import SEVERITY, audit, exit_status, sarif
from .harden import harden, verify
from .protect import keygen, protect as protect_payload, run_native
from .gateway import export_client, issue_token, serve
from .protect import read_key


def positive(value: str) -> int:
    if not value.isascii() or not value.isdecimal() or int(value) <= 0:
        raise argparse.ArgumentTypeError("Expected a positive decimal integer")
    return int(value)


def budget(value: str) -> int:
    if not value.isascii() or not value.isdecimal():
        raise argparse.ArgumentTypeError("Expected a nonnegative decimal integer")
    try:
        return int(value)
    except ValueError as error:
        raise argparse.ArgumentTypeError("Decimal integer is too large") from error


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
    defaults = Limits()
    scan.add_argument(
        "--max-entries", type=budget, default=defaults.files, help="Maximum entries"
    )
    scan.add_argument(
        "--max-file-bytes",
        type=budget,
        default=defaults.file_bytes,
        help="Maximum content bytes per member",
    )
    scan.add_argument(
        "--max-total-bytes",
        type=budget,
        default=defaults.total_bytes,
        help="Maximum total content bytes",
    )
    scan.add_argument(
        "--max-archive-bytes",
        type=budget,
        default=defaults.archive_bytes,
        help="Maximum ZIP carrier size in bytes",
    )
    scan.add_argument(
        "--max-header-bytes",
        type=budget,
        default=defaults.header_bytes,
        help="Maximum archive header size in bytes",
    )
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
    generate = commands.add_parser(
        "keygen", help="Create an external owner-only 32-byte protection key"
    )
    generate.add_argument("path", type=Path)
    for command, kind in [("protect-js", "commonjs"), ("protect-native", "linux-elf")]:
        cipher = commands.add_parser(
            command, help=f"Authenticated encryption for {kind} with an external key"
        )
        cipher.add_argument("source", type=Path)
        cipher.add_argument("output", type=Path)
        cipher.add_argument("--key-file", type=Path, required=True)
        cipher.set_defaults(kind=kind)
    launch = commands.add_parser(
        "run-native",
        help="Authenticate and launch an owned ELF from a Linux memory file",
    )
    launch.add_argument("artifact", type=Path)
    launch.add_argument("--key-file", type=Path, required=True)
    launch.add_argument("arguments", nargs="*", help="Arguments to the ELF, after --")
    token = commands.add_parser(
        "gateway-token", help="Issue a short-lived gateway capability (server operator)"
    )
    token.add_argument("--key-file", type=Path, required=True)
    token.add_argument("--subject", required=True)
    token.add_argument("--ttl", type=positive, default=300)
    server = commands.add_parser(
        "gateway-serve",
        help="Serve operator-owned logic on loopback; use a TLS reverse proxy externally",
    )
    server.add_argument("--key-file", type=Path, required=True)
    server.add_argument("--handler", required=True, help="/path/handler.py:function")
    server.add_argument("--port", type=positive, default=8765)
    client = commands.add_parser(
        "gateway-client",
        help="Export an ESM client containing only the endpoint contract",
    )
    client.add_argument("endpoint")
    client.add_argument("output", type=Path)
    values = list(sys.argv[1:] if argv is None else argv)
    forwarded = []
    # Split the native program's argv before argparse: Python 3.11 does not
    # resume a starred positional after an intervening optional and separator.
    if values[:1] == ["run-native"] and "--" in values:
        separator = values.index("--")
        forwarded = values[separator + 1 :]
        values = values[:separator]
    args = parser.parse_args(values)
    if args.command == "run-native":
        args.arguments.extend(forwarded)
    try:
        if args.command == "audit":
            limits = Limits(
                files=args.max_entries,
                file_bytes=args.max_file_bytes,
                total_bytes=args.max_total_bytes,
                archive_bytes=args.max_archive_bytes,
                header_bytes=args.max_header_bytes,
            )
            report = audit(args.artifact, limits)
            if args.format == "text":
                print(
                    f"REAegis {__version__} | coverage={report['coverage']} | members={report['members']}"
                    f" | examined_bytes={report['examined_bytes']}/{report['declared_bytes']}"
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
        if args.command == "keygen":
            result = keygen(args.path)
        elif args.command.startswith("protect-"):
            result = protect_payload(args.source, args.output, args.key_file, args.kind)
        elif args.command == "run-native":
            run_native(args.artifact, args.key_file, args.arguments)
            return 0
        elif args.command == "gateway-token":
            result = {
                "token": issue_token(read_key(args.key_file), args.subject, args.ttl)
            }
        elif args.command == "gateway-client":
            result = export_client(args.endpoint, args.output)
        elif args.command == "gateway-serve":
            if args.port > 65535:
                raise ValueError("Port must be in 1..65535")
            serve(args.key_file, args.handler, args.port)
            return 0
        else:
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
