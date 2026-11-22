<div align="center">

# REAegis

**Find accidental source and secret exposure before you ship.**

[![CI](https://github.com/ShuaixinHuang/rea-aegis/actions/workflows/ci.yml/badge.svg)](https://github.com/ShuaixinHuang/rea-aegis/actions/workflows/ci.yml)
[![Python 3.11+](https://img.shields.io/badge/Python-3.11%2B-3776AB)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

REAegis is a Python CLI for auditing release directories, ZIP archives and Electron ASAR packages. It flags embedded source maps, private-key markers and credential candidates, and can verify the integrity of a separate release copy. It also supports authenticated code protection and server-held logic.

[中文说明](docs/README.zh-CN.md) · [Try the demo](#reproduce-the-demo) · [Threat model](SECURITY.md)

</div>

## Why

A bundled source map can carry your original TypeScript even when the application ships minified JavaScript. A release directory can also accidentally include environment files, private-key material, or debug sidecars.

REAegis makes those observations explicit and provides a small, reviewable hardening workflow:

```text
audit release → choose removals → create a separate copy → pin receipt → verify
```

Protection mechanisms, supported formats and reproducible verification are documented below. See the [security model](SECURITY.md) for deployment boundaries and the [verification record](docs/verification.md) for test conditions. REAegis is independently maintained.

## Install

Python 3.11+ with **no third-party Python runtime dependencies**. Authenticated code protection uses Node.js 20+ and its built-in cryptography. Version 0.1.1 is distributed on GitHub.

```bash
python -m pip install "git+https://github.com/ShuaixinHuang/rea-aegis.git@v0.1.1"
rea-aegis --version
```

Source archives and release notes are available on [Releases](https://github.com/ShuaixinHuang/rea-aegis/releases).

## Reproduce the demo

Install v0.1.1 using the command above. Choose a fresh destination if `../demo-protected` already exists. The last two commands use Node.js to compare the sample's runtime output.

```bash
git clone --depth 1 --branch v0.1.1 https://github.com/ShuaixinHuang/rea-aegis.git
cd rea-aegis
rea-aegis audit examples/demo --format json   # exit 1: embedded source
rea-aegis harden examples/demo ../demo-protected --remove-source-maps
# Copy receipt_sha256 from the harden output and pass it here.
rea-aegis verify ../demo-protected --receipt-sha256 YOUR_RECORDED_SHA256
rea-aegis audit ../demo-protected --format json # exit 0 at high threshold
node examples/demo/main.js
node ../demo-protected/main.js
```

Both Node commands print `{"total":13.5}`. The source map disappears; `main.js` remains byte-identical. Its mapping reference remains and is still reported at medium severity. This demonstrates source exposure reduction with byte-preserved runtime code and matching application output. See the verification record for the complete test conditions.

## Maintenance and feedback

Check [GitHub Releases](https://github.com/ShuaixinHuang/rea-aegis/releases) for published versions, the [changelog](CHANGELOG.md) for pending fixes, and [CI runs](https://github.com/ShuaixinHuang/rea-aegis/actions/workflows/ci.yml?query=branch%3Amain) for test results on Linux, macOS and Windows. The [verification record](docs/verification.md) describes the fixtures and what the checks establish.

If a public or synthetic release artifact gives an unexpected result, [report an audit issue](https://github.com/ShuaixinHuang/rea-aegis/issues/new?template=audit-report.yml). Follow the [security policy](SECURITY.md) for vulnerabilities or sensitive details.

## Three protection layers

| Layer | Mechanism | Deployment |
| --- | --- | --- |
| JavaScript / TypeScript / Electron main | AES-256-GCM encrypted CommonJS, purpose-separated HKDF keys, authentication before module compilation | Compile/bundle to CommonJS; supply a key from outside the release |
| Linux native executables | Whole-ELF authenticated encryption and memory-file execution | External key; Linux `memfd` launcher; original arguments forwarded |
| Server-held logic | Server-only Python handler, signed short-lived capabilities, replay ledger and per-subject rate limits | Loopback gateway behind your HTTPS reverse proxy; generated ESM client |

Keys are never embedded by the protection commands. The gateway exports the endpoint contract while retaining its master key and business handler on the server. The release verification layer records the resulting file inventory and hashes.

```bash
# Keep this directory outside anything you distribute.
rea-aegis keygen ../operator/master.key
mkdir protected

# JS/TS: use the CommonJS output of your existing build. Electron main can point to this .cjs.
rea-aegis protect-js ./dist/core.cjs ./protected/core.cjs --key-file ../operator/master.key
REA_AEGIS_KEY_FILE=../operator/master.key node ./protected/core.cjs

# Native: protect an owned Linux executable, then authenticate and execute from memory.
rea-aegis protect-native ./dist/app ./protected/app.aegis --key-file ../operator/master.key
rea-aegis run-native ./protected/app.aegis --key-file ../operator/master.key -- argument

# Server: the handler and master key stay on the server.
rea-aegis gateway-serve --handler /srv/private/policy.py:evaluate --key-file /srv/private/master.key
rea-aegis gateway-token --subject customer-1 --ttl 300 --key-file /srv/private/master.key
rea-aegis gateway-client https://api.example.com/v1/evaluate ./protected/client.mjs
```

See the [deployment guide](docs/protection.md) for key delivery, CommonJS/Electron integration, native runtime context and the gateway contract. The protection tests actually execute encrypted CommonJS and a self-owned C-produced ELF, exercise a generated client against a live local gateway, and reject missing keys, tampering, expired capabilities and replay.

## Use

```bash
# Read-only audit. Point this at your release output, not your source checkout.
rea-aegis audit ./dist
rea-aegis audit ./app.zip --format json
rea-aegis audit ./app.asar --format sarif > report.sarif

# Explicit opt-in: remove interpretable v3 .map files and one exact file.
# The destination must not exist and must be disjoint from the input.
rea-aegis harden ./dist ./protected --remove-source-maps --omit .env

# Save the printed receipt_sha256 in trusted CI/release metadata, then:
rea-aegis verify ./protected --receipt-sha256 YOUR_RECORDED_SHA256
rea-aegis audit ./protected
```

`--omit` accepts exact, existing file paths relative to the input. It does not expand globs. Source maps are removed only after bounded JSON interpretation; malformed or oversized map files stop automatic removal rather than being deleted solely by extension. Choosing removals is your responsibility: an application may load a `.map` or configuration file at runtime. Always run your application's tests before shipping.

The input is unchanged. Kept files retain their exact bytes, empty directories are preserved, and POSIX executable bits are checked. `audit` and `harden` operate on file bytes. `run-native` explicitly executes an authenticated ELF payload; `gateway-serve` runs your selected server-side handler. Symlinks and special files are refused during hardening and verification.

### CI exit codes

| Code | Meaning |
| --- | --- |
| `0` | The configured audit completed with no finding at/above the chosen threshold, or verification succeeded |
| `1` | Audit findings reached the threshold (`--fail-on high` by default) |
| `2` | Incomplete coverage, unsupported layout, invalid input, or another error |

Partial scans never silently pass CI. JSON and SARIF 2.1.0 carry coverage and errors. Byte offsets identify sensitive matches without including matched values in reports; filenames and selected artifact paths remain visible.

### Use the audit as a CI gate

Run the audit against the finished artifact. This Bash step preserves the report for inspection while forwarding the audit's original exit code to CI.

```bash
status=0
rea-aegis audit ./dist --format json --fail-on high > rea-aegis-report.json || status=$?
case "$status" in
  1) echo "Review the findings that reached the release threshold." >&2 ;;
  2) echo "Review coverage, unread members, and errors before releasing." >&2 ;;
esac
exit "$status"
```

Configure your CI to retain the report on failure if the scan output can be shared with everyone who has access to the job. Reports include paths and filenames.

## Capabilities in 0.1.1

| Input / capability | Support |
| --- | --- |
| Directory audit | Hidden files included; links are reported and not followed |
| Single file audit | Bounded byte-marker and filename rules |
| Classic single-disk ZIP audit | Directory framing checked before member allocation; duplicate names keep separate ordinal identities; no extraction |
| Electron ASAR audit | Packed member ranges and v3 maps; links/unpacked sidecars remain explicitly unexamined |
| Directory hardening | Opt-in source-map removal and exact file omissions; separate output only |
| Verification | File/directory inventory, SHA-256 bytes, POSIX executable state, optional external receipt hash pin |
| Authenticated CommonJS protection | External key, AES-256-GCM/HKDF, preserved CommonJS module exports |
| Native protection | Encrypted Linux ELF and authenticated `memfd` execution |
| Logic gateway | Server-held handler, short-lived capabilities, replay/rate/capacity enforcement, generated Node ESM client |

Rules observe v3 source maps and embedded sources, `sourceMappingURL` markers, private-key headers, credential-shaped tokens, `.env` files, source attachments, and debug sidecars. A credential candidate is not a validated credential. A source attachment may be necessary for normal operation. Native binaries are scanned for those byte markers only; their executable structures are not decoded.

Defaults: **10,000 entries**, **2 MiB per member**, **64 MiB total content**, **32 MiB ZIP carrier**, **4 MiB archive header**. Larger/unread members, encrypted members and nested archives produce partial coverage. Raise `--max-file-bytes` / `--max-total-bytes` deliberately when appropriate. `complete` refers to these configured checks, not full program analysis or proof of secrecy.

An unsigned receipt detects changes only relative to the receipt you trust. An attacker who can replace both output and receipt can recompute both. Record its SHA-256 outside the artifact and pass `--receipt-sha256`; that still does not replace release signing or prove runtime equivalence.

## Develop

```bash
python -m pip install '.[dev]'
python -m unittest discover -s tests -v
ruff check .
ruff format --check .
```

Node.js 20+ is required for protection and its runtime tests. CI installs it explicitly. Linux native execution tests additionally use a C compiler. Tests cover public CLI behavior, bounded/malformed containers, duplicate member provenance, symlinks, failure cleanup, deterministic receipts, inventory drift, receipt tampering and external trust pins. See [verification notes](docs/verification.md) for actual results and limitations.

## Roadmap

1. Extend Electron integration across common packaging and key-delivery workflows.
2. Add native launch providers for more operating systems with real producer/runtime tests.
3. Add signed release attestations and managed key-delivery adapters.

Contributions should bring a concrete exposure, reproducible input, and verification for both normal and malformed cases. See [CONTRIBUTING.md](CONTRIBUTING.md).

## License

[MIT](LICENSE). Copyright © 2026 ShuaixinHuang.
