<div align="center">

# REAegis

**Reduce what your release gives away. Verify what you keep.**

[![CI](https://github.com/ShuaixinHuang/rea-aegis/actions/workflows/ci.yml/badge.svg)](https://github.com/ShuaixinHuang/rea-aegis/actions/workflows/ci.yml)
[![Python 3.11+](https://img.shields.io/badge/Python-3.11%2B-3776AB)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

REAegis protects release artifacts through exposure analysis, selective hardening, and verifiable integrity. Its local CLI helps software authors control the source, configuration and metadata available to REA and other reverse-engineering tools.

[中文说明](docs/README.zh-CN.md) · [Threat model](SECURITY.md) · [Verification](docs/verification.md)

</div>

## Why

A bundled source map can carry your original TypeScript even when the application ships minified JavaScript. A release directory can also accidentally include environment files, private-key material, or debug sidecars.

REAegis makes those observations explicit and provides a small, reviewable hardening workflow:

```text
audit release → choose removals → create a separate copy → pin receipt → verify
```

Protection mechanisms, supported formats and reproducible verification are documented below. See the [security model](SECURITY.md) for deployment boundaries and the [verification record](docs/verification.md) for test conditions. REAegis is independently maintained.

## Install

Python 3.11+; **no runtime dependencies**. Version 0.1.0 is distributed on GitHub, not PyPI.

```bash
python -m pip install "git+https://github.com/ShuaixinHuang/rea-aegis.git@v0.1.0"
rea-aegis --version
```

Alternatively, install the wheel from [Releases](https://github.com/ShuaixinHuang/rea-aegis/releases).

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

The input is unchanged. Kept files retain their exact bytes, empty directories are preserved, and POSIX executable bits are checked. No in-place patching, network calls, target execution, or live debugger attachment occurs. Symlinks and special files are refused during hardening and verification.

### CI exit codes

| Code | Meaning |
| --- | --- |
| `0` | The configured audit completed with no finding at/above the chosen threshold, or verification succeeded |
| `1` | Audit findings reached the threshold (`--fail-on high` by default) |
| `2` | Incomplete coverage, unsupported layout, invalid input, or another error |

Partial scans never silently pass CI. JSON and SARIF 2.1.0 carry coverage and errors. Byte offsets identify sensitive matches without including matched values in reports; filenames and selected artifact paths remain visible.

## Capabilities in 0.1.0

| Input / capability | Support |
| --- | --- |
| Directory audit | Hidden files included; links are reported and not followed |
| Single file audit | Bounded byte-marker and filename rules |
| Classic single-disk ZIP audit | Directory framing checked before member allocation; duplicate names keep separate ordinal identities; no extraction |
| Electron ASAR audit | Packed member ranges and v3 maps; links/unpacked sidecars remain explicitly unexamined |
| Directory hardening | Opt-in source-map removal and exact file omissions; separate output only |
| Verification | File/directory inventory, SHA-256 bytes, POSIX executable state, optional external receipt hash pin |

Rules observe v3 source maps and embedded sources, `sourceMappingURL` markers, private-key headers, credential-shaped tokens, `.env` files, source attachments, and debug sidecars. A credential candidate is not a validated credential. A source attachment may be necessary for normal operation. Native binaries are scanned for those byte markers only; their executable structures are not decoded.

Defaults: **10,000 entries**, **2 MiB per member**, **64 MiB total content**, **32 MiB ZIP carrier**, **4 MiB archive header**. Larger/unread members, encrypted members and nested archives produce partial coverage. Raise `--max-file-bytes` / `--max-total-bytes` deliberately when appropriate. `complete` refers to these configured checks, not full program analysis or proof of secrecy.

An unsigned receipt detects changes only relative to the receipt you trust. An attacker who can replace both output and receipt can recompute both. Record its SHA-256 outside the artifact and pass `--receipt-sha256`; that still does not replace release signing or prove runtime equivalence.

## Reproduce the demo

```bash
git clone https://github.com/ShuaixinHuang/rea-aegis.git
cd rea-aegis
python -m pip install .
rea-aegis audit examples/demo --format json   # exit 1: embedded source
rea-aegis harden examples/demo ../demo-protected --remove-source-maps
rea-aegis verify ../demo-protected
rea-aegis audit ../demo-protected --format json # exit 0 at high threshold
node examples/demo/main.js
node ../demo-protected/main.js
```

Both Node commands print `{"total":13.5}`. The source map disappears; `main.js` remains byte-identical. Its mapping reference remains and is still reported at medium severity. This demonstrates source exposure reduction with byte-preserved runtime code and matching application output. See the verification record for the complete test conditions.

## Develop

```bash
python -m pip install '.[dev]'
python -m unittest discover -s tests -v
ruff check .
ruff format --check .
```

Node.js is needed only for the optional real-runtime smoke test. CI installs it explicitly. Tests cover public CLI behavior, bounded/malformed containers, duplicate member provenance, symlinks, failure cleanup, deterministic receipts, inventory drift, receipt tampering and external trust pins. See [verification notes](docs/verification.md) for actual results and limitations.

## Roadmap

1. Validate common Electron packaging layouts against producer-generated fixtures.
2. Add explicit, format-aware rewriting only with corresponding runtime and packaging checks.
3. Add signed release attestations with an external trust anchor.

Contributions should bring a concrete exposure, reproducible input, and verification for both normal and malformed cases. See [CONTRIBUTING.md](CONTRIBUTING.md).

## License

[MIT](LICENSE). Copyright © 2026 ShuaixinHuang.
