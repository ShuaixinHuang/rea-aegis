# Verification record — 0.1.0

This record describes the executed release checks and the reproducible protection
experiment. Hosted results are linked from the release for its exact commit.

## Local environment and checks

- Linux; Python 3.12.14, Node.js 24.22.1.
- `python -m unittest discover -s tests -v`: includes the public CLI and real
  Node.js smoke test: 53 tests passed locally, with no skips.
- `ruff==0.14.5 check .` and `ruff format --check .`.
- `python -m compileall -q rea_aegis`.
- SARIF output for the demo validated with `jsonschema` 4.26.0 against
  `https://json.schemastore.org/sarif-2.1.0.json`: zero validation errors.

Tests exercise duplicate ZIP member identity, end-record count disagreements,
archive range limits, ASAR external/unpacked coverage, symlink refusal, per-file
and aggregate content limits, sensitive-value omission from JSON/SARIF, exact
file omissions, exclusive output creation, cleanup after failed copy, deterministic
receipts, empty directories, inventory drift, byte tampering, and trust pins.

## Real producer check

`@electron/asar` **4.2.0**, running under Node.js 24.22.1, packed `examples/demo`
through its actual `bin/asar.mjs pack` command. The resulting archive was audited:
two packed members, complete bounded coverage, no parser errors, and findings for
the mapping reference, source map and embedded source text. This used an existing
local installation of the producer; it is not a runtime dependency of REAegis.

An equivalent reproduction after obtaining that producer is:

```bash
npx --yes --package @electron/asar@4.2.0 asar pack examples/demo demo.asar
rea-aegis audit demo.asar --format json
```

Synthetic ASAR cases cover malformed ranges and external entries. ZIP fixtures
are emitted by Python's standard `zipfile` writer, with controlled mutations for
malformed directory records. No third-party proprietary binary is distributed.

## End-to-end result

The demo starts with a high-severity `embedded-source` finding. Hardening removes
its `.map` and keeps `main.js` byte-identical. At the default high threshold,
the subsequent audit passes, while continuing to report the remaining
`sourceMappingURL` reference at medium severity. Verification succeeds with the
externally recorded receipt hash; changing the JS bytes makes it fail. Replacing
both bytes and receipt can pass unpinned verification, but fails against the old
external hash, as the trust-anchor regression demonstrates.

Both original and copied JS were actually executed with Node.js and returned
`{"total":13.5}`. This is one smoke test. It does not prove equivalence for arbitrary
applications, installers, permissions, native modules, or Electron sessions.

## Authenticated protection and server execution

The public protection CLI encrypted a real CommonJS module, preserved its exports
and output, and rejected missing or incorrect keys. Tests altered ciphertext and
attempted cross-purpose decryption; authentication failed before plaintext output.
A compiled C executable was encrypted and launched through the public Linux
memory-file command with its arguments intact.

A generated Node.js client called an actual HTTP gateway backed by a private
Python handler. Tests exercised signed token expiry, wrong keys, request replay,
per-subject rate limits, bounded request bodies, and live replay-ledger capacity.
Key validation also runs before loading the operator-selected server module.

## REA source analysis experiment

[Machine-readable result](verification/protection-proof.json) records the fixture
hash, analyzer revision and entry-point hash. Reproduce with an installed REA
checkout and Node.js 20+:

```bash
python scripts/prove_protection.py --rea-entry /path/to/rea/scripts/rea.mjs
```

On the included 163-byte policy fixture, both the original and encrypted CommonJS
module returned `[32,111]`, including calls through their exported function.
The protected module rejected execution without its external key. REA's
`analyze_javascript_application` operation completed for both artifacts with zero
coverage limits or omitted items: it observed the original business export in the
plain module and did not observe that export in the encrypted artifact. The
protected artifact was 5,110 bytes. This measures static export recovery for this
fixture with the key outside the analyzed release.

## Execution environments

| Check | Execution |
| --- | --- |
| CommonJS encryption, authentication, exports and CLI | Local Node.js 24.22.1; hosted Node.js 24 matrix |
| Native encrypted launch | Local compiled Linux ELF through `memfd` |
| Server-held logic | Real local HTTP service and generated Node.js client |
| Electron GUI integration | Requires application-specific integration testing |
| Production TLS, key delivery and restart-persistent replay storage | Deployment responsibilities described in [protection.md](protection.md) |
| Windows/macOS | Hosted jobs verify their recorded commit; platform-specific skips remain visible |

The filesystem release workflow assumes trusted, non-racing parent directories.
Its file checks do not provide an atomic multi-file snapshot. The external key and
server-held handler determine which logic is available to a release recipient;
[protection.md](protection.md) documents runtime integration and key ownership.
