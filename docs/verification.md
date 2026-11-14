# Verification record — 0.1.0

These are checks actually run during initial development. Hosted results belong
to their recorded commit; this document does not predict future CI outcomes.

## Local environment and checks

- Linux; Python 3.12.14, Node.js 24.22.1.
- `python -m unittest discover -s tests -v`: includes the public CLI and real
  Node.js smoke test. See the release notes for the final test count.
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

## Limits on claims

No real Electron GUI, installer, production customer application, debugger,
decompiler, REA workflow, or anti-reverse-engineering benchmark was run. No timing,
token-cost amplification, or confidentiality improvement percentage is claimed.
Windows/macOS behavior is covered by the configured hosted matrix only when its
jobs pass; local Linux results are not substituted for those jobs. POSIX-specific
symlink/mode cases skip on Windows and are not counted as Windows passes.

The tool assumes trusted, non-racing filesystem parents. File checks do not provide
an atomic multi-file snapshot. Consult [SECURITY.md](../SECURITY.md) before using
receipts as part of a release process.
