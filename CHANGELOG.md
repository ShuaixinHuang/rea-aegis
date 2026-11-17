# Changelog

## Unreleased

- Enforce the shared directory entry budget during enumeration, before sorting or allocating an unbounded directory listing. Oversized directories fail closed with partial audit coverage.
- Reject negative, boolean and non-integer scan limits; retain zero-byte budgets for inventory-only traversal.
- Add regression coverage for bounded enumeration, resource cleanup and directory budget boundaries.

## 0.1.1 — 2026-11-14

- Apply idle connection timeouts before request-line/header parsing, releasing gateway worker slots for incomplete requests.
- Index nonce and rate-window expiry with bounded heaps instead of scanning live records on every request.
- Accept the full supported 128-character Unicode subject range in issued capabilities, retaining a 4 KiB encoded-token bound.
- Add real-socket timeout/recovery, concurrent replay, expiry-boundary and Unicode regressions, plus a reproducible ledger benchmark.

## 0.1.0 — 2026-11-14

- Key-separated AES-256-GCM/HKDF protection for CommonJS and Linux ELF.
- Authenticated CommonJS module loading and anonymous-memory ELF execution.
- Server-held logic gateway with short-lived capabilities, bounded replay/rate state and a generated ESM client.

- Read-only release exposure audit for directories, files, classic ZIP and Electron ASAR.
- Bounded content scanning with explicit partial coverage, duplicate member identities,
  and sensitive-match reports without matched values.
- Opt-in directory-copy hardening for source maps and exact file omissions.
- Deterministic SHA-256 receipts with optional external hash pins, file/directory
  inventory verification and POSIX executable-state checks.
- JSON, SARIF 2.1.0, CI exit codes, a self-owned demo, and a cross-platform test matrix.
