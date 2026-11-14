# Security model

REAegis separates read-only auditing, byte-copy hardening, authenticated protection
and explicit execution. Audit and harden do not execute artifact code, fetch mapping
URLs, extract archive members or install providers. `protect-js` parses CommonJS
without running it. `run-native` executes your authenticated ELF; `gateway-serve`
loads your selected operator-owned Python handler. Treat both execution commands
as application operations with the caller's operating-system authority.

The intended host has a trusted filesystem: inputs and output parents must not be
concurrently modified by an attacker. Regular file descriptors are checked against
observed file identities before/after reads; detected changes abort the operation.
This is not a filesystem snapshot, sandbox, or defense against an adversary racing
ancestor directories or rewriting data and restoring its metadata between observations.

Archive admission and content budgets are fixed or explicitly selected. Unsupported
formats and exhausted content budgets remain partial, not clean. Nested archives,
external ASAR sidecars and links are not traversed. Reports omit matched secret
values; they retain file names, selected paths, rule names and byte offsets. Treat
those reports as potentially sensitive metadata too. Credential matching is
heuristic and cannot establish that all secrets have been found.

Hardening creates a new directory exclusively. It streams selected file bytes and
checks input identity/content again before returning success. It never overwrites
an existing output. On failure it attempts to remove its own newly created output;
cleanup errors remain errors, and a partial directory may need manual attention.
Do not ship an output when the command exits unsuccessfully. Empty directories
are preserved; ownership, ACLs, extended attributes, hard-link topology, POSIX special
mode bits and timestamps are not preserved. Directory permissions are newly created.
Those differences can affect applications even when their file contents are identical.

Receipts are unsigned. Pin the receipt hash in a trusted external channel if you
need protection against receipt replacement. Verification does not authenticate a
publisher or establish application behavior. Run application and installer tests
after hardening, and use your normal release-signing process.

No client-side transformation can guarantee confidentiality against an adversary
who can execute and inspect the application. Keep durable secrets and sensitive
authorization decisions outside the distributed client where possible.

For ordinary bugs, open an issue with a minimal synthetic input. For sensitive
security reports, use GitHub's private vulnerability reporting if enabled, or
contact the repository owner before sharing a reproducer. Never attach live keys,
private customer software or credentials to public issues.

## Code protection and server authority

Authenticated envelopes use AES-256-GCM with fresh random 96-bit nonces and
purpose-specific HKDF-SHA256 keys. Format and payload purpose are authenticated.
Authentication completes before plaintext is passed to module compilation or ELF
execution. Keep master keys outside release output and distribute runtime keys
through your access-control mechanism. POSIX key permissions are checked; Windows
key-file ACL policy belongs to the operator's credential storage.

The client runtime, interpreter and privileged host remain trusted. Protecting a
payload does not hide plaintext from a host that legitimately possesses its key and
controls its execution. Linux memory execution changes executable-relative lookup
context; run integration checks for `$ORIGIN`, `/proc/self/exe` and native resources.

The gateway keeps its handler and HMAC master key server-side. Its short-lived
capabilities are bearer credentials. Use HTTPS at an authenticated reverse proxy,
keep capability issuance private, validate business inputs in the selected handler,
and manage key rotation/revocation in your deployment. The bundled listener binds
loopback, bounds connection/body/response sizes and tracks replay/rate state in
memory. A shared durable ledger is required across replicas and restarts. Handler
code and its computation/allocations are operator-owned, not sandboxed.
