# Security model

REAegis reads locally selected release artifacts. It does not execute artifact code,
fetch mapping URLs, extract archive members, or install analysis providers.

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
