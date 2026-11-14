# Contributing

Keep changes focused and evidence-based. Start from a concrete release exposure
and explain which producing format and consumer behavior establish it.

Use Python 3.11+ and standard-library runtime dependencies. Run the documented
unit/CLI checks and formatting before submitting a PR. Public CLI regressions are
preferred for behavior that they can reliably reproduce. Include malformed input,
resource bounds, path identity and cleanup cases when those boundaries change.

Format support needs real producer fixtures or an explicit statement that only
synthetic fixtures were tested. Separate source-derived reasoning from actual
tool runs. Do not equate a reverse-engineering tool's error, timeout or budget
refusal with demonstrated confidentiality or resistance to another tool.

Do not commit real secrets, third-party proprietary artifacts, generated wheels,
virtual environments, or scan results containing private metadata. New destructive
or in-place transformations need a clear design and recovery plan before integration.
