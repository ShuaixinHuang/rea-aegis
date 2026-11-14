# Protection deployment

## Key lifecycle

`keygen` creates 32 random bytes with exclusive creation and owner-only POSIX
permissions. Store keys outside release output. Code protection derives a distinct
AES key for CommonJS and Linux ELF using HKDF-SHA256. Every payload receives a fresh
96-bit nonce and a 128-bit GCM authentication tag. Format, purpose and source label
are authenticated as additional data. Gateway capability signing has a separate
HMAC-SHA256 derivation domain.

Deliver runtime keys through your licensing or operating-system secret-management
workflow. `REA_AEGIS_KEY_FILE` points to that external key file. Generated CommonJS
loaders contain the authenticated envelope and loader logic, not the master key.
Key material travels to the Node crypto helper over stdin rather than command-line
arguments. Private key values are never included in reports.

Encryption protects distributed code when the adversary lacks the external key.
An authorized host receives plaintext for execution: its debugger or administrator
can inspect that runtime. Choose key delivery and customer access policies around
this trust boundary. Rotate keys and redistribute protected payloads when needed.

## CommonJS and Electron

Use your existing JS/TS compiler or bundler to produce `.cjs`/CommonJS `.js`. The
protector parses CommonJS syntax without executing it, then emits a new `.cjs`
loader. Decryption authenticates the complete payload before `_compile` runs.
Exports, `require`, `__filename` and `__dirname` have normal CommonJS module semantics
at the output location. Ship required dependencies alongside the protected loader.

For Electron, point the package's `main` at the generated `.cjs` and arrange key
delivery before its startup. The integration target is the main process's Node
environment. Browser-only renderers, raw TypeScript and ESM entrypoints should go
through the appropriate build stage. Run your application and installer checks
after changing entrypoints or moving modules.

## Linux ELF

`protect-native` encrypts a selected ELF. `run-native` authenticates and decrypts
it, writes an anonymous Linux memory file, and replaces the launcher process with
the program via `execve`. The plaintext program is not written as a named disk file.
Arguments and the caller's environment are forwarded.

The executable identity is a memory file. Programs depending on their original
`/proc/self/exe`, `$ORIGIN`, executable-relative resources or custom loader layouts
need an integration check and explicit resource configuration. Protection currently
accepts payloads up to 16 MiB; launch requires Linux `memfd` and `/proc/self/fd`.
Ordinary Linux loader permissions and execution policy still apply.

## Logic gateway

Keep the handler file and master key in a server-only directory:

```python
# /srv/private/policy.py — deployed on the server
def evaluate(request):
    return {"total": request["quantity"] * 29}
```

Start `gateway-serve` with `/srv/private/policy.py:evaluate`. This explicitly loads
operator-owned Python code. Validate business inputs inside that handler. The
service binds IPv4 loopback; terminate HTTPS and apply public connection controls
in your reverse proxy. The generated Node ESM client requires HTTPS for external
hosts, with HTTP permitted only for loopback development.

Issue a capability with `gateway-token`. Its audience, subject, issue time and expiry
are authenticated; TTL is 1–3600 seconds. Pass it to the generated client:

```javascript
import { evaluate } from './client.mjs';
// Set REA_AEGIS_TOKEN through the calling application's credential mechanism.
const result = await evaluate({ quantity: 3 });
```

`POST /v1/evaluate` takes `Authorization: Bearer <capability>` and JSON with
`nonce` (32 lowercase hex characters) and `input`. The generated client creates a
fresh cryptographic nonce. Subjects support up to 128 Unicode characters; encoded
capabilities are bounded to 4 KiB. The service permits 60 accepted requests per subject
per fixed 60-second window, rejects replay, and never evicts a live replay record to admit
more traffic. Nonce and subject-window capacity is 10,000; overflow fails closed.

The wire boundary admits 8 KiB requests, 64 KiB successful responses and 16 active
connections. The five-second idle read timeout starts before the request line and headers,
as well as covering request bodies. Expiry heaps retire only expired ledger
records, avoiding a full live-ledger scan on each request. Handler exceptions return
a fixed error rather than private code details. Operator-owned handler computation
and allocations need application-level controls. The in-memory ledger resets when
the service restarts; use a shared durable ledger for multi-instance/restart-stable
replay enforcement. Short-lived capabilities are bearer credentials: protect them
with TLS, minimize their lifetime and keep issuance on the server.

## Verification

Run the public CLI tests for all three paths:

```bash
python -m unittest discover -s tests -v
```

`test_protect.py` executes actual encrypted CommonJS and C-produced ELF programs.
`test_gateway.py` runs a live HTTP gateway and its generated Node client. Missing or
wrong keys, modified ciphertext, cross-purpose payloads, replay, expiry and body
limits have negative controls. The release audit/receipt workflow remains available
for the final distribution directory.
