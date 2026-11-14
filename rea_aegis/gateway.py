"""Authenticated, replay-bounded gateway for operator-owned server logic."""

from __future__ import annotations

import base64
import hmac
import importlib.util
import json
import re
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlsplit

from .artifacts import ArtifactError, parse_json
from .harden import canonical
from .protect import read_key


def _b64(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _unb64(value: str) -> bytes:
    if not re.fullmatch(r"[A-Za-z0-9_-]+", value):
        raise ArtifactError("Invalid capability encoding")
    decoded = base64.b64decode(
        value + "=" * (-len(value) % 4), altchars=b"-_", validate=True
    )
    if _b64(decoded) != value:
        raise ArtifactError("Noncanonical capability encoding")
    return decoded


def _token_key(master: bytes) -> bytes:
    if not isinstance(master, bytes) or len(master) != 32:
        raise ArtifactError("Gateway master key must contain 32 bytes")
    return hmac.digest(master, b"rea-aegis/gateway/v1", "sha256")


def issue_token(
    master: bytes, subject: str, ttl: int = 300, now: int | None = None
) -> str:
    if (
        not subject
        or len(subject) > 128
        or type(ttl) is not int
        or not 1 <= ttl <= 3600
    ):
        raise ArtifactError(
            "Use a nonempty subject (up to 128 characters) and TTL 1..3600"
        )
    now = int(time.time()) if now is None else now
    payload = _b64(
        canonical(
            {
                "aud": "rea-aegis/gateway/v1",
                "sub": subject,
                "iat": now,
                "exp": now + ttl,
            }
        )
    )
    return (
        payload
        + "."
        + _b64(hmac.digest(_token_key(master), payload.encode(), "sha256"))
    )


def verify_token(master: bytes, token: str, now: int | None = None) -> dict:
    if len(token) > 2048 or token.count(".") != 1:
        raise ArtifactError("Invalid capability")
    payload, signature = token.split(".")
    expected = hmac.digest(_token_key(master), payload.encode(), "sha256")
    if not hmac.compare_digest(_unb64(signature), expected):
        raise ArtifactError("Invalid capability")
    claims = parse_json(_unb64(payload))
    now = int(time.time()) if now is None else now
    if (
        not isinstance(claims, dict)
        or claims.get("aud") != "rea-aegis/gateway/v1"
        or not isinstance(claims.get("sub"), str)
        or not 1 <= len(claims["sub"]) <= 128
        or type(claims.get("iat")) is not int
        or type(claims.get("exp")) is not int
        or not 1 <= claims["exp"] - claims["iat"] <= 3600
        or claims["iat"] > now
        or claims["exp"] <= now
    ):
        raise ArtifactError("Expired or invalid capability")
    return claims


class RequestGuard:
    def __init__(self, capacity: int = 10_000, requests_per_minute: int = 60):
        self.capacity = capacity
        self.requests_per_minute = requests_per_minute
        self.nonces: dict[tuple[str, str], int] = {}
        self.windows: dict[str, tuple[int, int]] = {}
        self.lock = threading.Lock()

    def claim(self, subject: str, nonce: str, expiry: int, now: int) -> bool:
        with self.lock:
            # Never evict a live replay record to admit another request.
            self.nonces = {key: end for key, end in self.nonces.items() if end > now}
            self.windows = {
                key: row for key, row in self.windows.items() if row[0] + 60 > now
            }
            key = (subject, nonce)
            if (
                expiry <= now
                or key in self.nonces
                or len(self.nonces) >= self.capacity
                or (subject not in self.windows and len(self.windows) >= self.capacity)
            ):
                return False
            start, count = self.windows.get(subject, (now, 0))
            if count >= self.requests_per_minute:
                return False
            self.nonces[key] = expiry
            self.windows[subject] = (start, count + 1)
            return True


class GatewayServer(ThreadingHTTPServer):
    allow_reuse_address = True

    def __init__(
        self, address, master: bytes, evaluate, *, guard: RequestGuard | None = None
    ):
        _token_key(master)
        self.master = master
        self.evaluate = evaluate
        self.guard = guard or RequestGuard()
        self.slots = threading.BoundedSemaphore(16)
        super().__init__(address, GatewayHandler)

    def process_request(self, request, client_address):
        if not self.slots.acquire(blocking=False):
            try:
                request.settimeout(1)
                request.sendall(b"HTTP/1.0 503 Busy\r\nContent-Length: 0\r\n\r\n")
            finally:
                self.shutdown_request(request)
            return
        try:
            super().process_request(request, client_address)
        except BaseException:
            self.slots.release()
            raise

    def process_request_thread(self, request, client_address):
        try:
            super().process_request_thread(request, client_address)
        finally:
            self.slots.release()


class GatewayHandler(BaseHTTPRequestHandler):
    server_version = "REAegis"
    sys_version = ""

    def log_message(self, _format, *args):
        pass

    def _reply(self, code: int, value: dict):
        self._write(code, canonical(value))

    def _write(self, code: int, data: bytes):
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(data)

    def do_POST(self):
        self.connection.settimeout(5)
        if self.path != "/v1/evaluate":
            self._reply(404, {"error": "Unknown operation"})
            return
        auth = self.headers.get_all("Authorization", [])
        try:
            if len(auth) != 1 or not auth[0].startswith("Bearer "):
                raise ArtifactError("Missing capability")
            claims = verify_token(self.server.master, auth[0][7:])
        except (ValueError, UnicodeError):
            self._reply(401, {"error": "Valid capability required"})
            return
        lengths = self.headers.get_all("Content-Length", [])
        if (
            self.headers.get("Transfer-Encoding") is not None
            or len(lengths) != 1
            or not re.fullmatch(r"[0-9]{1,5}", lengths[0])
            or not 1 <= int(lengths[0]) <= 8192
        ):
            self._reply(413, {"error": "Use one Content-Length in 1..8192"})
            return
        try:
            data = self.rfile.read(int(lengths[0]))
            if len(data) != int(lengths[0]):
                raise ArtifactError("Truncated request")
            request = parse_json(data)
            if (
                not isinstance(request, dict)
                or set(request) != {"nonce", "input"}
                or not isinstance(request["nonce"], str)
                or not re.fullmatch(r"[0-9a-f]{32}", request["nonce"])
            ):
                raise ArtifactError("Invalid request")
        except (OSError, ValueError, RecursionError):
            self._reply(400, {"error": "Invalid bounded JSON request"})
            return
        if not self.server.guard.claim(
            claims["sub"], request["nonce"], claims["exp"], int(time.time())
        ):
            self._reply(429, {"error": "Replay, rate, or capacity limit"})
            return
        try:
            result = self.server.evaluate(request["input"])
            # Bound and validate the result before writing any successful response.
            encoded = canonical({"result": result})
            if len(encoded) > 65536:
                raise ArtifactError("Response limit")
        except Exception:
            self._reply(500, {"error": "Server operation failed"})
            return
        self._write(200, encoded)


def export_client(endpoint: str, output: Path) -> dict:
    url = urlsplit(endpoint)
    if (
        url.scheme not in ("https", "http")
        or not url.hostname
        or url.username
        or url.password
        or url.query
        or url.fragment
        or (
            url.scheme == "http"
            and url.hostname not in ("127.0.0.1", "localhost", "::1")
        )
    ):
        raise ArtifactError("Use HTTPS, or HTTP on a loopback host for local testing")
    code = """import {randomBytes} from "node:crypto";
export async function evaluate(input, token = process.env.REA_AEGIS_TOKEN) {
  if (!token) throw new Error("A short-lived capability token is required");
  const response = await fetch(ENDPOINT, {
    method: "POST", signal: AbortSignal.timeout(10000),
    headers: {"Authorization": "Bearer " + token, "Content-Type": "application/json"},
    body: JSON.stringify({nonce: randomBytes(16).toString("hex"), input})
  });
  const result = await response.json();
  if (!response.ok) throw new Error(result.error || "Gateway request failed");
  return result.result;
}
""".replace("ENDPOINT", json.dumps(endpoint))
    with output.open("x", encoding="utf-8") as stream:
        stream.write(code)
    return {"output": str(output), "endpoint": endpoint, "server_logic_shipped": False}


def serve(key_file: Path, handler: str, port: int):
    path, separator, function_name = handler.rpartition(":")
    if not separator or not path or not function_name.isidentifier():
        raise ArtifactError(
            "Select an operator-owned handler as /path/file.py:function"
        )
    if type(port) is not int or not 1 <= port <= 65535:
        raise ArtifactError("Port must be in 1..65535")
    master = read_key(key_file)
    spec = importlib.util.spec_from_file_location("rea_aegis_private_handler", path)
    if spec is None or spec.loader is None:
        raise ArtifactError("Cannot load the selected handler")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    evaluate = getattr(module, function_name)
    if not callable(evaluate):
        raise ArtifactError("Selected handler is not callable")
    with GatewayServer(("127.0.0.1", port), master, evaluate) as server:
        try:
            server.serve_forever()
        except KeyboardInterrupt:
            pass
