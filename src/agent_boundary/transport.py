"""Strict HTTP/JSON transport shared by the broker and its isolated tool adapter."""
from __future__ import annotations

import json
import math
import re
import socket
from http.client import HTTPException
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.parse import urlsplit
from urllib.request import HTTPRedirectHandler, ProxyHandler, Request, build_opener

from .errors import BoundaryError

MAX_BODY = 64 * 1024
MAX_RESPONSE = 16 * 1024 * 1024
TOKEN_PATTERN = re.compile(r"[A-Za-z0-9._~+/-]+={0,2}\Z")


def _pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise BoundaryError("invalid_json", "Duplicate JSON object keys are forbidden.", 400)
        result[key] = value
    return result


def strict_json(data: bytes | str) -> Any:
    """Decode JSON without duplicate keys, NaN/Infinity, or invalid UTF-8."""
    def invalid_constant(_: str) -> None:
        raise ValueError("Non-finite JSON constant")

    def finite_float(value: str) -> float:
        number = float(value)
        if not math.isfinite(number):
            raise ValueError("Non-finite JSON number")
        return number

    try:
        text = data.decode("utf-8", errors="strict") if isinstance(data, bytes) else data
        return json.loads(text, object_pairs_hook=_pairs, parse_constant=invalid_constant, parse_float=finite_float)
    except BoundaryError:
        raise
    except (ValueError, UnicodeError, RecursionError) as exc:
        raise BoundaryError("invalid_json", "A valid UTF-8 JSON body is required.", 400) from exc


def validate_token(token: str) -> str:
    if type(token) is not str or len(token) > 4096 or not TOKEN_PATTERN.fullmatch(token):
        raise BoundaryError("invalid_credential", "A valid bearer credential is required.", 401)
    return token


def validate_base_url(url: str) -> str:
    if type(url) is not str or not url or any(ord(c) <= 32 or ord(c) == 127 for c in url):
        raise ValueError("The service URL must be an HTTP(S) origin.")
    parts = urlsplit(url)
    try:
        port = parts.port
    except ValueError as exc:
        raise ValueError("Invalid service port.") from exc
    if (parts.scheme not in {"http", "https"} or not parts.hostname
            or parts.username is not None or parts.password is not None
            or parts.path not in {"", "/"} or parts.query or parts.fragment
            or (port is not None and not 1 <= port <= 65535)):
        raise ValueError("The service URL must be an HTTP(S) origin without user information.")
    return url.rstrip("/")


class _NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def request_json(url: str, token: str, *, method: str = "POST",
                 payload: dict | None = None, timeout: float = 5) -> dict:
    """Make one internal call, never following redirects or environment proxies."""
    validate_token(token)
    if type(timeout) not in {int, float} or not math.isfinite(timeout) or not 0 < timeout <= 120:
        raise ValueError("Timeout must be between zero and 120 seconds.")
    parsed = urlsplit(url)
    validate_base_url(f"{parsed.scheme}://{parsed.netloc}")
    if parsed.query or parsed.fragment:
        raise ValueError("Internal request URLs cannot have queries or fragments.")
    headers = {"Authorization": "Bearer " + token, "Accept": "application/json", "Connection": "close"}
    data = None
    if payload is not None:
        try:
            data = json.dumps(payload, separators=(",", ":"), allow_nan=False).encode("utf-8")
        except (ValueError, TypeError, UnicodeError) as exc:
            raise BoundaryError("invalid_json", "Request must be JSON serializable.", 400) from exc
        if len(data) > MAX_BODY:
            raise BoundaryError("body_too_large", "Request exceeds 64 KiB.", 413)
        headers["Content-Type"] = "application/json"
    request = Request(url, data=data, headers=headers, method=method)
    opener = build_opener(ProxyHandler({}), _NoRedirect())
    try:
        with opener.open(request, timeout=timeout) as response:
            if not 200 <= response.status < 300:
                raise BoundaryError("upstream_status", "Service rejected the request.", 502)
            raw = response.read(MAX_RESPONSE + 1)
    except HTTPError as exc:
        if 300 <= exc.code < 400:
            exc.close()
            raise BoundaryError("redirect_forbidden", "Service redirects are forbidden.", 502) from None
        try:
            try:
                raw_error = exc.read(MAX_BODY + 1)
            except (URLError, OSError, TimeoutError, HTTPException) as read_error:
                # Exceptions raised inside this handler do not reach the sibling
                # transport handler below. A failed error-body read is ambiguous.
                raise BoundaryError("transport_error", "Service connection failed; outcome may be pending.", 502) from read_error
            try:
                error_payload = strict_json(raw_error) if len(raw_error) <= MAX_BODY else {}
            except BoundaryError:
                error_payload = {}
            error = error_payload.get("error", {}) if type(error_payload) is dict else {}
            if (type(error) is dict and type(error.get("code")) is str
                    and type(error.get("message")) is str):
                raise BoundaryError(error["code"], error["message"], exc.code)
        finally:
            exc.close()
        raise BoundaryError("upstream_status", "Service rejected the request.", exc.code) from None
    except (URLError, OSError, TimeoutError, HTTPException) as exc:
        raise BoundaryError("transport_error", "Service connection failed; outcome may be pending.", 502) from exc
    if len(raw) > MAX_RESPONSE:
        raise BoundaryError("response_too_large", "Service response exceeds the transport limit.", 502)
    try:
        result = strict_json(raw)
    except BoundaryError:
        # A malformed successful reply may follow a committed remote effect.
        # Do not misclassify a response parser's 400 as a request denial.
        raise BoundaryError("invalid_response", "Service returned invalid JSON; outcome may be pending.", 502) from None
    if type(result) is not dict:
        raise BoundaryError("invalid_response", "Service response must be a JSON object.", 502)
    return result


class StrictHTTPServer(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True

    def handle_error(self, request, client_address):
        # Network/parser failures must not emit request details or credentials.
        pass


class StrictJSONHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    server_version = "AgentBoundary"
    sys_version = ""

    def setup(self):
        self.request.settimeout(5)
        super().setup()

    def log_message(self, format, *args):
        pass

    def parse_request(self):
        if not super().parse_request():
            return False
        self.close_connection = True
        try:
            lengths = self.headers.get_all("Content-Length", [])
            if self.headers.get_all("Transfer-Encoding", []):
                raise BoundaryError("invalid_framing", "Transfer-Encoding is forbidden.", 400)
            if len(lengths) > 1 or len(self.headers.get_all("Authorization", [])) > 1:
                raise BoundaryError("invalid_framing", "Duplicate framing or authorization headers are forbidden.", 400)
            if lengths:
                if not re.fullmatch(r"[0-9]+", lengths[0]):
                    raise BoundaryError("invalid_framing", "Invalid Content-Length.", 400)
                if len(lengths[0]) > 8 or int(lengths[0]) > MAX_BODY:
                    raise BoundaryError("body_too_large", "Request exceeds 64 KiB.", 413)
            if self.headers.get_all("Expect", []):
                raise BoundaryError("invalid_framing", "Expect is unsupported.", 417)
            return True
        except BoundaryError as exc:
            self.fail(exc)
            return False

    def handle_expect_100(self):
        self.send_json(417, {"error": {"code": "invalid_framing", "message": "Expect is unsupported."}})
        return False

    def ensure_no_body(self):
        if self.headers.get("Content-Length", "0") != "0":
            raise BoundaryError("invalid_framing", "This route does not accept a body.", 400)

    def read_json_object(self, fields: set[str]) -> dict:
        length = self.headers.get("Content-Length")
        if length is None:
            raise BoundaryError("length_required", "Content-Length is required.", 411)
        content_types = self.headers.get_all("Content-Type", [])
        if (len(content_types) != 1 or content_types[0].lower()
                not in {"application/json", "application/json; charset=utf-8"}):
            raise BoundaryError("content_type", "Content-Type must be application/json.", 415)
        try:
            raw = self.rfile.read(int(length))
        except (socket.timeout, OSError) as exc:
            raise BoundaryError("request_timeout", "Request body was not received in time.", 408) from exc
        if len(raw) != int(length):
            raise BoundaryError("invalid_framing", "Incomplete request body.", 400)
        body = strict_json(raw)
        if type(body) is not dict or set(body) != fields:
            raise BoundaryError("invalid_fields", "The route requires exactly its documented JSON fields.", 400)
        return body

    def require_bearer(self) -> str:
        values = self.headers.get_all("Authorization", [])
        if len(values) != 1 or not values[0].startswith("Bearer "):
            raise BoundaryError("unauthorized", "Bearer authentication is required.", 401)
        return validate_token(values[0][7:])

    def send_json(self, status: int, payload: dict):
        raw = json.dumps(payload, separators=(",", ":"), ensure_ascii=True, allow_nan=False).encode("utf-8")
        self.close_connection = True
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(raw)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Connection", "close")
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(raw)

    def fail(self, error: BoundaryError):
        self.send_json(error.status, {"error": {"code": error.code, "message": str(error)}})

    def send_error(self, code, message=None, explain=None):
        self.send_json(code, {"error": {"code": "http_error", "message": "HTTP request rejected."}})

    def reject_method(self):
        self.send_json(405, {"error": {"code": "method_not_allowed", "message": "HTTP method is not supported."}})

    do_GET = reject_method
    do_POST = reject_method
    do_PUT = reject_method
    do_PATCH = reject_method
    do_DELETE = reject_method
    do_OPTIONS = reject_method
    do_HEAD = reject_method
    do_TRACE = reject_method
    do_CONNECT = reject_method
