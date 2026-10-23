"""Bounded, stateless HTTPS requests with credential-safe error messages."""

import json as jsonlib
import logging
import math
import os
import re
import time
from http.cookiejar import CookieJar, DefaultCookiePolicy
from threading import Lock
from time import monotonic

import httpx

from . import __version__

# HTTPX logs complete request URLs at INFO; query parameters may contain keys.
logging.getLogger("httpx").setLevel(logging.WARNING)
logging.getLogger("httpcore").setLevel(logging.WARNING)

UA = os.environ.get("MCP_MAINTAINER_TOOLS_UA", f"mcp-maintainer-tools/{__version__}")
MAX_GET_RETRIES = 2
RETRYABLE_STATUSES = frozenset({429, 502, 503, 504})
MAX_RESPONSE_BYTES = 32 * 1024 * 1024
# Checked after headers and at each body chunk; this is not a hard deadline
# while waiting for headers. HTTPX also enforces per-operation I/O timeouts.
MAX_RESPONSE_SECONDS = 45.0
MAX_JSON_DEPTH = 64
# A provider's documented not-found body is tiny; read no more than this.
MAX_NOT_FOUND_BYTES = 1024
_SURROGATE = re.compile(r"[\ud800-\udfff]")
_client = None
_client_lock = Lock()


class UpstreamError(RuntimeError):
    """A request failed; its message contains no URL or upstream content."""


class UpstreamUnavailable(UpstreamError):
    """A GET availability failure permits an explicit, fixed-source fallback."""


class UpstreamNotFound(UpstreamError):
    """A GET 404 whose small JSON body carries the caller's documented not-found code."""


class _NoCookies(DefaultCookiePolicy):
    """Public data lookups do not need provider-controlled session state."""

    def set_ok(self, cookie, request):
        return False

    def return_ok(self, cookie, request):
        return False


def _trust_environment() -> bool:
    value = os.environ.get("MCP_MAINTAINER_TOOLS_TRUST_ENV", "false")
    if value not in {"true", "false"}:
        raise UpstreamError("MCP_MAINTAINER_TOOLS_TRUST_ENV must be 'true' or 'false'.") from None
    return value == "true"


def client() -> httpx.Client:
    global _client
    with _client_lock:
        if _client is None:
            trust_environment = _trust_environment()
            try:
                _client = httpx.Client(
                    headers={"User-Agent": UA, "Accept-Encoding": "identity"},
                    cookies=CookieJar(policy=_NoCookies()),
                    timeout=httpx.Timeout(15.0, connect=10.0, pool=10.0),
                    limits=httpx.Limits(max_connections=10, max_keepalive_connections=5),
                    follow_redirects=False,
                    verify=True,
                    trust_env=trust_environment,
                )
            except (OSError, ValueError, httpx.InvalidURL):
                raise UpstreamError("Upstream HTTPS client configuration failed.") from None
    return _client


def _https_url(url) -> httpx.URL:
    try:
        parsed = httpx.URL(url)
    except (httpx.InvalidURL, TypeError, ValueError):
        raise UpstreamError("Upstream request requires an HTTPS URL without credentials.") from None
    if parsed.scheme != "https" or not parsed.host or parsed.username or parsed.password:
        raise UpstreamError("Upstream request requires an HTTPS URL without credentials.") from None
    return parsed


def _unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("Duplicate JSON key")
        result[key] = value
    return result


def _reject_constant(value):
    raise ValueError("Non-finite JSON number")


def _finite_float(value):
    number = float(value)
    if not math.isfinite(number):
        raise ValueError("Non-finite JSON number")
    return number


def _check_json_nesting(text):
    """Bound nesting before the JSON parser allocates deeply nested containers."""
    depth = 0
    quoted = False
    escaped = False
    for char in text:
        if quoted:
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == '"':
                quoted = False
        elif char == '"':
            quoted = True
        elif char in "[{":
            depth += 1
            if depth > MAX_JSON_DEPTH:
                raise ValueError("JSON nesting limit exceeded")
        elif char in "]}":
            depth -= 1


def _check_unicode_scalars(value):
    # Escaped lone surrogates survive json.loads but cannot be represented in
    # UTF-8 structured MCP output. Valid non-BMP characters remain unchanged.
    if isinstance(value, str):
        if _SURROGATE.search(value):
            raise ValueError("Invalid Unicode scalar in JSON")
    elif isinstance(value, dict):
        for key, item in value.items():
            _check_unicode_scalars(key)
            _check_unicode_scalars(item)
    elif isinstance(value, list):
        for item in value:
            _check_unicode_scalars(item)


def _is_not_found(response: httpx.Response, started: float, code: int) -> bool:
    """Read at most MAX_NOT_FOUND_BYTES of an identity-encoded 404 body.

    Only an object whose integer "code" equals the caller's documented value
    counts. Routing errors, proxies and oversized or malformed bodies do not.
    """
    if response.headers.get("content-encoding", "identity").strip().lower() != "identity":
        return False
    body = bytearray()
    for chunk in response.iter_raw():
        if monotonic() - started > MAX_RESPONSE_SECONDS:
            return False
        body.extend(chunk)
        if len(body) > MAX_NOT_FOUND_BYTES:
            return False
    try:
        value = _strict_json(body)
    except (ValueError, UnicodeError, RecursionError):
        return False
    return isinstance(value, dict) and type(value.get("code")) is int and value["code"] == code


def _strict_json(body: bytes):
    """Decode JSON with the same rules for every provider body this client reads."""
    text = body.decode("utf-8-sig")
    _check_json_nesting(text)
    result = jsonlib.loads(
        text,
        object_pairs_hook=_unique_object,
        parse_constant=_reject_constant,
        parse_float=_finite_float,
    )
    _check_unicode_scalars(result)
    return result


def _read_response(
    response: httpx.Response,
    method: str,
    started: float,
    as_text: bool = False,
    not_found_code: int | None = None,
):
    if (
        response.status_code == 404
        and method == "GET"
        and not_found_code is not None
        and _is_not_found(response, started, not_found_code)
    ):
        raise UpstreamNotFound("Upstream reported that the requested record does not exist.")
    if not 200 <= response.status_code < 300:
        # Do not call raise_for_status(): HTTPStatusError includes the URL.
        error_class = UpstreamError
        if method == "GET" and (
            response.status_code in {403, 404, 408, 429} or 500 <= response.status_code < 600
        ):
            error_class = UpstreamUnavailable
        raise error_class(f"Upstream {method} returned HTTP {response.status_code}.") from None
    # Ask for identity and reject unexpected compression before decoding it.
    # Decoded iter_bytes(chunk_size=...) alone cannot bound decompressor memory.
    if response.headers.get("content-encoding", "identity").strip().lower() != "identity":
        raise UpstreamError("Upstream response used an unsupported content encoding.") from None
    length = response.headers.get("content-length")
    if length is not None:
        if not length.isascii() or not length.isdigit() or len(length) > 20:
            raise UpstreamError("Upstream response had an invalid content length.") from None
        if int(length) > MAX_RESPONSE_BYTES:
            raise UpstreamError("Upstream response exceeded the size limit.") from None
    body = bytearray()
    if monotonic() - started > MAX_RESPONSE_SECONDS:
        raise UpstreamError("Upstream response exceeded the time limit.") from None
    # Do not aggregate raw chunks before checking the deadline: a slow stream
    # can otherwise keep a fixed-size chunk buffer open indefinitely.
    chunks = (response.content,) if response.is_stream_consumed else response.iter_raw()
    for chunk in chunks:
        if monotonic() - started > MAX_RESPONSE_SECONDS:
            raise UpstreamError("Upstream response exceeded the time limit.") from None
        if len(body) + len(chunk) > MAX_RESPONSE_BYTES:
            raise UpstreamError("Upstream response exceeded the size limit.") from None
        body.extend(chunk)
    if as_text:
        try:
            text = body.decode(response.encoding or "utf-8", errors="replace")
            _check_unicode_scalars(text)
            return text
        except (LookupError, ValueError):
            raise UpstreamError("Upstream response was not valid text.") from None
    try:
        return _strict_json(body)
    except (ValueError, UnicodeError, RecursionError):
        raise UpstreamError("Upstream response was not valid JSON.") from None


def get(url, params=None, headers=None, retries=2, as_text=False, not_found_code=None):
    """GET with at most two retries for transient status or transport errors.

    Redirects are rejected. Retry waits are two seconds, then four seconds;
    caller-supplied retry counts are bounded to the inclusive range 0..2.
    With not_found_code, a 404 whose small JSON body has that integer "code"
    raises UpstreamNotFound; every other error keeps its usual class.
    """
    if type(retries) is not int:
        raise ValueError("retries must be an integer") from None
    if not_found_code is not None and type(not_found_code) is not int:
        raise ValueError("not_found_code must be an integer") from None
    url = _https_url(url)
    retry_count = min(max(retries, 0), MAX_GET_RETRIES)
    for attempt in range(retry_count + 1):
        started = monotonic()
        try:
            with client().stream(
                "GET", url, params=params, headers=headers, follow_redirects=False
            ) as response:
                if response.status_code not in RETRYABLE_STATUSES or attempt == retry_count:
                    return _read_response(response, "GET", started, as_text, not_found_code)
        except httpx.TransportError:
            if attempt == retry_count:
                raise UpstreamUnavailable("Upstream GET failed due to a transport error.") from None
        except (httpx.RequestError, httpx.InvalidURL, UnicodeError, ValueError, TypeError):
            raise UpstreamError("Upstream GET request failed.") from None
        # The stream context has closed the response before a retry wait.
        time.sleep(2 * (attempt + 1))


def post(url, json=None, data=None, headers=None):
    """POST once, without following redirects or retrying a possible write."""
    url = _https_url(url)
    started = monotonic()
    try:
        with client().stream(
            "POST", url, json=json, data=data, headers=headers, follow_redirects=False
        ) as response:
            return _read_response(response, "POST", started)
    except (httpx.RequestError, httpx.InvalidURL, UnicodeError, ValueError, TypeError):
        raise UpstreamError("Upstream POST request failed.") from None


def env(name: str, required=True):
    value = os.environ.get(name)
    if required and not value:
        raise RuntimeError(f"{name} env var is not set")
    return value
