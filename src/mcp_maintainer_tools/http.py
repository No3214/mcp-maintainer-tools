"""Bounded HTTP requests with errors that do not expose upstream data."""

import logging
import os
import time

import httpx

# HTTPX logs complete request URLs at INFO; query parameters may contain keys.
logging.getLogger("httpx").setLevel(logging.WARNING)
logging.getLogger("httpcore").setLevel(logging.WARNING)

UA = os.environ.get("MCP_MAINTAINER_TOOLS_UA", "mcp-maintainer-tools/0.1")
MAX_GET_RETRIES = 2
RETRYABLE_STATUSES = frozenset({429, 502, 503, 504})
_client = None


class UpstreamError(RuntimeError):
    """A request failed; its message contains no URL or upstream content."""


def client() -> httpx.Client:
    global _client
    if _client is None:
        _client = httpx.Client(
            headers={"User-Agent": UA}, timeout=45, follow_redirects=False
        )
    return _client


def _read_response(response: httpx.Response, method: str, as_text: bool = False):
    if not 200 <= response.status_code < 300:
        # Do not call raise_for_status(): HTTPStatusError includes the URL.
        raise UpstreamError(
            f"Upstream {method} returned HTTP {response.status_code}."
        ) from None
    if as_text:
        return response.text
    try:
        return response.json()
    except (ValueError, UnicodeError):
        raise UpstreamError("Upstream response was not valid JSON.") from None


def get(url, params=None, headers=None, retries=2, as_text=False):
    """GET with at most two retries for transient status or transport errors.

    Redirects are rejected. Retry waits are two seconds, then four seconds;
    caller-supplied retry counts are bounded to the inclusive range 0..2.
    """
    if not isinstance(retries, int):
        raise ValueError("retries must be an integer") from None
    retry_count = min(max(retries, 0), MAX_GET_RETRIES)
    for attempt in range(retry_count + 1):
        try:
            response = client().get(
                url, params=params, headers=headers, follow_redirects=False
            )
        except httpx.TransportError:
            if attempt < retry_count:
                time.sleep(2 * (attempt + 1))
                continue
            raise UpstreamError("Upstream GET failed due to a transport error.") from None
        except (httpx.RequestError, httpx.InvalidURL):
            raise UpstreamError("Upstream GET request failed.") from None
        if response.status_code in RETRYABLE_STATUSES and attempt < retry_count:
            time.sleep(2 * (attempt + 1))
            continue
        return _read_response(response, "GET", as_text)


def post(url, json=None, data=None, headers=None):
    """POST once, without following redirects or retrying a possible write."""
    try:
        response = client().post(
            url, json=json, data=data, headers=headers, follow_redirects=False
        )
    except (httpx.RequestError, httpx.InvalidURL):
        raise UpstreamError("Upstream POST request failed.") from None
    return _read_response(response, "POST")


def env(name: str, required=True):
    value = os.environ.get(name)
    if required and not value:
        raise RuntimeError(f"{name} env var is not set")
    return value

