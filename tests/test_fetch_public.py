"""fetch_public: the only way the server fetches a caller-supplied URL.

No real network: address literals resolve locally, names go through a fake
resolver, and the HTTP hop is a recorded stand-in.
"""

from __future__ import annotations

import ipaddress
import itertools
import socket

import pytest
import requests
from requests.structures import CaseInsensitiveDict

from plane_mcp import attachments
from plane_mcp.attachments import ResponseTooLarge, assert_public_url, fetch_public, is_blocked_ip

PUBLIC_IP = "93.184.215.14"


@pytest.mark.parametrize(
    "url",
    [
        "http://127.0.0.1/",
        "http://169.254.169.254/latest/meta-data/",
        "http://10.0.0.5/",
        "http://0.0.0.0:8211/mcp",
        "http://[::]:8211/",
        "http://[::1]/",
        "http://[::ffff:127.0.0.1]:8211/",
        "http://[::ffff:169.254.169.254]/",
        "http://[64:ff9b::a9fe:a9fe]/",  # NAT64 of 169.254.169.254
        "http://100.100.100.200/",  # carrier-grade NAT
        "http://[2002:7f00:1::]/",  # 6to4 of 127.0.0.1
        "http://[2001:0:4136:e378:8000:63bf:f5ff:fffe]/",  # Teredo, client 10.0.0.1
        "http://[fd00::1]/",
        "http://[fe80::1]/",
    ],
)
def test_internal_addresses_are_refused(url):
    with pytest.raises(ValueError, match="private/reserved"):
        assert_public_url(url)


@pytest.mark.parametrize("url", ["ftp://example.com/a", "file:///etc/passwd", "gopher://example.com/"])
def test_only_http_and_https_are_fetched(url):
    with pytest.raises(ValueError, match="http and https"):
        assert_public_url(url)


def test_the_teredo_example_really_embeds_a_private_address():
    """Guards the parametrised case above against a typo that makes it trivially blocked."""
    teredo = ipaddress.ip_address("2001:0:4136:e378:8000:63bf:f5ff:fffe").teredo
    assert teredo is not None and teredo[1] == ipaddress.ip_address("10.0.0.1")


def test_a_public_address_passes():
    assert not is_blocked_ip(ipaddress.ip_address(PUBLIC_IP))
    assert not is_blocked_ip(ipaddress.ip_address("2606:2800:21f:cb07:6820:80da:af6b:8b2c"))


# ── Fetching ─────────────────────────────────────────────────────────────────


@pytest.fixture
def dns(monkeypatch):
    """Fake resolver: hostname -> addresses. Literals resolve to themselves."""
    table: dict[str, list[str]] = {}

    def getaddrinfo(host, port, *args, **kwargs):
        addresses = table.get(host, [host])
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", (a, port)) for a in addresses]

    monkeypatch.setattr(attachments.socket, "getaddrinfo", getaddrinfo)
    return table


class _Response:
    def __init__(self, status: int = 200, headers: dict[str, str] | None = None, chunks=()) -> None:
        self.status_code = status
        self.headers = CaseInsensitiveDict(headers or {})
        self._chunks = chunks
        self.read = 0

    def iter_content(self, size):
        for chunk in self._chunks:
            self.read += len(chunk)
            yield chunk

    def raise_for_status(self) -> None:
        if self.status_code >= 400:
            raise requests.HTTPError(f"HTTP {self.status_code}")

    def close(self) -> None:
        pass


@pytest.fixture
def http(monkeypatch):
    """Records each hop and answers from a queue of responses."""
    calls: list[tuple[str, dict]] = []
    queue: list[_Response] = []

    def get(session, url, **kwargs):
        calls.append((url, kwargs))
        return queue.pop(0)

    monkeypatch.setattr(attachments.requests.Session, "get", get)
    return calls, queue


def test_a_public_url_is_fetched_from_the_checked_address(dns, http):
    calls, queue = http
    dns["files.example.com"] = [PUBLIC_IP]
    queue.append(_Response(headers={"Content-Type": "image/png"}, chunks=[b"abc", b"def"]))

    fetched = fetch_public("https://files.example.com/a.png?x=1", limit=1024)

    assert fetched.content == b"abcdef"
    url, kwargs = calls[0]
    # Pinned: the socket goes to the IP that was checked; Host (and TLS) keep the name.
    assert url == f"https://{PUBLIC_IP}:443/a.png?x=1"
    assert kwargs["headers"]["Host"] == "files.example.com"
    assert kwargs["allow_redirects"] is False and kwargs["stream"] is True


def test_a_name_with_any_private_address_is_refused(dns, http):
    calls, _ = http
    dns["mixed.example.com"] = [PUBLIC_IP, "10.1.2.3"]

    with pytest.raises(ValueError, match="private/reserved"):
        fetch_public("https://mixed.example.com/", limit=1024)
    assert not calls


@pytest.mark.parametrize("location", ["http://127.0.0.1:8211/", "http://internal.example.com/"])
def test_a_redirect_to_an_internal_address_is_refused(dns, http, location):
    calls, queue = http
    dns["files.example.com"] = [PUBLIC_IP]
    dns["internal.example.com"] = ["10.0.0.7"]
    queue.append(_Response(302, {"Location": location}))

    with pytest.raises(ValueError, match="private/reserved"):
        fetch_public("https://files.example.com/a", limit=1024)
    assert len(calls) == 1  # the internal hop was never requested


def test_a_public_redirect_is_followed_and_rechecked(dns, http):
    calls, queue = http
    dns["files.example.com"] = [PUBLIC_IP]
    dns["cdn.example.net"] = ["93.184.215.15"]
    queue.extend([_Response(302, {"Location": "https://cdn.example.net/b"}), _Response(chunks=[b"ok"])])

    fetched = fetch_public("https://files.example.com/a", limit=1024)

    assert fetched.content == b"ok" and fetched.url == "https://cdn.example.net/b"
    assert calls[1][0] == "https://93.184.215.15:443/b"


def test_redirects_stop_after_five(dns, http):
    calls, queue = http
    dns["loop.example.com"] = [PUBLIC_IP]
    queue.extend(_Response(302, {"Location": "/again"}) for _ in range(10))

    with pytest.raises(ValueError, match="Too many redirects"):
        fetch_public("https://loop.example.com/", limit=1024)
    assert len(calls) == attachments.MAX_REDIRECTS + 1


def test_an_oversize_body_stops_reading_at_the_limit(dns, http):
    _, queue = http
    dns["big.example.com"] = [PUBLIC_IP]
    endless = _Response(chunks=itertools.repeat(b"x" * 1024))
    queue.append(endless)

    with pytest.raises(ResponseTooLarge):
        fetch_public("https://big.example.com/", limit=10 * 1024)
    assert endless.read <= 11 * 1024


def test_a_declared_oversize_body_is_refused_unread(dns, http):
    _, queue = http
    dns["big.example.com"] = [PUBLIC_IP]
    response = _Response(headers={"Content-Length": str(10**9)}, chunks=[b"x"])
    queue.append(response)

    with pytest.raises(ResponseTooLarge):
        fetch_public("https://big.example.com/", limit=1024)
    assert response.read == 0
