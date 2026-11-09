"""Attachment helpers shared by both tool surfaces.

Network limits, MIME allow-lists, the SSRF-guarded fetch and the attachment
normaliser. Kept out of either surface package so neither depends on the other.
"""

import ipaddress
import socket
from collections.abc import Mapping
from typing import Any, NamedTuple
from urllib.parse import unquote, urljoin, urlsplit

import requests
from requests.adapters import HTTPAdapter

# ── Limits ────────────────────────────────────────────────────────────────────
IMAGE_READ_LIMIT = 5 * 1024 * 1024  # 5 MB
TEXT_READ_LIMIT = 1 * 1024 * 1024  # 1 MB
UPLOAD_SIZE_LIMIT = 5 * 1024 * 1024  # 5 MB

# Connect timeout / read timeout tuple used for all outbound HTTP calls.
HTTP_TIMEOUT = (10, 60)

# ── Supported MIME types ──────────────────────────────────────────────────────
READABLE_IMAGE_TYPES: frozenset[str] = frozenset({"image/png", "image/jpeg", "image/gif", "image/webp"})
READABLE_TEXT_TYPES: frozenset[str] = frozenset(
    {
        "text/plain",
        "text/markdown",
        "text/csv",
        "text/html",
        "text/xml",
        "text/yaml",
        "application/json",
        "application/xml",
        "application/yaml",
        "application/x-yaml",
    }
)

# ── Outbound fetch (SSRF guard) ──────────────────────────────────────────────
# The server fetches URLs on a caller's behalf, so every address a URL reaches
# must be public. The stdlib flags do not classify every range consistently
# across Python versions, so these are blocked explicitly. Mirrors Plane's own
# plane/utils/ip_address.py.
BLOCKED_NETWORKS = [
    ipaddress.ip_network(cidr)
    for cidr in (
        "0.0.0.0/8",  # "this network"; 0.0.0.0 reaches the local host on Linux
        "100.64.0.0/10",  # carrier-grade NAT (RFC 6598)
        "169.254.0.0/16",  # link-local, cloud metadata
        "255.255.255.255/32",  # broadcast
        "::ffff:0:0/96",  # IPv4-mapped IPv6
        "64:ff9b::/96",  # NAT64 (RFC 6052)
        "64:ff9b:1::/48",  # NAT64 local use (RFC 8215)
        "2002::/16",  # 6to4
        "2001::/32",  # Teredo
        "fec0::/10",  # deprecated site-local
    )
]
_NAT64 = ipaddress.ip_network("64:ff9b::/96")

MAX_REDIRECTS = 5
_REDIRECT_STATUSES = frozenset({301, 302, 303, 307, 308})
_CHUNK = 64 * 1024
# Never tunnel through an ambient proxy: it would resolve the name itself.
_NO_PROXIES = {"http": None, "https": None}


class ResponseTooLarge(ValueError):
    """The body passed the caller's byte limit; reading stopped there."""

    def __init__(self, limit: int) -> None:
        super().__init__(f"Response exceeds the {limit // 1024 // 1024} MB limit")
        self.limit = limit


class Fetched(NamedTuple):
    content: bytes
    headers: Mapping[str, str]
    url: str


def _embedded_ipv4(ip: ipaddress.IPv4Address | ipaddress.IPv6Address):
    """IPv4 addresses carried inside an IPv6 transition address; the network may route to them."""
    if ip.version != 6:
        return
    if ip.ipv4_mapped is not None:
        yield ip.ipv4_mapped
    if ip.sixtofour is not None:
        yield ip.sixtofour
    if ip.teredo is not None:
        yield from ip.teredo
    if ip in _NAT64:
        yield ipaddress.IPv4Address(int(ip) & 0xFFFFFFFF)


def is_blocked_ip(ip: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
    """True unless ``ip`` is a public unicast address. Fails closed."""
    if (
        not ip.is_global
        or ip.is_private
        or ip.is_loopback
        or ip.is_reserved
        or ip.is_link_local
        or ip.is_multicast
        or ip.is_unspecified
    ):
        return True
    if any(ip.version == net.version and ip in net for net in BLOCKED_NETWORKS):
        return True
    return any(is_blocked_ip(inner) for inner in _embedded_ipv4(ip))


def _target(url: str) -> tuple[str, str, int]:
    parsed = urlsplit(url)
    if parsed.scheme not in ("http", "https"):
        raise ValueError(f"Only http and https URLs can be fetched: {url!r}")
    if not parsed.hostname:
        raise ValueError(f"Invalid URL (no hostname): {url!r}")
    try:
        port = parsed.port or (443 if parsed.scheme == "https" else 80)
    except ValueError as exc:
        raise ValueError(f"Invalid URL port: {url!r}") from exc
    return parsed.scheme, parsed.hostname, port


def _public_addresses(url: str, hostname: str, port: int) -> list[str]:
    """Resolve ``hostname`` once; refuse if *any* address is not public."""
    try:
        infos = socket.getaddrinfo(hostname, port, type=socket.SOCK_STREAM)
    except (socket.gaierror, UnicodeError) as exc:
        raise ValueError(f"Could not resolve hostname {hostname!r}: {exc}") from exc

    addresses: list[str] = []
    for info in infos:
        address = str(info[4][0]).split("%")[0]  # drop an IPv6 zone id
        if is_blocked_ip(ipaddress.ip_address(address)):
            raise ValueError(
                f"URL {url!r} resolves to a private/reserved address ({address}) "
                "and cannot be fetched for security reasons."
            )
        if address not in addresses:
            addresses.append(address)
    if not addresses:
        raise ValueError(f"Could not resolve hostname {hostname!r}")
    return addresses


def assert_public_url(url: str) -> None:
    """Raise ValueError unless the URL is http(s) and every address it resolves to is public."""
    _, hostname, port = _target(url)
    _public_addresses(url, hostname, port)


class _PinnedAdapter(HTTPAdapter):
    """Connects to the IP literal in the URL; TLS SNI and certificate checks use the real hostname."""

    def __init__(self, server_hostname: str) -> None:
        self._server_hostname = server_hostname
        super().__init__()

    def get_connection_with_tls_context(self, request, verify, proxies=None, cert=None):
        host_params, pool_kwargs = self.build_connection_pool_key_attributes(request, verify, cert)
        pool_kwargs["server_hostname"] = self._server_hostname
        return self.poolmanager.connection_from_host(**host_params, pool_kwargs=pool_kwargs)


def _get_pinned(url: str, timeout) -> requests.Response:
    """One GET, no redirects, its socket pinned to an address that was just checked.

    Connecting to the checked IP literal means no second DNS lookup, so the name
    cannot be re-pointed at an internal address between the check and the fetch.
    """
    scheme, hostname, port = _target(url)
    parsed = urlsplit(url)
    path = (parsed.path or "/") + (f"?{parsed.query}" if parsed.query else "")
    auth = None
    if parsed.username is not None or parsed.password is not None:
        auth = (unquote(parsed.username or ""), unquote(parsed.password or ""))
    host = f"[{hostname}]" if ":" in hostname else hostname
    headers = {"Host": host if port == (443 if scheme == "https" else 80) else f"{host}:{port}"}

    last_error: Exception | None = None
    for address in _public_addresses(url, hostname, port):
        literal = f"[{address}]" if ":" in address else address
        session = requests.Session()
        session.trust_env = False
        if scheme == "https":
            session.mount("https://", _PinnedAdapter(hostname))
        try:
            response = session.get(
                f"{scheme}://{literal}:{port}{path}",
                headers=headers,
                auth=auth,
                timeout=timeout,
                allow_redirects=False,
                stream=True,
                proxies=_NO_PROXIES,
            )
        except requests.RequestException as exc:
            session.close()
            last_error = exc  # try the next address of a dual-stack host
            continue
        close = response.close

        def _close(close=close, session=session) -> None:
            try:
                close()
            finally:
                session.close()

        response.close = _close
        return response
    raise last_error or requests.ConnectionError(f"No reachable address for {hostname!r}")


def fetch_public(url: str, limit: int, timeout=HTTP_TIMEOUT) -> Fetched:
    """GET a public URL with redirects followed by hand, each hop checked, the body capped at ``limit`` bytes.

    Raises ValueError for a refused address or too many redirects, ResponseTooLarge
    (a ValueError) past ``limit``, and requests.RequestException for transport or
    HTTP errors.
    """
    for _ in range(MAX_REDIRECTS + 1):
        response = _get_pinned(url, timeout)
        location = response.headers.get("Location")
        if response.status_code in _REDIRECT_STATUSES and location:
            response.close()
            url = urljoin(url, location)
            continue
        try:
            response.raise_for_status()
            declared = response.headers.get("Content-Length", "")
            if declared.isdigit() and int(declared) > limit:
                raise ResponseTooLarge(limit)
            body = bytearray()
            for chunk in response.iter_content(_CHUNK):
                body += chunk
                if len(body) > limit:
                    raise ResponseTooLarge(limit)
            return Fetched(bytes(body), response.headers, url)
        finally:
            response.close()
    raise ValueError(f"Too many redirects (more than {MAX_REDIRECTS})")


def attachment_to_dict(attachment: Any, workspace_slug: str) -> dict[str, Any]:
    data = attachment.model_dump()
    attrs = data.get("attributes") or {}
    data["name"] = attrs.get("name")
    data["size"] = attrs.get("size") or data.get("size")
    data["content_type"] = attrs.get("type")
    return data
