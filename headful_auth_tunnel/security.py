from __future__ import annotations

import fnmatch
import ipaddress
import socket
import time

try:
    import idna as _idna  # UTS46 / IDNA-2008 (matches browsers)
except ImportError:
    _idna = None
from dataclasses import dataclass
from http.cookies import SimpleCookie
from urllib.parse import urlsplit, urlunsplit

from .config import Config

_INTERNAL_SUFFIXES = (
    ".localhost",
    ".local",
    ".internal",
    ".lan",
    ".home",
    ".home.arpa",
)


@dataclass(frozen=True)
class NavigationDecision:
    allowed: bool
    reason: str
    normalized_url: str | None = None


def _matches(hostname: str, patterns: tuple[str, ...]) -> bool:
    return any(fnmatch.fnmatch(hostname, pattern) for pattern in patterns)


def _raw_hostname(netloc: str) -> str | None:
    # urlsplit().hostname Unicode-lowercases first, remapping U+212A (Kelvin)
    # to "k" before strict IDNA can reject it. Split netloc without case-folding.
    _, _, hostinfo = netloc.rpartition("@")
    _, have_open_br, bracketed = hostinfo.partition("[")
    if have_open_br:
        hostname, _, _ = bracketed.partition("]")
    else:
        hostname, _, _ = hostinfo.partition(":")
    return hostname or None


def _blocked_ip(address: str) -> bool:
    ip = ipaddress.ip_address(address)
    return any(
        (
            ip.is_private,
            ip.is_loopback,
            ip.is_link_local,
            ip.is_multicast,
            ip.is_reserved,
            ip.is_unspecified,
        )
    )


def validate_navigation_url(url: str, config: Config) -> NavigationDecision:
    candidate = url.strip()
    if not candidate:
        return NavigationDecision(False, "URL is required")
    if len(candidate) > config.max_url_chars:
        return NavigationDecision(False, "URL is too long")

    parsed = urlsplit(candidate)
    if parsed.scheme.lower() not in {"http", "https"}:
        return NavigationDecision(False, "Only http and https URLs are allowed")
    if parsed.username or parsed.password:
        return NavigationDecision(False, "Credentials in URLs are not allowed")
    if not parsed.hostname:
        return NavigationDecision(False, "URL must include a hostname")

    raw_host = _raw_hostname(parsed.netloc)
    if not raw_host:
        return NavigationDecision(False, "URL must include a hostname")

    try:
        direct_ip = ipaddress.ip_address(raw_host)
    except ValueError:
        direct_ip = None

    # Validate port before any allow decision — direct IP literals must not
    # be classified as "Public IP address" when the port is out of range.
    try:
        _port = parsed.port
    except ValueError:
        return NavigationDecision(False, "URL contains an invalid port")

    if direct_ip is not None:
        hostname = str(direct_ip)
    else:
        if _idna is None:
            return NavigationDecision(False, "IDNA-2008 support is unavailable")
        try:
            # IDNA-2008 (strict, no transitional mapping): matches what
            # Chromium actually resolves. stdlib encode("idna") is
            # IDNA-2003/nameprep and diverges - "faß.de" becomes "fass.de"
            # under 2003 but "xn--fa-hia.de" in the browser, so policy would
            # check a different hostname than the browser navigates to.
            # Strict mode also REJECTS ambiguous codepoints (U+00AA, U+212A)
            # instead of silently remapping them - fail-closed.
            hostname = _idna.encode(raw_host, uts46=False).decode("ascii").rstrip(".").lower()
        except (UnicodeError, _idna.core.IDNAError):
            return NavigationDecision(False, "Hostname is not valid IDNA")

    if _matches(hostname, config.denied_hosts):
        return NavigationDecision(False, "Hostname is denied by DENIED_HOSTS")

    if _matches(hostname, config.allowed_hosts):
        return NavigationDecision(True, "Hostname allowed explicitly", candidate)

    if config.allow_private_network_navigation:
        return NavigationDecision(True, "Private network navigation enabled", candidate)

    if direct_ip is not None:
        if _blocked_ip(str(direct_ip)):
            return NavigationDecision(False, "Private or special-use IP addresses are blocked")
        return NavigationDecision(True, "Public IP address", candidate)

    if hostname == "localhost" or hostname.endswith(_INTERNAL_SUFFIXES) or "." not in hostname:
        return NavigationDecision(False, "Local and internal hostnames are blocked")

    port = _port or (443 if parsed.scheme.lower() == "https" else 80)
    try:
        results = socket.getaddrinfo(hostname, port, type=socket.SOCK_STREAM)
    except socket.gaierror:
        return NavigationDecision(False, "Hostname could not be resolved")

    addresses = {item[4][0] for item in results}
    if not addresses:
        return NavigationDecision(False, "Hostname resolved to no addresses")
    if any(_blocked_ip(address) for address in addresses):
        return NavigationDecision(False, "Hostname resolves to a private or special-use address")

    return NavigationDecision(True, "Hostname resolves only to public addresses", candidate)


class NavigationPolicy:
    def __init__(self, config: Config):
        self.config = config
        self._cache: dict[str, tuple[float, NavigationDecision]] = {}
        self.cache_ttl_seconds = 30

    def validate(
        self,
        url: str,
        *,
        allow_non_network: bool = False,
        refresh: bool = False,
    ) -> NavigationDecision:
        parsed = urlsplit(url)
        scheme = parsed.scheme.lower()
        if allow_non_network and scheme in {"about", "blob", "data"}:
            return NavigationDecision(True, "Safe non-network browser URL", url)
        if allow_non_network and scheme not in {"http", "https"}:
            return NavigationDecision(False, "Unsupported browser URL scheme")
        if not parsed.hostname:
            return validate_navigation_url(url, self.config)

        host = (_raw_hostname(parsed.netloc) or parsed.hostname).rstrip(".")
        try:
            port = parsed.port
        except ValueError:
            return NavigationDecision(False, "URL contains an invalid port")
        display_host = f"[{host}]" if ":" in host else host
        netloc = display_host if port is None else f"{display_host}:{port}"
        origin = urlunsplit((parsed.scheme.lower(), netloc, "/", "", ""))
        now = time.monotonic()
        cached_entry = self._cache.get(origin)
        if refresh or cached_entry is None or now - cached_entry[0] > self.cache_ttl_seconds:
            decision = validate_navigation_url(origin, self.config)
            if len(self._cache) >= 2048:
                self._cache.clear()
            self._cache[origin] = (now, decision)
        else:
            decision = cached_entry[1]
        if decision.allowed:
            return NavigationDecision(True, decision.reason, url)
        return decision

    def validate_websocket(self, url: str) -> NavigationDecision:
        parsed = urlsplit(url)
        scheme = parsed.scheme.lower()
        if scheme not in {"ws", "wss"}:
            return NavigationDecision(False, "Unsupported WebSocket URL scheme")
        mapped_scheme = "https" if scheme == "wss" else "http"
        mapped = urlunsplit(
            (mapped_scheme, parsed.netloc, parsed.path, parsed.query, parsed.fragment)
        )
        decision = self.validate(mapped)
        return NavigationDecision(
            decision.allowed, decision.reason, url if decision.allowed else None
        )


def token_from_cookie(cookie_header: str | None, cookie_name: str) -> str | None:
    if not cookie_header:
        return None
    cookie = SimpleCookie()
    try:
        cookie.load(cookie_header)
    except Exception:
        return None
    morsel = cookie.get(cookie_name)
    return morsel.value if morsel else None


def bearer_token(authorization: str | None) -> str | None:
    if not authorization:
        return None
    scheme, _, value = authorization.partition(" ")
    if scheme.lower() != "bearer" or not value:
        return None
    return value.strip()
