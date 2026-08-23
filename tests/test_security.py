from __future__ import annotations

import socket

import pytest

from headful_auth_tunnel.security import NavigationPolicy, validate_navigation_url


def public_dns(*args, **kwargs):
    return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", 443))]


@pytest.mark.parametrize(
    "url",
    [
        "http://localhost",
        "http://127.0.0.1",
        "http://192.168.1.10",
        "http://169.254.169.254/latest/meta-data",
        "http://service.internal",
        "http://printer.local",
        "http://singlelabel",
        "file:///etc/passwd",
    ],
)
def test_internal_and_non_http_destinations_are_blocked(url, make_config):
    decision = validate_navigation_url(url, make_config())
    assert decision.allowed is False


def test_public_hostname_is_allowed(monkeypatch, make_config):
    monkeypatch.setattr(socket, "getaddrinfo", public_dns)
    decision = validate_navigation_url("https://example.com/login", make_config())
    assert decision.allowed is True


def test_public_name_resolving_private_is_blocked(monkeypatch, make_config):
    monkeypatch.setattr(
        socket,
        "getaddrinfo",
        lambda *args, **kwargs: [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("10.0.0.8", 443))],
    )
    decision = validate_navigation_url("https://example.com", make_config())
    assert decision.allowed is False


def test_allowlist_can_override_internal_default(make_config):
    config = make_config(allowed_hosts=("auth.internal",))
    decision = validate_navigation_url("https://auth.internal/login", config)
    assert decision.allowed is True


def test_denylist_has_highest_precedence(make_config):
    config = make_config(allowed_hosts=("blocked.example",), denied_hosts=("blocked.example",))
    decision = validate_navigation_url("https://blocked.example", config)
    assert decision.allowed is False


def test_private_network_switch_allows_internal(make_config):
    config = make_config(allow_private_network_navigation=True)
    decision = validate_navigation_url("http://192.168.1.10", config)
    assert decision.allowed is True


def test_route_policy_only_allows_safe_non_network_schemes(make_config):
    policy = NavigationPolicy(make_config())
    assert policy.validate("blob:https://example.com/id", allow_non_network=True).allowed
    assert not policy.validate("file:///etc/passwd", allow_non_network=True).allowed
    assert not policy.validate("ws://127.0.0.1/socket", allow_non_network=True).allowed


def test_invalid_port_is_rejected(make_config):
    decision = validate_navigation_url("https://example.com:99999", make_config())
    assert decision.allowed is False


def test_overlong_url_is_rejected_before_resolution(monkeypatch, make_config):
    monkeypatch.setattr(
        socket, "getaddrinfo", lambda *args, **kwargs: pytest.fail("DNS should not run")
    )
    config = make_config(max_url_chars=64)
    decision = validate_navigation_url("https://example.com/" + "a" * 80, config)
    assert decision.allowed is False
    assert decision.reason == "URL is too long"


def test_idna_dependency_absent_fails_closed(monkeypatch, make_config):
    monkeypatch.setattr("headful_auth_tunnel.security._idna", None)
    monkeypatch.setattr(
        socket, "getaddrinfo", lambda *args, **kwargs: pytest.fail("DNS should not run")
    )
    decision = validate_navigation_url("https://example.com", make_config())
    assert decision.allowed is False
    assert decision.reason == "IDNA-2008 support is unavailable"


@pytest.mark.parametrize(
    "url",
    [
        "https://exa\u212aple.com",
        "https://exa\u212aple.com:8443/login",
        "https://x\u00aay.example",
    ],
)
def test_ambiguous_idna_codepoints_are_rejected(url, monkeypatch, make_config):
    monkeypatch.setattr(
        socket, "getaddrinfo", lambda *args, **kwargs: pytest.fail("DNS should not run")
    )
    decision = validate_navigation_url(url, make_config())
    assert decision.allowed is False
    assert decision.reason == "Hostname is not valid IDNA"


def test_policy_rejects_kelvin_sign_via_raw_origin(make_config):
    policy = NavigationPolicy(make_config())
    decision = policy.validate("https://exa\u212aple.com/login")
    assert decision.allowed is False
    assert decision.reason == "Hostname is not valid IDNA"


def test_idna_preserves_port(monkeypatch, make_config):
    seen: dict[str, object] = {}

    def capture_dns(host, port, *args, **kwargs):
        seen["host"] = host
        seen["port"] = port
        return public_dns()

    monkeypatch.setattr(socket, "getaddrinfo", capture_dns)
    decision = validate_navigation_url("https://example.com:8443/login", make_config())
    assert decision.allowed is True
    assert seen == {"host": "example.com", "port": 8443}


def test_ipv6_literal_passthrough(make_config):
    public = validate_navigation_url("http://[2001:4860:4860::8888]:8443/login", make_config())
    assert public.allowed is True
    assert public.reason == "Public IP address"

    loopback = validate_navigation_url("http://[::1]:8080/", make_config())
    assert loopback.allowed is False
    assert loopback.reason == "Private or special-use IP addresses are blocked"


def test_policy_ipv6_and_port_origin(make_config):
    policy = NavigationPolicy(make_config())
    decision = policy.validate("http://[2001:4860:4860::8888]:8443/path")
    assert decision.allowed is True
    assert decision.reason == "Public IP address"


def test_direct_ip_invalid_port_is_rejected_before_allow(make_config):
    for url in [
        "https://93.184.216.34:99999/",
        "https://93.184.216.34:65536/login",
        "http://[2001:4860:4860::8888]:99999/",
        "http://[2001:4860:4860::8888]:65536/login",
        "http://[::1]:99999/",
    ]:
        decision = validate_navigation_url(url, make_config())
        assert decision.allowed is False
        assert decision.reason == "URL contains an invalid port"
        assert "Public IP" not in decision.reason
