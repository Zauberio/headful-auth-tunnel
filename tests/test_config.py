from __future__ import annotations

import os

import pytest

from headful_auth_tunnel.config import Config

RELEVANT_ENV = {
    "AUTH_TOKEN",
    "TOKEN_FILE",
    "PROFILE_DIR",
    "BROWSER_MODE",
    "CDP_ENDPOINT",
    "CDP_TARGET",
    "SCREEN_WIDTH",
    "SCREEN_HEIGHT",
    "LOCALE",
    "TIMEZONE_ID",
    "SESSION_COOKIE_NAME",
    "TLS_CERT",
    "TLS_KEY",
}


def clear_env(monkeypatch):
    for name in RELEVANT_ENV:
        monkeypatch.delenv(name, raising=False)


def test_defaults_are_original_values(monkeypatch, tmp_path):
    clear_env(monkeypatch)
    token_file = tmp_path / "state" / "token"
    monkeypatch.setenv("TOKEN_FILE", str(token_file))
    monkeypatch.setenv("PROFILE_DIR", str(tmp_path / "profile"))

    config = Config.from_env()

    assert (config.screen_width, config.screen_height) == (1440, 1100)
    assert config.locale == "en-US"
    assert config.timezone_id == "UTC"
    assert config.max_type_text_chars == 16384
    assert config.max_url_chars == 8192
    assert config.allow_private_network_navigation is False
    assert config.allow_query_token is False
    assert token_file.read_text().strip() == config.auth_token
    if os.name != "nt":
        assert token_file.stat().st_mode & 0o777 == 0o600


def test_resolution_and_locale_are_editable(monkeypatch, tmp_path):
    clear_env(monkeypatch)
    monkeypatch.setenv("TOKEN_FILE", str(tmp_path / "token"))
    monkeypatch.setenv("PROFILE_DIR", str(tmp_path / "profile"))
    monkeypatch.setenv("SCREEN_WIDTH", "3840")
    monkeypatch.setenv("SCREEN_HEIGHT", "2160")
    monkeypatch.setenv("LOCALE", "en-GB")
    monkeypatch.setenv("TIMEZONE_ID", "UTC")

    config = Config.from_env()

    assert (config.screen_width, config.screen_height) == (3840, 2160)
    assert config.locale == "en-GB"
    assert config.timezone_id == "UTC"


def test_invalid_cookie_name_is_rejected(monkeypatch, tmp_path):
    clear_env(monkeypatch)
    monkeypatch.setenv("TOKEN_FILE", str(tmp_path / "token"))
    monkeypatch.setenv("PROFILE_DIR", str(tmp_path / "profile"))
    monkeypatch.setenv("SESSION_COOKIE_NAME", "bad cookie")

    with pytest.raises(ValueError, match="SESSION_COOKIE_NAME"):
        Config.from_env()


def test_partial_tls_configuration_is_rejected(monkeypatch, tmp_path):
    clear_env(monkeypatch)
    monkeypatch.setenv("TOKEN_FILE", str(tmp_path / "token"))
    monkeypatch.setenv("PROFILE_DIR", str(tmp_path / "profile"))
    monkeypatch.setenv("TLS_CERT", str(tmp_path / "cert.pem"))

    with pytest.raises(ValueError, match="configured together"):
        Config.from_env()


def test_cdp_mode_requires_endpoint_and_does_not_create_profile(monkeypatch, tmp_path):
    clear_env(monkeypatch)
    monkeypatch.setenv("TOKEN_FILE", str(tmp_path / "token"))
    profile = tmp_path / "must-not-exist"
    monkeypatch.setenv("PROFILE_DIR", str(profile))
    monkeypatch.setenv("BROWSER_MODE", "cdp")

    with pytest.raises(ValueError, match="CDP_ENDPOINT"):
        Config.from_env()

    monkeypatch.setenv("CDP_ENDPOINT", "http://127.0.0.1:9223")
    monkeypatch.setenv("CDP_TARGET", "aliexpress")
    config = Config.from_env()

    assert config.browser_mode == "cdp"
    assert config.cdp_endpoint == "http://127.0.0.1:9223"
    assert config.cdp_target == "aliexpress"
    assert config.profile_dir is None
    assert not profile.exists()


def test_invalid_browser_mode_is_rejected(monkeypatch, tmp_path):
    clear_env(monkeypatch)
    monkeypatch.setenv("TOKEN_FILE", str(tmp_path / "token"))
    monkeypatch.setenv("BROWSER_MODE", "other")

    with pytest.raises(ValueError, match="BROWSER_MODE"):
        Config.from_env()
