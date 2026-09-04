from __future__ import annotations

import os
import re
import secrets
from contextlib import suppress
from dataclasses import dataclass
from pathlib import Path


def _env_bool(name: str, default: bool) -> bool:
    value = os.getenv(name)
    if value is None:
        return default
    normalized = value.strip().lower()
    if normalized in {"1", "true", "yes", "on"}:
        return True
    if normalized in {"0", "false", "no", "off"}:
        return False
    raise ValueError(f"{name} must be a boolean value")


def _env_int(name: str, default: int, minimum: int, maximum: int) -> int:
    value = os.getenv(name)
    if value is None or not value.strip():
        parsed = default
    else:
        try:
            parsed = int(value)
        except ValueError as exc:
            raise ValueError(f"{name} must be an integer") from exc
    if not minimum <= parsed <= maximum:
        raise ValueError(f"{name} must be between {minimum} and {maximum}")
    return parsed


def _env_csv(name: str) -> tuple[str, ...]:
    value = os.getenv(name, "")
    return tuple(item.strip().lower() for item in value.split(",") if item.strip())


def _default_state_dir() -> Path:
    return (
        Path(os.getenv("XDG_STATE_HOME", Path.home() / ".local" / "state")) / "headful-auth-tunnel"
    )


def _default_token_file() -> Path:
    return _default_state_dir() / "token"


def load_or_create_token() -> tuple[str, Path | None]:
    inline = os.getenv("AUTH_TOKEN")
    if inline:
        token = inline.strip()
        if len(token) < 24:
            raise ValueError("AUTH_TOKEN must contain at least 24 characters")
        return token, None

    token_file = Path(os.getenv("TOKEN_FILE", _default_token_file())).expanduser()
    token_file.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    with suppress(OSError):
        token_file.parent.chmod(0o700)

    if token_file.exists():
        token = token_file.read_text(encoding="utf-8").strip()
        if len(token) < 24:
            raise ValueError(f"Token in {token_file} must contain at least 24 characters")
        with suppress(OSError):
            token_file.chmod(0o600)
        return token, token_file

    token = secrets.token_urlsafe(32)
    token_file.write_text(token + "\n", encoding="utf-8")
    token_file.chmod(0o600)
    return token, token_file


@dataclass(frozen=True)
class Config:
    bind_host: str
    port: int
    base_url: str
    browser_mode: str
    cdp_endpoint: str | None
    cdp_target: str | None
    profile_dir: Path | None
    browser_executable_path: Path | None
    screen_width: int
    screen_height: int
    locale: str
    timezone_id: str
    screenshot_interval_ms: int
    max_request_bytes: int
    max_type_text_chars: int
    max_url_chars: int
    socket_timeout_seconds: int
    navigation_timeout_ms: int
    auth_token: str
    token_file: Path | None
    session_cookie_name: str
    session_ttl_seconds: int
    dns_validation_max_events: int
    allow_query_token: bool
    allow_private_network_navigation: bool
    allowed_hosts: tuple[str, ...]
    denied_hosts: tuple[str, ...]
    expose_health_details: bool
    trust_forwarded_proto: bool
    tls_cert: Path | None
    tls_key: Path | None
    max_dom_text_chars: int
    max_dom_elements: int

    @property
    def tls_enabled(self) -> bool:
        return self.tls_cert is not None and self.tls_key is not None

    @classmethod
    def from_env(cls) -> Config:
        tls_cert_raw = os.getenv("TLS_CERT", "").strip()
        tls_key_raw = os.getenv("TLS_KEY", "").strip()
        if bool(tls_cert_raw) != bool(tls_key_raw):
            raise ValueError("TLS_CERT and TLS_KEY must be configured together")

        tls_cert = Path(tls_cert_raw).expanduser() if tls_cert_raw else None
        tls_key = Path(tls_key_raw).expanduser() if tls_key_raw else None
        if tls_cert and not tls_cert.is_file():
            raise ValueError(f"TLS_CERT does not exist: {tls_cert}")
        if tls_key and not tls_key.is_file():
            raise ValueError(f"TLS_KEY does not exist: {tls_key}")

        token, token_file = load_or_create_token()
        cookie_name = (
            os.getenv("SESSION_COOKIE_NAME", "headful_auth_session").strip()
            or "headful_auth_session"
        )
        if not re.fullmatch(r"[!#$%&'*+.^_`|~0-9A-Za-z-]+", cookie_name):
            raise ValueError("SESSION_COOKIE_NAME contains invalid characters")

        browser_mode = os.getenv("BROWSER_MODE", "managed").strip().lower() or "managed"
        if browser_mode not in {"managed", "cdp"}:
            raise ValueError("BROWSER_MODE must be either managed or cdp")

        cdp_endpoint = os.getenv("CDP_ENDPOINT", "").strip() or None
        cdp_target = os.getenv("CDP_TARGET", "").strip() or None
        if browser_mode == "cdp" and not cdp_endpoint:
            raise ValueError("CDP_ENDPOINT is required when BROWSER_MODE=cdp")

        profile_dir = None
        if browser_mode == "managed":
            profile_dir = Path(
                os.getenv("PROFILE_DIR", Path.home() / ".headful-auth-tunnel" / "profile")
            ).expanduser()
            profile_dir.mkdir(parents=True, exist_ok=True)

        return cls(
            bind_host=os.getenv("BIND_HOST", "127.0.0.1"),
            port=_env_int("PORT", 19192, 1, 65535),
            base_url=os.getenv("BASE_URL", "https://example.com").strip(),
            browser_mode=browser_mode,
            cdp_endpoint=cdp_endpoint,
            cdp_target=cdp_target,
            profile_dir=profile_dir,
            browser_executable_path=(
                Path(os.environ["BROWSER_EXECUTABLE_PATH"]).expanduser()
                if os.getenv("BROWSER_EXECUTABLE_PATH", "").strip()
                else None
            ),
            screen_width=_env_int("SCREEN_WIDTH", 1440, 320, 7680),
            screen_height=_env_int("SCREEN_HEIGHT", 1100, 240, 4320),
            locale=os.getenv("LOCALE", "en-US").strip() or "en-US",
            timezone_id=os.getenv("TIMEZONE_ID", "UTC").strip() or "UTC",
            screenshot_interval_ms=_env_int("SCREENSHOT_INTERVAL_MS", 2000, 250, 60000),
            max_request_bytes=_env_int("MAX_REQUEST_BYTES", 1_048_576, 1024, 16_777_216),
            max_type_text_chars=_env_int("MAX_TYPE_TEXT_CHARS", 16_384, 1, 1_048_576),
            max_url_chars=_env_int("MAX_URL_CHARS", 8_192, 256, 65_536),
            socket_timeout_seconds=_env_int("SOCKET_TIMEOUT_SECONDS", 15, 1, 300),
            navigation_timeout_ms=_env_int("NAVIGATION_TIMEOUT_MS", 30000, 1000, 300000),
            auth_token=token,
            token_file=token_file,
            session_cookie_name=cookie_name,
            session_ttl_seconds=_env_int("SESSION_TTL_SECONDS", 2_592_000, 300, 31_536_000),
            dns_validation_max_events=_env_int("DNS_VALIDATION_MAX_EVENTS", 512, 1, 100_000),
            allow_query_token=_env_bool("ALLOW_QUERY_TOKEN", False),
            allow_private_network_navigation=_env_bool("ALLOW_PRIVATE_NETWORK_NAVIGATION", False),
            allowed_hosts=_env_csv("ALLOWED_HOSTS"),
            denied_hosts=_env_csv("DENIED_HOSTS"),
            expose_health_details=_env_bool("EXPOSE_HEALTH_DETAILS", False),
            trust_forwarded_proto=_env_bool("TRUST_FORWARDED_PROTO", False),
            tls_cert=tls_cert,
            tls_key=tls_key,
            max_dom_text_chars=_env_int("MAX_DOM_TEXT_CHARS", 20000, 1000, 250000),
            max_dom_elements=_env_int("MAX_DOM_ELEMENTS", 250, 10, 5000),
        )
