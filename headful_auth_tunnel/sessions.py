from __future__ import annotations

import hashlib
import hmac
import secrets
import time


class SessionStore:
    """Stateless, per-browser signed sessions derived from the master auth token."""

    def __init__(self, auth_token: str, ttl_seconds: int = 2_592_000):
        self.auth_key = auth_token.encode("utf-8")
        self.ttl_seconds = ttl_seconds

    def _signature(self, payload: str) -> str:
        return hmac.new(
            self.auth_key,
            payload.encode("ascii"),
            hashlib.sha256,
        ).hexdigest()

    def create(self) -> str:
        expires = int(time.time()) + self.ttl_seconds
        device_id = secrets.token_urlsafe(24)
        payload = f"v1.{expires}.{device_id}"
        return f"{payload}.{self._signature(payload)}"

    def valid(self, token: str | None) -> bool:
        if not token:
            return False
        try:
            version, expires_raw, device_id, signature = token.split(".", 3)
            expires = int(expires_raw)
        except (ValueError, TypeError):
            return False
        if version != "v1" or not device_id or expires <= int(time.time()):
            return False
        payload = f"{version}.{expires}.{device_id}"
        return hmac.compare_digest(signature, self._signature(payload))

    def revoke(self, token: str | None) -> None:
        # Sessions are stateless. Logout clears this browser's cookie.
        # Rotating the master auth token invalidates every outstanding session.
        return None
