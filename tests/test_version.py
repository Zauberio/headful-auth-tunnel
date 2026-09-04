from __future__ import annotations

import re
from pathlib import Path
from types import SimpleNamespace

from headful_auth_tunnel import __version__
from headful_auth_tunnel.server import make_handler


def test_package_and_server_versions_match_pyproject():
    match = re.search(
        r"^version = \"([^\"]+)\"$",
        Path("pyproject.toml").read_text(),
        re.MULTILINE,
    )
    assert match is not None
    expected = match.group(1)
    handler = make_handler(SimpleNamespace(), None, None)

    assert __version__ == expected
    assert handler.server_version == f"HeadfulAuthTunnel/{expected}"


def test_ui_labels_text_entry_button_send():
    from headful_auth_tunnel.ui import APP_HTML

    assert '<button id="type">Send</button>' in APP_HTML
    assert '<button id="type">Type</button>' not in APP_HTML
