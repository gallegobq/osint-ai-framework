import socket

import pytest

from app.osint.http import _require_public_https


def test_public_endpoint_is_pinned_to_validated_address(monkeypatch) -> None:
    monkeypatch.setattr(
        socket,
        "getaddrinfo",
        lambda *args, **kwargs: [
            (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", 443))
        ],
    )

    host, pinned_url = _require_public_https(
        "https://example.com/resource?q=1"
    )

    assert host == "example.com"
    assert pinned_url == "https://93.184.216.34/resource?q=1"


def test_private_endpoint_is_rejected(monkeypatch) -> None:
    monkeypatch.setattr(
        socket,
        "getaddrinfo",
        lambda *args, **kwargs: [
            (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("127.0.0.1", 443))
        ],
    )

    with pytest.raises(ValueError, match="non-public"):
        _require_public_https("https://example.com/")
