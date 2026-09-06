import importlib.util
from pathlib import Path
from unittest.mock import Mock

import pytest

from app.osint.active_collectors import SandboxTlsHttpBaselineCollector


def load_sandbox_server():
    path = Path(__file__).parents[1] / "sandbox" / "server.py"
    spec = importlib.util.spec_from_file_location("soc_sandbox_server", path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_sandbox_rejects_targets_resolving_to_private_addresses(monkeypatch) -> None:
    server = load_sandbox_server()
    monkeypatch.setattr(
        server.socket,
        "getaddrinfo",
        lambda *args, **kwargs: [
            (2, 1, 6, "", ("127.0.0.1", 443)),
        ],
    )

    with pytest.raises(ValueError, match="non-public"):
        server.resolve_public_addresses("example.com")


def test_active_collector_has_a_closed_contract() -> None:
    collector = SandboxTlsHttpBaselineCollector()

    assert collector.passive is False
    assert collector.target_types == {"domain", "hostname"}
    assert collector.validate_query({"hostname": "Example.COM"}) == {
        "hostname": "example.com"
    }


def test_active_collector_normalizes_sandbox_result(monkeypatch) -> None:
    response = Mock()
    response.raise_for_status.return_value = None
    response.json.return_value = {
        "tool": "tls_http_baseline",
        "target": "example.com",
        "issues": [],
    }
    client = Mock()
    client.__enter__ = Mock(return_value=client)
    client.__exit__ = Mock(return_value=False)
    client.post.return_value = response
    monkeypatch.setattr(
        "app.osint.active_collectors.httpx.Client",
        lambda **kwargs: client,
    )

    items = SandboxTlsHttpBaselineCollector().collect(
        {"hostname": "example.com"}
    )

    assert len(items) == 1
    assert items[0].source_metadata["execution_boundary"] == "soc-sandbox"
    assert items[0].raw_data["target"] == "example.com"
