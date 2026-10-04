import pytest

from app.core.exceptions import BadRequestException
from app.osint.registry import CollectorRegistry
from app.osint.url_feed_collectors import (
    MAX_URL_FEED_ENTRIES,
    URL_FEED_SPECS,
    UrlFeedMembershipCollector,
    public_url_feed_collectors,
)


TARGET_URL = "https://phish5.example.com/path"


def url_feed(size: int) -> str:
    return "\n".join(
        f"https://phish{index}.example.com/path"
        for index in range(size)
    )


class UrlFeedClient:
    def __init__(self, body: str | None = None) -> None:
        self.body = body
        self.calls: list[tuple[str, dict]] = []

    def get_text(self, url: str, **kwargs) -> str:
        self.calls.append((url, kwargs))
        if self.body is not None:
            return self.body
        size = 100 if "openphish/public_feed" in url else 1_000
        return url_feed(size)


def test_public_url_feed_pack_is_unique_passive_and_traceable() -> None:
    modules = public_url_feed_collectors(UrlFeedClient())

    assert len(modules) == 2
    assert len({module.name for module in modules}) == 2
    assert len({module.capability_id for module in modules}) == 2
    assert all(module.passive and not module.requires_api_key for module in modules)
    assert all(module.provider and module.reference_url for module in modules)
    assert all(module.module_family == "threat_feed" for module in modules)


@pytest.mark.parametrize("spec", URL_FEED_SPECS)
def test_url_feed_match_is_local_and_does_not_transmit_target(spec) -> None:
    client = UrlFeedClient()

    item = UrlFeedMembershipCollector(spec, client).collect(
        {"url": TARGET_URL}
    )[0]

    assert item.raw_data["listed"] is True
    assert item.raw_data["entries_checked"] >= spec.minimum_entries
    assert client.calls == [
        (
            spec.feed_url,
            {
                "headers": {"Accept": "text/plain"},
                "allowed_hosts": {spec.allowed_host},
            },
        )
    ]
    assert TARGET_URL not in client.calls[0][0]
    assert "params" not in client.calls[0][1]


def test_url_feed_membership_is_exact_after_normalization() -> None:
    item = UrlFeedMembershipCollector(
        URL_FEED_SPECS[0],
        UrlFeedClient(),
    ).collect({"url": "https://phish5.example.com/other"})[0]

    assert item.raw_data["listed"] is False


@pytest.mark.parametrize("spec", URL_FEED_SPECS)
def test_url_feed_rejects_empty_or_truncated_response(spec) -> None:
    client = UrlFeedClient("# unavailable\nhttps://only.example.com/")

    with pytest.raises(RuntimeError, match="safe number"):
        UrlFeedMembershipCollector(spec, client).collect(
            {"url": TARGET_URL}
        )


def test_url_feed_collectors_reject_private_targets_before_fetching() -> None:
    client = UrlFeedClient()

    for collector in public_url_feed_collectors(client):
        with pytest.raises(BadRequestException):
            collector.collect({"url": "http://127.0.0.1/private"})

    assert client.calls == []


def test_url_feed_rejects_oversized_response() -> None:
    body = "\n".join(
        ["https://oversized.example.com/path"] * (MAX_URL_FEED_ENTRIES + 1)
    )

    with pytest.raises(RuntimeError, match="safe number"):
        UrlFeedMembershipCollector(
            URL_FEED_SPECS[0],
            UrlFeedClient(body),
        ).collect({"url": TARGET_URL})


def test_registry_exposes_public_url_feed_pack() -> None:
    descriptions = {item["name"]: item for item in CollectorRegistry().describe()}
    expected = {"url_openphish_feed", "url_urlhaus_recent"}

    assert expected <= descriptions.keys()
    assert all(descriptions[name]["available"] for name in expected)
    assert all(
        descriptions[name]["module_family"] == "threat_feed"
        for name in expected
    )
