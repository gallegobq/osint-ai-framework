import pytest

from app.core.exceptions import BadRequestException
from app.osint.network_range_collectors import (
    CloudflareRangeCollector,
    FastlyRangeCollector,
    GoogleCloudRangeCollector,
    public_network_range_collectors,
)
from app.osint.registry import CollectorRegistry


class RangeClient:
    def __init__(self) -> None:
        self.calls: list[tuple[str, dict]] = []

    def get_text(self, url: str, **kwargs) -> str:
        self.calls.append((url, kwargs))
        if url.endswith("ips-v4"):
            return "\n".join(
                [
                    "173.245.48.0/20",
                    "103.21.244.0/22",
                    "103.22.200.0/22",
                    "103.31.4.0/22",
                    "141.101.64.0/18",
                ]
            )
        if url.endswith("ips-v6"):
            return "\n".join(
                [
                    "2400:cb00::/32",
                    "2606:4700::/32",
                    "2803:f800::/32",
                    "2405:b500::/32",
                    "2405:8100::/32",
                ]
            )
        raise AssertionError(f"Unexpected URL: {url}")

    def get_json(self, url: str, **kwargs) -> object:
        self.calls.append((url, kwargs))
        if "fastly.com" in url:
            return {
                "addresses": ["23.235.32.0/20", "151.101.0.0/16"],
                "ipv6_addresses": ["2a04:4e40::/32"],
            }
        if "gstatic.com" in url:
            return {
                "syncToken": "123",
                "creationTime": "2026-10-04T00:00:00.000000",
                "prefixes": [
                    {
                        "ipv4Prefix": f"34.{octet}.0.0/16",
                        "service": "Google Cloud",
                        "scope": "global",
                    }
                    for octet in range(1, 11)
                ],
            }
        raise AssertionError(f"Unexpected URL: {url}")


class StaticTextClient:
    def __init__(self, value: str) -> None:
        self.value = value

    def get_text(self, _url: str, **_kwargs) -> str:
        return self.value


class StaticJsonClient:
    def __init__(self, value: object) -> None:
        self.value = value

    def get_json(self, _url: str, **_kwargs) -> object:
        return self.value


def test_public_network_range_pack_is_unique_passive_and_traceable() -> None:
    modules = public_network_range_collectors(RangeClient())

    assert len(modules) == 3
    assert len({module.name for module in modules}) == 3
    assert len({module.capability_id for module in modules}) == 3
    assert all(module.passive and not module.requires_api_key for module in modules)
    assert all(module.provider and module.reference_url for module in modules)
    assert all(module.module_family == "network_attribution" for module in modules)


def test_range_collectors_match_locally_without_transmitting_the_ip() -> None:
    client = RangeClient()
    cloudflare = CloudflareRangeCollector(client).collect(
        {"ip": "173.245.48.1"}
    )[0]
    fastly = FastlyRangeCollector(client).collect({"ip": "23.235.32.1"})[0]
    google = GoogleCloudRangeCollector(client).collect({"ip": "34.1.2.3"})[0]

    assert cloudflare.raw_data["matched_prefix"] == "173.245.48.0/20"
    assert fastly.raw_data["matched_prefix"] == "23.235.32.0/20"
    assert google.raw_data["matched_entry"] == {
        "prefix": "34.1.0.0/16",
        "service": "Google Cloud",
        "scope": "global",
    }
    assert [call[1]["allowed_hosts"] for call in client.calls] == [
        {"www.cloudflare.com"},
        {"api.fastly.com"},
        {"www.gstatic.com"},
    ]
    assert all(
        "173.245.48.1" not in url
        and "23.235.32.1" not in url
        and "34.1.2.3" not in url
        for url, _kwargs in client.calls
    )
    assert all("params" not in kwargs for _url, kwargs in client.calls)


def test_cloudflare_ipv6_and_negative_membership() -> None:
    client = RangeClient()
    ipv6 = CloudflareRangeCollector(client).collect({"ip": "2606:4700::1"})[0]
    missing = FastlyRangeCollector(client).collect({"ip": "8.8.8.8"})[0]

    assert ipv6.raw_data["matched_prefix"] == "2606:4700::/32"
    assert ipv6.raw_data["address_family"] == "IPv6"
    assert missing.raw_data["listed"] is False
    assert missing.raw_data["matched_prefix"] is None


def test_cloudflare_rejects_empty_or_too_small_feeds() -> None:
    with pytest.raises(RuntimeError, match="enough entries"):
        CloudflareRangeCollector(
            StaticTextClient("173.245.48.0/20\n")
        ).collect({"ip": "173.245.48.1"})


def test_fastly_rejects_wrong_family_entries() -> None:
    payload = {
        "addresses": ["2a04:4e40::/32"],
        "ipv6_addresses": ["2a04:4e40::/32"],
    }

    with pytest.raises(ValueError, match="network-range"):
        FastlyRangeCollector(StaticJsonClient(payload)).collect(
            {"ip": "23.235.32.1"}
        )


@pytest.mark.parametrize(
    "mutation",
    ["wrong_service", "duplicate_prefix", "missing_metadata"],
)
def test_google_cloud_rejects_malformed_feed(mutation: str) -> None:
    payload = RangeClient().get_json(
        "https://www.gstatic.com/ipranges/cloud.json"
    )
    assert isinstance(payload, dict)
    if mutation == "wrong_service":
        payload["prefixes"][0]["service"] = "Other"
    elif mutation == "duplicate_prefix":
        payload["prefixes"][1]["ipv4Prefix"] = payload["prefixes"][0][
            "ipv4Prefix"
        ]
    else:
        payload["syncToken"] = None

    with pytest.raises(ValueError, match="Google Cloud"):
        GoogleCloudRangeCollector(StaticJsonClient(payload)).collect(
            {"ip": "34.1.2.3"}
        )


def test_range_collectors_reject_private_targets() -> None:
    for collector in public_network_range_collectors(RangeClient()):
        with pytest.raises(BadRequestException):
            collector.collect({"ip": "127.0.0.1"})


def test_registry_exposes_network_range_pack() -> None:
    descriptions = {item["name"]: item for item in CollectorRegistry().describe()}
    expected = {
        "ip_cloudflare_ranges",
        "ip_fastly_ranges",
        "ip_google_cloud_ranges",
    }

    assert expected <= descriptions.keys()
    assert all(descriptions[name]["available"] for name in expected)
    assert all(
        descriptions[name]["module_family"] == "network_attribution"
        for name in expected
    )
