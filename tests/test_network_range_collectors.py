import pytest

from app.core.exceptions import BadRequestException
from app.osint.network_range_collectors import (
    AtlassianRangeCollector,
    CloudflareRangeCollector,
    DigitalOceanRangeCollector,
    FastlyRangeCollector,
    GitHubRangeCollector,
    GoogleCloudRangeCollector,
    GoogleServicesRangeCollector,
    Microsoft365RangeCollector,
    OracleCloudRangeCollector,
    public_network_range_collectors,
)
from app.osint.registry import CollectorRegistry


def github_payload() -> dict[str, object]:
    return {
        "hooks": ["192.30.252.0/22"],
        "web": ["192.30.252.0/22"],
        "api": ["192.30.252.0/22"],
        "git": ["192.30.252.0/22"],
        "pages": ["185.199.108.0/22"],
        "actions": [
            "4.148.0.0/16",
            "20.7.92.0/23",
            "20.22.98.0/23",
            "20.26.156.0/23",
            "2a01:111:f403::/48",
        ],
    }


def oracle_payload() -> dict[str, object]:
    return {
        "last_updated_timestamp": "2026-10-04T00:00:00.000000+00:00",
        "regions": [
            {
                "region": "mx-monterrey-1",
                "cidrs": [
                    {"cidr": "40.233.0.0/19", "tags": ["OCI"]},
                    {"cidr": "129.159.0.0/20", "tags": ["OCI"]},
                    {"cidr": "130.35.0.0/16", "tags": ["OSN"]},
                    {"cidr": "134.70.0.0/17", "tags": ["OCI"]},
                    {"cidr": "138.1.0.0/16", "tags": ["OCI"]},
                ],
                "ipv6_cidrs": [
                    {"cidr": f"2603:c02{octet:x}::/32", "tags": ["OCI"]}
                    for octet in range(5)
                ],
            }
        ],
    }


def atlassian_payload() -> dict[str, object]:
    return {
        "syncToken": 456,
        "creationDate": "2026-10-04T00:00:00.000000",
        "items": [
            {
                "cidr": f"52.82.{octet}.0/24",
                "product": ["email"],
                "direction": ["egress"],
                "perimeter": "commercial",
                "region": ["global"],
            }
            for octet in range(10)
        ],
    }


def google_services_payload() -> dict[str, object]:
    prefixes = [
        "8.8.4.0/24",
        "8.8.8.0/24",
        "35.190.0.0/17",
        "64.233.160.0/19",
        "66.102.0.0/20",
        "72.14.192.0/18",
        "74.125.0.0/16",
        "108.177.8.0/21",
        "142.250.0.0/15",
        "2001:4860::/32",
    ]
    return {
        "syncToken": "789",
        "creationTime": "2026-10-04T00:00:00.000000",
        "prefixes": [
            {"ipv6Prefix" if ":" in prefix else "ipv4Prefix": prefix}
            for prefix in prefixes
        ],
    }


def digitalocean_feed() -> str:
    return "\n".join(
        f"5.101.{octet}.0/24,NL,NL-NH,Amsterdam,1098 XH"
        for octet in range(96, 106)
    )


def microsoft_365_payload() -> list[dict[str, object]]:
    records: list[dict[str, object]] = []
    for index in range(10):
        duplicate = index == 1
        records.append(
            {
                "id": index + 1,
                "serviceArea": "SharePoint" if duplicate else "Exchange",
                "serviceAreaDisplayName": (
                    "SharePoint Online" if duplicate else "Exchange Online"
                ),
                "category": "Allow" if duplicate else "Optimize",
                "required": True,
                "ips": [
                    "13.107.0.0/24"
                    if duplicate
                    else f"13.107.{index}.0/24"
                ],
            }
        )
    return records


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
        if "digitalocean.com" in url:
            return digitalocean_feed()
        raise AssertionError(f"Unexpected URL: {url}")

    def get_json(self, url: str, **kwargs) -> object:
        self.calls.append((url, kwargs))
        if "api.github.com" in url:
            return github_payload()
        if url.endswith("/goog.json"):
            return google_services_payload()
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
        if "docs.oracle.com" in url:
            return oracle_payload()
        if "ip-ranges.atlassian.com" in url:
            return atlassian_payload()
        if "endpoints.office.com" in url:
            return microsoft_365_payload()
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

    assert len(modules) == 9
    assert len({module.name for module in modules}) == 9
    assert len({module.capability_id for module in modules}) == 9
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
    github = GitHubRangeCollector(client).collect({"ip": "192.30.252.1"})[0]
    oracle = OracleCloudRangeCollector(client).collect({"ip": "40.233.0.1"})[0]
    atlassian = AtlassianRangeCollector(client).collect({"ip": "52.82.0.1"})[0]
    google_services = GoogleServicesRangeCollector(client).collect(
        {"ip": "8.8.4.1"}
    )[0]
    digitalocean = DigitalOceanRangeCollector(client).collect(
        {"ip": "5.101.96.1"}
    )[0]
    microsoft = Microsoft365RangeCollector(client).collect(
        {"ip": "13.107.0.1"}
    )[0]

    assert cloudflare.raw_data["matched_prefix"] == "173.245.48.0/20"
    assert fastly.raw_data["matched_prefix"] == "23.235.32.0/20"
    assert google.raw_data["matched_entry"] == {
        "prefix": "34.1.0.0/16",
        "service": "Google Cloud",
        "scope": "global",
    }
    assert github.raw_data["matched_entry"] == {
        "prefix": "192.30.252.0/22",
        "services": ["api", "git", "hooks", "web"],
    }
    assert oracle.raw_data["matched_entry"] == {
        "prefix": "40.233.0.0/19",
        "region": "mx-monterrey-1",
        "tags": ["OCI"],
    }
    assert atlassian.raw_data["matched_entry"] == {
        "prefix": "52.82.0.0/24",
        "products": ["email"],
        "directions": ["egress"],
        "perimeters": ["commercial"],
        "regions": ["global"],
    }
    assert google_services.raw_data["matched_prefix"] == "8.8.4.0/24"
    assert digitalocean.raw_data["matched_entry"] == {
        "prefix": "5.101.96.0/24",
        "country_code": "NL",
        "region_code": "NL-NH",
        "city": "Amsterdam",
        "postal_code": "1098 XH",
    }
    assert microsoft.raw_data["matched_entry"] == {
        "prefix": "13.107.0.0/24",
        "service_areas": ["Exchange", "SharePoint"],
        "service_names": ["Exchange Online", "SharePoint Online"],
        "categories": ["Allow", "Optimize"],
        "required": True,
    }
    assert [call[1]["allowed_hosts"] for call in client.calls] == [
        {"www.cloudflare.com"},
        {"api.fastly.com"},
        {"www.gstatic.com"},
        {"api.github.com"},
        {"docs.oracle.com"},
        {"ip-ranges.atlassian.com"},
        {"www.gstatic.com"},
        {"www.digitalocean.com"},
        {"endpoints.office.com"},
    ]
    assert all(
        "173.245.48.1" not in url
        and "23.235.32.1" not in url
        and "34.1.2.3" not in url
        and "192.30.252.1" not in url
        and "40.233.0.1" not in url
        and "52.82.0.1" not in url
        and "8.8.4.1" not in url
        and "5.101.96.1" not in url
        and "13.107.0.1" not in url
        for url, _kwargs in client.calls
    )
    assert all("params" not in kwargs for _url, kwargs in client.calls)


def test_cloudflare_ipv6_and_negative_membership() -> None:
    client = RangeClient()
    ipv6 = CloudflareRangeCollector(client).collect({"ip": "2606:4700::1"})[0]
    oracle_ipv6 = OracleCloudRangeCollector(client).collect(
        {"ip": "2603:c020::1"}
    )[0]
    missing = FastlyRangeCollector(client).collect({"ip": "8.8.8.8"})[0]

    assert ipv6.raw_data["matched_prefix"] == "2606:4700::/32"
    assert ipv6.raw_data["address_family"] == "IPv6"
    assert oracle_ipv6.raw_data["matched_entry"]["prefix"] == "2603:c020::/32"
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


@pytest.mark.parametrize(
    "provider",
    [
        "github",
        "oracle",
        "atlassian",
        "google_services",
        "digitalocean",
        "microsoft_365",
    ],
)
def test_additional_range_collectors_reject_malformed_feeds(provider: str) -> None:
    if provider == "github":
        payload = github_payload()
        del payload["actions"]
        collector = GitHubRangeCollector(StaticJsonClient(payload))
        ip = "192.30.252.1"
        error = "GitHub"
    elif provider == "oracle":
        payload = oracle_payload()
        payload["regions"][0]["cidrs"][0]["tags"] = []
        collector = OracleCloudRangeCollector(StaticJsonClient(payload))
        ip = "40.233.0.1"
        error = "Oracle Cloud"
    elif provider == "atlassian":
        payload = atlassian_payload()
        payload["items"][0]["product"] = "email"
        collector = AtlassianRangeCollector(StaticJsonClient(payload))
        ip = "52.82.0.1"
        error = "Atlassian"
    elif provider == "google_services":
        payload = google_services_payload()
        del payload["creationTime"]
        collector = GoogleServicesRangeCollector(StaticJsonClient(payload))
        ip = "8.8.4.1"
        error = "Google services"
    elif provider == "digitalocean":
        payload = digitalocean_feed().replace(
            "5.101.96.0/24",
            "not-a-prefix",
            1,
        )
        collector = DigitalOceanRangeCollector(StaticTextClient(payload))
        ip = "5.101.96.1"
        error = "network-range"
    else:
        payload = microsoft_365_payload()
        payload[0]["required"] = "true"
        collector = Microsoft365RangeCollector(StaticJsonClient(payload))
        ip = "13.107.0.1"
        error = "Microsoft 365"

    with pytest.raises(ValueError, match=error):
        collector.collect({"ip": ip})


def test_github_rejects_oversized_range_feed() -> None:
    payload = github_payload()
    payload["actions"] = ["4.148.0.0/16"] * 10_001

    with pytest.raises(ValueError, match="GitHub"):
        GitHubRangeCollector(StaticJsonClient(payload)).collect(
            {"ip": "192.30.252.1"}
        )


def test_range_collectors_reject_private_targets() -> None:
    for collector in public_network_range_collectors(RangeClient()):
        with pytest.raises(BadRequestException):
            collector.collect({"ip": "127.0.0.1"})


def test_registry_exposes_network_range_pack() -> None:
    descriptions = {item["name"]: item for item in CollectorRegistry().describe()}
    expected = {
        "ip_atlassian_ranges",
        "ip_cloudflare_ranges",
        "ip_digitalocean_ranges",
        "ip_fastly_ranges",
        "ip_github_ranges",
        "ip_google_cloud_ranges",
        "ip_google_services_ranges",
        "ip_microsoft_365_ranges",
        "ip_oracle_cloud_ranges",
    }

    assert expected <= descriptions.keys()
    assert all(descriptions[name]["available"] for name in expected)
    assert all(
        descriptions[name]["module_family"] == "network_attribution"
        for name in expected
    )
