from copy import deepcopy

import pytest

from app.core.exceptions import BadRequestException
from app.osint.aws_ranges_collector import AwsRangeCollector


def feed():
    metadata = {"service": "AMAZON", "region": "GLOBAL", "network_border_group": "GLOBAL"}
    return {
        "syncToken": "1791222426", "createDate": "2026-10-05-17-47-06",
        "prefixes": [
            {"ip_prefix": "3.4.12.0/24", **metadata},
            {"ip_prefix": "3.4.12.0/24", **metadata, "service": "EC2"},
            *[{"ip_prefix": f"3.5.{index}.0/24", **metadata} for index in range(8)],
        ],
        "ipv6_prefixes": [
            {"ipv6_prefix": f"2600:1f00:{index:x}::/48", **metadata}
            for index in range(10)
        ],
    }


class FeedClient:
    def __init__(self, payload=None):
        self.payload = feed() if payload is None else payload
        self.calls = []

    def get_json(self, url, **kwargs):
        self.calls.append((url, kwargs))
        return self.payload


@pytest.mark.parametrize("ip", ["3.4.12.0", "3.4.12.42", "3.4.12.255"])
def test_aws_local_membership_preserves_overlapping_service_labels(ip):
    client = FeedClient()
    item = AwsRangeCollector(client).collect({"ip": ip})[0]
    assert item.raw_data["listed"] is True
    assert {entry["service"] for entry in item.raw_data["matched_entries"]} == {"AMAZON", "EC2"}
    assert item.raw_data["records_checked"] == 20
    assert item.raw_data["feed_created_at"] == "2026-10-05-17-47-06"
    assert client.calls == [(AwsRangeCollector.endpoint, {
        "allowed_hosts": {"ip-ranges.amazonaws.com"},
    })]


def test_aws_ipv6_and_unlisted_ip():
    collector = AwsRangeCollector(FeedClient())
    assert collector.collect({"ip": "2600:1f00:1::1"})[0].raw_data["listed"] is True
    item = collector.collect({"ip": "8.8.8.8"})[0]
    assert item.raw_data["listed"] is False
    assert item.raw_data["matched_entries"] == []


def test_aws_private_target_rejected_before_request():
    client = FeedClient()
    with pytest.raises(BadRequestException):
        AwsRangeCollector(client).collect({"ip": "10.0.0.1"})
    assert client.calls == []


@pytest.mark.parametrize("mutation", [
    lambda p: p.update(syncToken=True),
    lambda p: p.update(createDate="2026-99-05-17-47-06"),
    lambda p: p.update(ipv6_prefixes=[]),
    lambda p: p["prefixes"].append({"ip_prefix": "10.0.0.0/24"}),
    lambda p: p["prefixes"][0].update(ip_prefix="2600:1f00::/48"),
    lambda p: p["prefixes"][0].update(ip_prefix="3.4.12.1/24"),
    lambda p: p["prefixes"][0].update(service=""),
    lambda p: p["prefixes"][0].update(region=["GLOBAL"]),
])
def test_aws_rejects_invalid_feed_without_false_negative(mutation):
    payload = deepcopy(feed())
    mutation(payload)
    with pytest.raises((ValueError, RuntimeError)):
        AwsRangeCollector(FeedClient(payload)).collect({"ip": "8.8.8.8"})


def test_aws_bounds_records_and_matches():
    collector = AwsRangeCollector(FeedClient())
    collector.maximum_records = 19
    with pytest.raises(RuntimeError, match="record limit"):
        collector.collect({"ip": "3.4.12.1"})
    collector.maximum_records = 30_000
    collector.maximum_matches = 1
    with pytest.raises(RuntimeError, match="match limit"):
        collector.collect({"ip": "3.4.12.1"})


def test_aws_response_bound_and_registry_metadata():
    collector = AwsRangeCollector()
    assert collector.client.max_bytes == 8_000_000
    assert collector.passive and not collector.requires_api_key
    assert collector.capability_id == "network_range:aws"
