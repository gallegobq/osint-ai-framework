import pytest

from app.core.exceptions import BadRequestException
from app.osint.dshield_collector import DshieldSubnetCollector


HEADER = "# DShield.org Recommended Block List\n# updated: 2026-10-05T19:01:08\n"
ROW = "8.8.8.0\t8.8.8.255\t24\t42\tExample Network\tUS\tcontact@example.com"


class FeedClient:
    def __init__(self, body=HEADER + ROW):
        self.body = body
        self.calls = []

    def get_text(self, url, **kwargs):
        self.calls.append((url, kwargs))
        return self.body


@pytest.mark.parametrize("ip", ["8.8.8.0", "8.8.8.8", "8.8.8.255"])
def test_dshield_checks_entire_subnet_locally_and_omits_contact(ip):
    client = FeedClient()
    item = DshieldSubnetCollector(client).collect({"ip": ip})[0]

    assert item.raw_data["listed"] is True
    assert item.raw_data["matches"] == [{
        "cidr": "8.8.8.0/24", "reporting_targets": 42,
        "network_name": "Example Network", "country": "US",
    }]
    assert item.raw_data["match_basis"] == "subnet_membership"
    assert "contact@example.com" not in item.content
    assert client.calls == [(DshieldSubnetCollector.feed_url, {
        "headers": {"Accept": "text/plain"},
        "allowed_hosts": {"feeds.dshield.org"},
    })]


@pytest.mark.parametrize("ip", ["8.8.9.0", "2606:4700:4700::1111"])
def test_dshield_does_not_match_adjacent_network_or_other_ip_version(ip):
    item = DshieldSubnetCollector(FeedClient()).collect({"ip": ip})[0]
    assert item.raw_data["listed"] is False
    assert item.raw_data["matches"] == []


def test_dshield_rejects_private_target_before_fetching():
    client = FeedClient()
    with pytest.raises(BadRequestException):
        DshieldSubnetCollector(client).collect({"ip": "127.0.0.1"})
    assert client.calls == []


@pytest.mark.parametrize("body", [
    "<html>Unavailable</html>", HEADER,
    HEADER + ROW.replace("8.8.8.255", "8.8.8.254"),
    HEADER + ROW.replace("\t42\t", "\t-1\t"),
    HEADER.replace("2026-10-05T19:01:08", "invalid") + ROW,
    HEADER + ROW + "\nmalformed row",
])
def test_dshield_rejects_invalid_or_incomplete_feed_instead_of_false_negative(body):
    with pytest.raises((ValueError, RuntimeError)):
        DshieldSubnetCollector(FeedClient(body)).collect({"ip": "8.8.9.1"})


def test_dshield_rejects_oversized_feed_even_after_matching():
    body = HEADER + "\n".join([ROW] * (DshieldSubnetCollector.maximum_entries + 1))
    with pytest.raises(RuntimeError, match="safe entry limit"):
        DshieldSubnetCollector(FeedClient(body)).collect({"ip": "8.8.8.8"})
