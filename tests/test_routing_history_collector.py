import pytest

from app.core.exceptions import BadRequestException
from app.osint.routing_history_collector import IpRoutingHistoryCollector


class HistoryClient:
    def __init__(self, mutation=None):
        self.mutation = mutation
        self.calls = []

    def get_json(self, url, **kwargs):
        self.calls.append((url, kwargs))
        params = kwargs["params"]
        prefix = "8.8.8.0/24" if ":" not in params["resource"] else "2606:4700::/32"
        data = {
            "resource": params["resource"],
            "query_starttime": params["starttime"], "query_endtime": params["endtime"],
            "by_origin": [{"origin": "15169", "prefixes": [{
                "prefix": prefix, "timelines": [{
                    "starttime": params["starttime"], "endtime": params["endtime"],
                    "full_peers_seeing": 328.0,
                }],
            }]}],
            "private_contact": "excluded@example.com",
        }
        payload = {"status": "ok", "data": data}
        if self.mutation:
            self.mutation(payload)
        return payload


@pytest.mark.parametrize("ip", ["8.8.8.8", "2606:4700:4700::1111"])
def test_history_preserves_only_bounded_temporal_routing_projection(ip):
    client = HistoryClient()
    item = IpRoutingHistoryCollector(client).collect({"ip": ip})[0]
    assert item.raw_data["observed"] is True
    assert item.raw_data["routes"][0]["origin_asn"] == "AS15169"
    assert item.raw_data["routes"][0]["timelines"][0]["full_peers_seeing"] == 328.0
    assert "private_contact" not in item.raw_data
    url, request = client.calls[0]
    assert url == IpRoutingHistoryCollector.endpoint
    assert request["allowed_hosts"] == {"stat.ripe.net"}
    assert request["params"]["resource"] == ip
    assert request["params"]["max_rows"] == 100
    assert request["params"]["include_first_hop"] == "false"


def test_history_accepts_valid_empty_observation():
    item = IpRoutingHistoryCollector(HistoryClient(
        lambda p: p["data"].update(by_origin=[]),
    )).collect({"ip": "8.8.8.8"})[0]
    assert item.raw_data["observed"] is False
    assert item.raw_data["routes"] == []


def test_history_rejects_private_target_before_provider_call():
    client = HistoryClient()
    with pytest.raises(BadRequestException):
        IpRoutingHistoryCollector(client).collect({"ip": "127.0.0.1"})
    assert client.calls == []


@pytest.mark.parametrize("mutation", [
    lambda p: p.update(status="error"),
    lambda p: p["data"].update(resource="1.1.1.1"),
    lambda p: p["data"].update(query_starttime="invalid"),
    lambda p: p["data"].update(query_endtime="2099-01-01T00:00:00"),
    lambda p: p["data"].update(by_origin=None),
    lambda p: p["data"]["by_origin"][0].update(origin="0"),
    lambda p: p["data"]["by_origin"][0]["prefixes"][0].update(prefix="1.1.1.0/24"),
    lambda p: p["data"]["by_origin"][0]["prefixes"][0].update(timelines=[]),
    lambda p: p["data"]["by_origin"][0]["prefixes"][0]["timelines"][0].update(full_peers_seeing=True),
    lambda p: p["data"]["by_origin"][0]["prefixes"][0]["timelines"][0].update(full_peers_seeing=float("nan")),
    lambda p: p["data"]["by_origin"][0]["prefixes"][0]["timelines"][0].update(starttime="2099-01-01T00:00:00"),
])
def test_history_rejects_malformed_or_mismatched_response(mutation):
    with pytest.raises((ValueError, RuntimeError)):
        IpRoutingHistoryCollector(HistoryClient(mutation)).collect({"ip": "8.8.8.8"})


def test_history_enforces_hard_limits_despite_provider_soft_limit():
    collector = IpRoutingHistoryCollector(HistoryClient())
    collector.maximum_routes = 0
    with pytest.raises(ValueError):
        collector.collect({"ip": "8.8.8.8"})
    collector.maximum_routes = 100
    collector.maximum_timelines = 0
    with pytest.raises(RuntimeError, match="timeline limit"):
        collector.collect({"ip": "8.8.8.8"})
