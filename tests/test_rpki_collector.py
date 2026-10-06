from copy import deepcopy

import pytest

from app.core.exceptions import BadRequestException
from app.osint.rpki_collector import IpRpkiCollector


def overview():
    return {"status": "ok", "version": "1.3", "data": {
        "resource": "1.1.1.0/24", "query_time": "2026-01-01T00:00:00",
        "type": "prefix", "announced": True, "num_filtered_out": 0,
        "asns": [{"asn": 13335, "holder": "not projected"}],
    }}


def validation(state="valid", asn="13335", prefix="1.1.1.0/24"):
    return {"status": "ok", "version": "0.3", "data": {
        "resource": asn, "prefix": prefix, "status": state, "validator": "routinator",
        "unrelated": "not projected",
    }}


class RpkiClient:
    def __init__(self, initial=None, responses=None):
        self.initial = overview() if initial is None else initial
        self.responses = [validation()] if responses is None else responses
        self.calls = []

    def get_json(self, endpoint, **kwargs):
        self.calls.append((endpoint, kwargs))
        if endpoint == IpRpkiCollector.overview_endpoint:
            return self.initial
        assert endpoint == IpRpkiCollector.endpoint
        return self.responses[len(self.calls) - 2]


@pytest.mark.parametrize("state", ["valid", "invalid_asn", "invalid_length", "unknown"])
def test_rpki_preserves_provider_states_without_maliciousness_inference(state):
    client = RpkiClient(responses=[validation(state)])
    item = IpRpkiCollector(client).collect({"ip": "1.1.1.1"})[0]
    assert item.raw_data["validations"] == [{
        "origin_asn": "AS13335", "prefix": "1.1.1.0/24", "status": state,
        "validator": "routinator",
    }]
    assert item.raw_data["origins_checked"] == 1
    assert item.discoveries == ()
    assert client.calls == [
        (IpRpkiCollector.overview_endpoint, {
            "params": {"resource": "1.1.1.1", "min_peers_seeing": 10, "max_related": 0,
                       "preferred_version": "1.3", "sourceapp": "osint-ai-framework"},
            "allowed_hosts": {"stat.ripe.net"},
        }),
        (IpRpkiCollector.endpoint, {
            "params": {"resource": "AS13335", "prefix": "1.1.1.0/24",
                       "preferred_version": "0.3", "sourceapp": "osint-ai-framework"},
            "allowed_hosts": {"stat.ripe.net"},
        }),
    ]


def test_rpki_unannounced_prefix_is_not_an_unknown_validity():
    value = overview()
    value["data"].update(announced=False, asns=[])
    client = RpkiClient(value, responses=[])
    item = IpRpkiCollector(client).collect({"ip": "1.1.1.1"})[0]
    assert item.raw_data["validations"] == []
    assert item.raw_data["announced"] is False
    assert len(client.calls) == 1


def test_rpki_checks_all_origins_in_deterministic_order():
    value = overview()
    value["data"]["asns"] = [{"asn": 15169}, {"asn": 13335}]
    client = RpkiClient(value, [validation(), validation("invalid_asn", "15169")])
    item = IpRpkiCollector(client).collect({"ip": "1.1.1.1"})[0]
    assert [row["origin_asn"] for row in item.raw_data["validations"]] == ["AS13335", "AS15169"]


def test_rpki_ipv6_uses_the_exact_observed_prefix():
    value = overview()
    value["data"].update(resource="2606:4700:4700::/48")
    client = RpkiClient(value, [validation(prefix="2606:4700:4700::/48")])
    item = IpRpkiCollector(client).collect({"ip": "2606:4700:4700::1111"})[0]
    assert item.raw_data["prefix"] == "2606:4700:4700::/48"


@pytest.mark.parametrize("target", ["127.0.0.1", "http://1.1.1.1", None])
def test_rpki_rejects_unsafe_target_before_fetch(target):
    client = RpkiClient()
    with pytest.raises(BadRequestException):
        IpRpkiCollector(client).collect({"ip": target})
    assert client.calls == []


@pytest.mark.parametrize("mutation", [
    lambda p: p.update(status="error"),
    lambda p: p.update(version="2.0"),
    lambda p: p.update(data=[]),
    lambda p: p["data"].update(resource="8.8.8.0/24"),
    lambda p: p["data"].update(resource="2606:4700:4700::/48"),
    lambda p: p["data"].update(resource="1.1.1.1/24"),
    lambda p: p["data"].update(query_time="2099-01-01T00:00:00"),
    lambda p: p["data"].update(announced="true"),
    lambda p: p["data"].update(announced=False),
    lambda p: p["data"].update(asns=[]),
    lambda p: p["data"].update(num_filtered_out=True),
    lambda p: p["data"]["asns"][0].update(asn=True),
    lambda p: p["data"]["asns"][0].update(asn=0),
    lambda p: p["data"]["asns"].append(deepcopy(p["data"]["asns"][0])),
    lambda p: p["data"].update(asns=[{"asn": n} for n in range(1, 7)]),
])
def test_rpki_rejects_invalid_overview_before_validation_requests(mutation):
    value = overview()
    mutation(value)
    client = RpkiClient(value)
    with pytest.raises(ValueError):
        IpRpkiCollector(client).collect({"ip": "1.1.1.1"})
    assert len(client.calls) == 1


@pytest.mark.parametrize("mutation", [
    lambda p: p.update(status="error"),
    lambda p: p.update(version="1.0"),
    lambda p: p["data"].update(resource="15169"),
    lambda p: p["data"].update(prefix="1.1.0.0/16"),
    lambda p: p["data"].update(status="malicious"),
    lambda p: p["data"].update(status=[]),
    lambda p: p["data"].update(validator=None),
])
def test_rpki_rejects_invalid_validation_without_emitting_evidence(mutation):
    value = validation()
    mutation(value)
    with pytest.raises(ValueError):
        IpRpkiCollector(RpkiClient(responses=[value])).collect({"ip": "1.1.1.1"})


def test_rpki_multi_origin_failure_does_not_return_partial_evidence():
    value = overview()
    value["data"]["asns"] = [{"asn": 13335}, {"asn": 15169}]
    client = RpkiClient(value, [validation(), {"status": "error"}])
    with pytest.raises(ValueError):
        IpRpkiCollector(client).collect({"ip": "1.1.1.1"})
    assert len(client.calls) == 3
