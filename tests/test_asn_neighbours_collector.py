from copy import deepcopy

import pytest

from app.core.exceptions import BadRequestException
from app.osint.asn_neighbours_collector import AsnNeighboursCollector


def payload():
    return {"status": "ok", "version": "3.2", "data": {
        "resource": "3333", "query_starttime": "2026-10-05T00:00:00",
        "query_endtime": "2026-10-05T00:00:00",
        "neighbours": [
            {"asn": 1103, "type": "left", "power": 12, "v4_peers": 34, "v6_peers": 5},
            {"asn": 12654, "type": "right", "power": 3, "v4_peers": 0, "v6_peers": 6},
            {"asn": 6939, "type": "uncertain", "power": 100, "v4_peers": 7, "v6_peers": 8},
        ], "unrelated_contact": "omit@example.com",
    }}


class NeighbourClient:
    def __init__(self, value=None):
        self.value = payload() if value is None else value
        self.calls = []

    def get_json(self, url, **kwargs):
        self.calls.append((url, kwargs))
        return self.value


def test_neighbours_preserve_uncertainty_and_emit_only_bounded_observed_targets():
    client = NeighbourClient()
    item = AsnNeighboursCollector(client).collect({"asn": "3333"})[0]
    assert item.raw_data["position_record_counts"] == {"left": 1, "right": 1, "uncertain": 1}
    assert item.raw_data["neighbours"][-1]["position"] == "uncertain"
    assert {target.value for target in item.discoveries} == {"AS1103", "AS12654"}
    assert all(target.relation == "observed_bgp_neighbour" for target in item.discoveries)
    assert "unrelated_contact" not in item.raw_data
    assert client.calls == [(AsnNeighboursCollector.endpoint, {
        "params": {"resource": "AS3333", "preferred_version": "3.2", "sourceapp": "osint-ai-framework"},
        "allowed_hosts": {"stat.ripe.net"},
    })]


def test_neighbours_report_truncation_and_bound_discoveries_without_skipping_validation():
    collector = AsnNeighboursCollector(NeighbourClient())
    collector.maximum_results = 1
    collector.maximum_discoveries = 1
    item = collector.collect({"asn": "AS3333"})[0]
    assert item.raw_data["truncated"] is True
    assert item.raw_data["omitted_records"] == 2
    assert item.raw_data["records_checked"] == 3
    assert len(item.discoveries) == 1


def test_neighbours_accept_empty_observation_without_inventing_relations():
    value = payload()
    value["data"]["neighbours"] = []
    item = AsnNeighboursCollector(NeighbourClient(value)).collect({"asn": "AS3333"})[0]
    assert item.raw_data["neighbours"] == []
    assert item.discoveries == ()


@pytest.mark.parametrize("asn", ["AS0", "AS4294967296", "https://localhost", None])
def test_neighbours_reject_invalid_targets_before_request(asn):
    client = NeighbourClient()
    with pytest.raises(BadRequestException):
        AsnNeighboursCollector(client).collect({"asn": asn})
    assert client.calls == []


@pytest.mark.parametrize("mutation", [
    lambda p: p.update(status="error"),
    lambda p: p.update(version="4.1"),
    lambda p: p["data"].update(resource="15169"),
    lambda p: p["data"].update(query_endtime="2099-01-01T00:00:00"),
    lambda p: p["data"]["neighbours"][0].update(asn=True),
    lambda p: p["data"]["neighbours"][0].update(type="upstream"),
    lambda p: p["data"]["neighbours"][-1].update(power=-1),
    lambda p: p["data"]["neighbours"][0].update(v4_peers=float("nan")),
    lambda p: p["data"]["neighbours"].append({"asn": 0, "type": "left", "power": 1}),
])
def test_neighbours_reject_invalid_identity_time_and_records_even_beyond_output_limit(mutation):
    value = payload()
    mutation(value)
    collector = AsnNeighboursCollector(NeighbourClient(value))
    collector.maximum_results = 1
    with pytest.raises(ValueError):
        collector.collect({"asn": "AS3333"})


def test_neighbours_reject_oversized_input():
    collector = AsnNeighboursCollector(NeighbourClient())
    collector.maximum_records = 2
    with pytest.raises(ValueError, match="oversized"):
        collector.collect({"asn": "AS3333"})


def test_neighbours_preserve_repeated_ris_observations_without_summing_or_discovering_uncertain_asns():
    value = payload()
    repeated = deepcopy(value["data"]["neighbours"][-1])
    repeated["v4_peers"] = 9
    value["data"]["neighbours"].append(repeated)
    item = AsnNeighboursCollector(NeighbourClient(value)).collect({"asn": "AS3333"})[0]
    assert item.raw_data["unique_asns"] == 3
    assert item.raw_data["repeated_asn_position_records"] == 1
    assert item.raw_data["position_record_counts"]["uncertain"] == 2
    assert len(item.raw_data["neighbours"]) == 4
    assert {target.value for target in item.discoveries} == {"AS1103", "AS12654"}
