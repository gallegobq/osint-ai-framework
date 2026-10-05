from copy import deepcopy

import pytest

from app.core.exceptions import BadRequestException
from app.osint.as_path_length_collector import AsPathLengthCollector


def payload():
    return {"status": "ok", "version": "2.1", "data": {
        "resource": "3333", "query_time": "2026-10-05T16:00:00",
        "stats": [{"number": 0, "count": 2, "location": "RIS Amsterdam",
                   "stripped": {"min": 1, "max": 3, "sum": 4, "avg": 2.0},
                   "unstripped": {"min": 1, "max": 5, "sum": 6, "avg": 3.0}}],
        "unrelated_data": "excluded",
    }}


class MetricsClient:
    def __init__(self, value=None):
        self.value = payload() if value is None else value
        self.calls = []

    def get_json(self, url, **kwargs):
        self.calls.append((url, kwargs))
        return self.value


def test_path_length_preserves_both_prepending_projections_as_one_capability():
    client = MetricsClient()
    item = AsPathLengthCollector(client).collect({"asn": "3333"})[0]
    record = item.raw_data["collectors"][0]
    assert record["including_prepending"]["avg"] == 3.0
    assert record["excluding_prepending"]["avg"] == 2.0
    assert record["route_count"] == 2
    assert "unrelated_data" not in item.raw_data
    assert item.discoveries == ()
    assert client.calls == [(AsPathLengthCollector.endpoint, {
        "params": {"resource": "AS3333", "preferred_version": "2.1", "sort_by": "number",
                   "sourceapp": "osint-ai-framework"},
        "allowed_hosts": {"stat.ripe.net"},
    })]


def test_path_length_accepts_empty_observation():
    value = payload()
    value["data"]["stats"] = []
    item = AsPathLengthCollector(MetricsClient(value)).collect({"asn": "AS3333"})[0]
    assert item.raw_data["observed"] is False
    assert item.raw_data["collectors"] == []


def test_path_length_rejects_target_before_request():
    client = MetricsClient()
    with pytest.raises(BadRequestException):
        AsPathLengthCollector(client).collect({"asn": "AS0"})
    assert client.calls == []


@pytest.mark.parametrize("mutation", [
    lambda p: p.update(status="error"),
    lambda p: p.update(version="3.0"),
    lambda p: p["data"].update(resource="15169"),
    lambda p: p["data"].update(query_time="2099-01-01T00:00:00"),
    lambda p: p["data"].update(stats=None),
    lambda p: p["data"]["stats"][0].update(count=True),
    lambda p: p["data"]["stats"][0].update(location=None),
    lambda p: p["data"]["stats"][0]["stripped"].update(avg=float("nan")),
    lambda p: p["data"]["stats"][0]["stripped"].update(sum=100),
    lambda p: p["data"]["stats"][0]["stripped"].update(min=4),
    lambda p: p["data"]["stats"][0].update(unstripped={"min": 0, "max": 2, "sum": 2, "avg": 1.0}),
    lambda p: p["data"]["stats"].append(deepcopy(p["data"]["stats"][0])),
])
def test_path_length_rejects_invalid_or_inconsistent_provider_data(mutation):
    value = payload()
    mutation(value)
    with pytest.raises(ValueError):
        AsPathLengthCollector(MetricsClient(value)).collect({"asn": "AS3333"})


def test_path_length_caps_route_collectors():
    collector = AsPathLengthCollector(MetricsClient())
    collector.maximum_collectors = 0
    with pytest.raises(ValueError, match="oversized"):
        collector.collect({"asn": "AS3333"})
