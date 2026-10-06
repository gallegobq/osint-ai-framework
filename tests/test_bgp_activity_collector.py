from copy import deepcopy
from datetime import datetime, timedelta, timezone

import pytest

from app.core.exceptions import BadRequestException
from app.osint.bgp_activity_collector import AsnBgpActivityCollector


def response():
    end = datetime.now(timezone.utc).replace(minute=0, second=0, microsecond=0) - timedelta(hours=4)
    start = end - timedelta(hours=24)
    return {"status": "ok", "version": "1.5", "data": {
        "resource": "3333", "resource_type": "asn", "sampling_period": 3600.0,
        "query_starttime": start.isoformat(), "query_endtime": end.isoformat(),
        "updates": [{"starttime": (start + timedelta(hours=n)).isoformat(),
                     "announcements": n, "withdrawals": None} for n in range(24)],
        "related_prefixes": ["not projected"],
    }}


class ActivityClient:
    def __init__(self, payload=None):
        self.payload = response() if payload is None else payload
        self.calls = []

    def get_json(self, url, **kwargs):
        self.calls.append((url, kwargs))
        return self.payload


def test_bgp_activity_projects_bounded_counts_with_unavailable_withdrawals():
    client = ActivityClient()
    collector = AsnBgpActivityCollector(client)
    item = collector.collect({"asn": "3333"})[0]
    data = item.raw_data
    assert data["asn"] == "AS3333"
    assert data["sampled_announcements"] == sum(range(24))
    assert data["records_checked"] == 24
    assert data["complete_sample_coverage"] is True
    assert data["withdrawals_available"] is False
    assert data["sampled_withdrawals"] is None
    assert "related_prefixes" not in data
    assert item.discoveries == ()
    assert collector.passive and not collector.requires_api_key
    assert client.calls == [(collector.endpoint, {
        "params": {"resource": "AS3333", "preferred_version": "1.5", "num_hours": 24,
                   "max_samples": 24, "min_sampling_period": 3600,
                   "hide_empty_samples": "false", "sourceapp": "osint-ai-framework"},
        "allowed_hosts": {"stat.ripe.net"},
    })]


@pytest.mark.parametrize("remaining", [[], [0, 2, 23]])
def test_bgp_activity_does_not_fill_missing_samples_or_claim_full_coverage(remaining):
    payload = response()
    payload["data"]["updates"] = [payload["data"]["updates"][n] for n in remaining]
    data = AsnBgpActivityCollector(ActivityClient(payload)).collect({"asn": "AS3333"})[0].raw_data
    assert len(data["samples"]) == len(remaining)
    assert data["sampled_announcements"] == sum(remaining)
    assert data["complete_sample_coverage"] is False
    assert data["sampled_withdrawals"] is None


@pytest.mark.parametrize("target", [None, "AS0", "AS4294967296", "3333/24", "https://evil.test"])
def test_bgp_activity_rejects_bad_asn_before_network(target):
    client = ActivityClient()
    with pytest.raises(BadRequestException):
        AsnBgpActivityCollector(client).collect({"asn": target})
    assert client.calls == []


@pytest.mark.parametrize("field,value", [
    ("resource", "3334"), ("resource", True), ("resource_type", 4),
    ("sampling_period", True), ("sampling_period", float("nan")),
    ("sampling_period", float("inf")), ("sampling_period", 60),
    ("sampling_period", 86401), ("query_starttime", "bad"),
    ("query_endtime", "2099-01-01T00:00:00Z"), ("updates", {}), ("updates", [None]),
])
def test_bgp_activity_rejects_invalid_identity_window_sampling_or_records(field, value):
    payload = response()
    payload["data"][field] = value
    with pytest.raises(ValueError):
        AsnBgpActivityCollector(ActivityClient(payload)).collect({"asn": "3333"})


@pytest.mark.parametrize("field,value", [
    ("announcements", True), ("announcements", -1), ("announcements", 1.5),
    ("announcements", 2**63), ("withdrawals", 0), ("withdrawals", "unknown"),
    ("starttime", "2099-01-01T00:00:00Z"),
])
def test_bgp_activity_rejects_invalid_sample_counts_or_time(field, value):
    payload = response()
    payload["data"]["updates"][-1][field] = value
    with pytest.raises(ValueError):
        AsnBgpActivityCollector(ActivityClient(payload)).collect({"asn": "3333"})


@pytest.mark.parametrize("change", ["duplicate", "reverse", "unaligned", "oversize", "missing"])
def test_bgp_activity_rejects_duplicate_unordered_overflow_or_missing_fields(change):
    payload = response()
    rows = payload["data"]["updates"]
    if change == "duplicate":
        rows[-1] = deepcopy(rows[-2])
    elif change == "reverse":
        rows.reverse()
    elif change == "unaligned":
        rows[0]["starttime"] = (datetime.fromisoformat(rows[0]["starttime"])
                                + timedelta(minutes=1)).isoformat()
    elif change == "oversize":
        rows.append(deepcopy(rows[-1]))
    else:
        del rows[-1]["withdrawals"]
    with pytest.raises(ValueError):
        AsnBgpActivityCollector(ActivityClient(payload)).collect({"asn": "3333"})


@pytest.mark.parametrize("status,version", [("error", "1.5"), ("ok", "1.4")])
def test_bgp_activity_rejects_provider_errors_or_schema_drift(status, version):
    payload = response()
    payload.update(status=status, version=version)
    with pytest.raises(ValueError):
        AsnBgpActivityCollector(ActivityClient(payload)).collect({"asn": "3333"})


def test_bgp_activity_rejects_window_over_24_hours():
    payload = response()
    payload["data"]["query_starttime"] = (
        datetime.fromisoformat(payload["data"]["query_starttime"]) - timedelta(hours=1)
    ).isoformat()
    with pytest.raises(ValueError):
        AsnBgpActivityCollector(ActivityClient(payload)).collect({"asn": "3333"})
