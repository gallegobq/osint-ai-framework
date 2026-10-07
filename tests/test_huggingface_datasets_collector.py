from copy import deepcopy

import pytest

from app.core.exceptions import BadRequestException
from app.osint.huggingface_datasets_collector import HuggingFaceDatasetsCollector
from app.osint.registry import CollectorRegistry


def dataset():
    return {"id": "google/example-data", "author": "google", "private": False,
            "downloads": 100, "likes": 3, "lastModified": "2026-01-01T00:00:00Z",
            "gated": False, "disabled": False, "cardData": {"text": "not projected"},
            "siblings": ["private-looking.csv"], "description": "not projected"}


class HubClient:
    def __init__(self, value=None):
        self.value = [dataset()] if value is None else value
        self.calls = []

    def get_json(self, url, **kwargs):
        self.calls.append((url, kwargs))
        return self.value


def test_datasets_projects_only_public_metadata_and_fixed_provider():
    client = HubClient()
    collector = HuggingFaceDatasetsCollector(client)
    item = collector.collect({"username": "google"})[0]
    assert item.raw_data["datasets"] == [{
        "dataset_id": "google/example-data", "author": "google", "downloads": 100,
        "likes": 3, "last_modified": "2026-01-01T00:00:00+00:00",
        "gated": False, "disabled": False,
        "url": "https://huggingface.co/datasets/google/example-data",
    }]
    assert item.discoveries == ()
    assert item.source_type == "dataset_registry"
    assert item.raw_data["truncated"] is False
    assert client.calls == [(collector.endpoint, {
        "params": {"author": "google", "limit": 26, "sort": "downloads",
                   "expand": list(collector.expanded_fields)},
        "allowed_hosts": {"huggingface.co"},
    })]


@pytest.mark.parametrize("gated", [False, True, "auto", "manual"])
def test_datasets_preserves_gated_disabled_state_without_access_attempt(gated):
    row = {**dataset(), "gated": gated, "disabled": True}
    client = HubClient([row])
    result = HuggingFaceDatasetsCollector(client).collect({"username": "google"})[0]
    assert result.raw_data["datasets"][0]["gated"] == gated
    assert result.raw_data["datasets"][0]["disabled"] is True
    assert len(client.calls) == 1


def test_datasets_null_metrics_and_case_insensitive_namespace():
    row = {**dataset(), "downloads": None, "likes": None, "lastModified": None}
    result = HuggingFaceDatasetsCollector(HubClient([row])).collect({"username": "Google"})[0]
    assert result.raw_data["datasets"][0]["last_modified"] is None
    assert result.raw_data["datasets"][0]["downloads"] is None


def test_datasets_empty_catalog_is_not_missing_identity():
    result = HuggingFaceDatasetsCollector(HubClient([])).collect({"username": "google"})[0]
    assert result.raw_data["datasets"] == []
    assert "account_exists" not in result.raw_data


@pytest.mark.parametrize("target", [None, "../google", "google/name", "google.example"])
def test_datasets_invalid_target_never_fetches(target):
    client = HubClient()
    with pytest.raises(BadRequestException):
        HuggingFaceDatasetsCollector(client).collect({"username": target})
    assert client.calls == []


@pytest.mark.parametrize("changes", [
    {"id": "other/data"}, {"author": "other"}, {"id": "google/../data"},
    {"id": "google/a..b"}, {"id": "google/data-"}, {"id": "google/" + "a" * 97},
    {"private": True}, {"private": 0}, {"private": None}, {"downloads": True},
    {"likes": -1}, {"likes": 2**63}, {"gated": []}, {"disabled": 0},
    {"disabled": None}, {"lastModified": "2099-01-01T00:00:00Z"},
    {"lastModified": "2026-01-01"},
])
def test_datasets_rejects_unrelated_private_and_malformed_metadata(changes):
    row = {**dataset(), **changes}
    with pytest.raises(ValueError):
        HuggingFaceDatasetsCollector(HubClient([row])).collect({"username": "google"})


def test_datasets_bounds_response_and_validates_omitted_sentinel():
    rows = [{**dataset(), "id": f"google/data-{n}"} for n in range(26)]
    collector = HuggingFaceDatasetsCollector(HubClient(rows))
    item = collector.collect({"username": "google"})[0]
    assert len(item.raw_data["datasets"]) == 25
    assert item.raw_data["records_checked"] == 26
    assert item.raw_data["truncated"] is True
    rows[-1]["private"] = True
    with pytest.raises(ValueError):
        collector.collect({"username": "google"})


@pytest.mark.parametrize("value", [{"error": "unavailable"}, [None], [dataset()] * 27])
def test_datasets_rejects_error_nonrecord_or_oversized_payload(value):
    with pytest.raises(ValueError):
        HuggingFaceDatasetsCollector(HubClient(value)).collect({"username": "google"})


def test_datasets_rejects_case_insensitive_duplicate_ids():
    row = dataset()
    duplicate = deepcopy(row)
    duplicate["id"] = row["id"].upper()
    with pytest.raises(ValueError, match="duplicate"):
        HuggingFaceDatasetsCollector(HubClient([row, duplicate])).collect({"username": "google"})


def test_datasets_registry_has_distinct_capability_from_models():
    registry = CollectorRegistry()
    datasets = registry.get("username_huggingface_datasets")
    models = registry.get("username_huggingface_models")
    assert datasets.capability_id != models.capability_id
    assert datasets.endpoint != models.endpoint
    assert datasets.passive and not datasets.requires_api_key
    assert datasets.supports_profile("auto")
