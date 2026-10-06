from copy import deepcopy

import pytest

from app.core.exceptions import BadRequestException
from app.osint.huggingface_collector import HuggingFaceModelsCollector


def model():
    return {"id": "google/example-model", "author": "google", "private": False,
            "downloads": 100, "likes": 3, "lastModified": "2026-01-01T00:00:00Z",
            "pipeline_tag": "text-generation", "gated": False,
            "cardData": {"instructions": "not projected"}, "siblings": ["code.py"]}


class HubClient:
    def __init__(self, value=None):
        self.value = [model()] if value is None else value
        self.calls = []

    def get_json(self, url, **kwargs):
        self.calls.append((url, kwargs))
        return self.value


def test_huggingface_projects_public_metadata_without_files_auth_or_inference():
    client = HubClient()
    collector = HuggingFaceModelsCollector(client)
    item = collector.collect({"username": "google"})[0]
    assert item.raw_data["models"] == [{
        "model_id": "google/example-model", "author": "google", "downloads": 100,
        "likes": 3, "last_modified": "2026-01-01T00:00:00+00:00",
        "pipeline_tag": "text-generation", "gated": False,
        "url": "https://huggingface.co/google/example-model",
    }]
    assert item.discoveries == ()
    assert item.raw_data["truncated"] is False
    assert client.calls == [(collector.endpoint, {
        "params": {"author": "google", "limit": 26, "sort": "downloads",
                   "expand": list(collector.expanded_fields)},
        "allowed_hosts": {"huggingface.co"},
    })]


@pytest.mark.parametrize("gated", [False, True, "auto", "manual"])
def test_huggingface_preserves_gating_without_attempting_access(gated):
    row = model()
    row["gated"] = gated
    client = HubClient([row])
    item = HuggingFaceModelsCollector(client).collect({"username": "google"})[0]
    assert item.raw_data["models"][0]["gated"] == gated
    assert len(client.calls) == 1


def test_huggingface_accepts_null_optional_metrics_and_case_insensitive_namespace():
    row = model()
    row.update(downloads=None, likes=None, lastModified=None, pipeline_tag=None)
    item = HuggingFaceModelsCollector(HubClient([row])).collect({"username": "Google"})[0]
    assert item.raw_data["models"][0]["downloads"] is None
    assert item.raw_data["models"][0]["last_modified"] is None


def test_huggingface_empty_response_does_not_claim_missing_account():
    item = HuggingFaceModelsCollector(HubClient([])).collect({"username": "google"})[0]
    assert item.raw_data["models"] == []
    assert "account_exists" not in item.raw_data


@pytest.mark.parametrize("target", [None, "../google", "google/name", "google.example"])
def test_huggingface_rejects_invalid_namespace_before_fetch(target):
    client = HubClient()
    with pytest.raises(BadRequestException):
        HuggingFaceModelsCollector(client).collect({"username": target})
    assert client.calls == []


@pytest.mark.parametrize("mutation", [
    lambda r: r.update(id="other/model"),
    lambda r: r.update(author="other"),
    lambda r: r.update(id="google/../model"),
    lambda r: r.update(id="google/a..b"),
    lambda r: r.update(id="google/model-"),
    lambda r: r.update(id="google/" + "a" * 97),
    lambda r: r.update(private=True),
    lambda r: r.update(private=0),
    lambda r: r.update(downloads=True),
    lambda r: r.update(likes=-1),
    lambda r: r.update(gated=[]),
    lambda r: r.update(pipeline_tag="x" * 101),
    lambda r: r.update(lastModified="2099-01-01T00:00:00Z"),
    lambda r: r.update(lastModified="2026-01-01"),
])
def test_huggingface_rejects_private_unrelated_or_invalid_metadata(mutation):
    row = model()
    mutation(row)
    with pytest.raises(ValueError):
        HuggingFaceModelsCollector(HubClient([row])).collect({"username": "google"})


def test_huggingface_caps_page_with_sentinel_and_validates_omitted_record():
    rows = [{**model(), "id": f"google/model-{n}"} for n in range(26)]
    collector = HuggingFaceModelsCollector(HubClient(rows))
    item = collector.collect({"username": "google"})[0]
    assert len(item.raw_data["models"]) == 25
    assert item.raw_data["records_checked"] == 26
    assert item.raw_data["truncated"] is True
    rows[-1]["private"] = True
    with pytest.raises(ValueError):
        collector.collect({"username": "google"})


@pytest.mark.parametrize("value", [{"error": "unavailable"}, [None], [model()] * 27])
def test_huggingface_rejects_error_or_oversized_response(value):
    with pytest.raises(ValueError):
        HuggingFaceModelsCollector(HubClient(value)).collect({"username": "google"})


def test_huggingface_rejects_duplicate_ids():
    row = model()
    with pytest.raises(ValueError, match="duplicate"):
        HuggingFaceModelsCollector(HubClient([row, deepcopy(row)])).collect({"username": "google"})
