from copy import deepcopy

import pytest

from app.core.exceptions import BadRequestException
from app.osint.dockerhub_collector import DockerHubRepositoriesCollector


def payload():
    return {"count": 1, "next": None, "previous": None, "results": [{
        "namespace": "docker", "name": "example-image", "description": "Public fixture",
        "is_private": False, "star_count": 2, "pull_count": 40,
        "last_updated": "2026-01-01T00:00:00Z", "full_description": "not projected",
        "permissions": {"admin": True}, "source": {"contact": "not projected"},
    }]}


class HubClient:
    def __init__(self, value=None):
        self.value = payload() if value is None else value
        self.calls = []

    def get_json(self, url, **kwargs):
        self.calls.append((url, kwargs))
        return self.value


def test_dockerhub_projects_public_metadata_without_auth_or_identity_claims():
    client = HubClient()
    item = DockerHubRepositoriesCollector(client).collect({"username": "Docker"})[0]
    assert item.raw_data["namespace"] == "docker"
    assert item.raw_data["repositories"] == [{
        "namespace": "docker", "name": "example-image", "description": "Public fixture",
        "star_count": 2, "pull_count": 40, "last_updated": "2026-01-01T00:00:00+00:00",
        "url": "https://hub.docker.com/r/docker/example-image",
    }]
    assert item.raw_data["truncated"] is False
    assert item.discoveries == ()
    assert client.calls == [("https://hub.docker.com/v2/namespaces/docker/repositories", {
        "params": {"page": 1, "page_size": 25, "ordering": "name"},
        "allowed_hosts": {"hub.docker.com"},
    })]


def test_dockerhub_does_not_follow_provider_pagination_links():
    value = payload()
    value.update(count=40, next="https://127.0.0.1/private")
    client = HubClient(value)
    item = DockerHubRepositoriesCollector(client).collect({"username": "docker"})[0]
    assert item.raw_data["truncated"] is True
    assert "127.0.0.1" not in item.content
    assert len(client.calls) == 1


def test_dockerhub_accepts_empty_public_page_without_claiming_missing_account():
    value = payload()
    value.update(count=0, results=[])
    item = DockerHubRepositoriesCollector(HubClient(value)).collect({"username": "docker"})[0]
    assert item.raw_data["repositories"] == []
    assert item.raw_data["truncated"] is False
    assert "account_exists" not in item.raw_data


def test_dockerhub_accepts_null_last_updated_and_deterministic_names():
    value = payload()
    second = deepcopy(value["results"][0])
    second.update(name="a__image", last_updated=None)
    value["results"].append(second)
    value["count"] = 2
    item = DockerHubRepositoriesCollector(HubClient(value)).collect({"username": "docker"})[0]
    assert item.raw_data["repositories"][0]["name"] == "a__image"
    assert item.raw_data["repositories"][0]["last_updated"] is None


@pytest.mark.parametrize("target", [None, "../docker", "docker/name", "name.example", "a" * 64])
def test_dockerhub_rejects_unsafe_namespace_before_fetch(target):
    client = HubClient()
    with pytest.raises(BadRequestException):
        DockerHubRepositoriesCollector(client).collect({"username": target})
    assert client.calls == []


@pytest.mark.parametrize("mutation", [
    lambda p: p.update(count=True),
    lambda p: p.update(count=-1),
    lambda p: p.update(count=0),
    lambda p: p.update(results={}),
    lambda p: p.update(next={"url": "https://example.com"}),
    lambda p: p["results"][0].update(namespace="other"),
    lambda p: p["results"][0].update(is_private=True),
    lambda p: p["results"][0].update(is_private=0),
    lambda p: p["results"][0].update(name="../image"),
    lambda p: p["results"][0].update(description="x" * 1_001),
    lambda p: p["results"][0].update(pull_count=True),
    lambda p: p["results"][0].update(star_count=-1),
    lambda p: p["results"][0].update(last_updated="2099-01-01T00:00:00Z"),
    lambda p: p["results"][0].update(last_updated="2026-01-01"),
    lambda p: p["results"][0].update(last_updated="not-a-date"),
    lambda p: (p.update(count=2), p["results"].append(deepcopy(p["results"][0]))),
])
def test_dockerhub_rejects_invalid_private_or_unrelated_provider_data(mutation):
    value = payload()
    mutation(value)
    with pytest.raises(ValueError):
        DockerHubRepositoriesCollector(HubClient(value)).collect({"username": "docker"})


def test_dockerhub_rejects_oversized_page_without_partial_evidence():
    value = payload()
    value["results"] *= 26
    value["count"] = 26
    with pytest.raises(ValueError, match="oversized"):
        DockerHubRepositoriesCollector(HubClient(value)).collect({"username": "docker"})


def test_dockerhub_propagates_provider_failure_not_as_empty_repositories():
    class FailedClient:
        def get_json(self, *_args, **_kwargs):
            raise RuntimeError("Provider unavailable")

    with pytest.raises(RuntimeError, match="unavailable"):
        DockerHubRepositoriesCollector(FailedClient()).collect({"username": "docker"})
