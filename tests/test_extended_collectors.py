import json

import pytest

from app.osint.extended_collectors import (
    BlueskyUserCollector,
    CrossrefSearchCollector,
    DomainCertSpotterCollector,
    DomainCommonCrawlCollector,
    EuropePmcSearchCollector,
    GdeltNewsSearchCollector,
    GitHubRepositoriesCollector,
    GoogleBooksSearchCollector,
    HackerNewsSearchCollector,
    HackerNewsUserCollector,
    IpShodanInternetDbCollector,
    NpmMaintainerCollector,
    OpenLibrarySearchCollector,
    StackExchangeSearchCollector,
    UrlCommonCrawlCollector,
)
from app.osint.registry import CollectorRegistry


NEW_COLLECTOR_NAMES = {
    "domain_certspotter",
    "domain_commoncrawl",
    "url_commoncrawl",
    "ip_shodan_internetdb",
    "username_bluesky",
    "username_hackernews",
    "username_github_repositories",
    "username_npm_maintainer",
    "keyword_gdelt_news",
    "keyword_crossref",
    "keyword_openlibrary",
    "keyword_stackexchange",
    "keyword_europepmc",
    "keyword_google_books",
    "keyword_hackernews",
}


class StubClient:
    def __init__(self) -> None:
        self.requests: list[tuple[str, str, dict]] = []

    def get_json(self, url: str, **kwargs):
        self.requests.append(("json", url, kwargs))
        if url.endswith("collinfo.json"):
            return [{"id": "CC-MAIN-2026-30"}]
        if "certspotter" in url:
            return [{"id": "issuance-1", "dns_names": ["example.com"]}]
        if "internetdb.shodan.io" in url:
            return {"ip": "8.8.8.8", "ports": [53], "vulns": []}
        if "bsky.app" in url:
            return {"handle": "alice.example", "did": "did:plc:test"}
        if "firebaseio.com" in url:
            return {"id": "alice", "karma": 42, "submitted": [1]}
        if "api.github.com" in url:
            return [{"name": "public-repository", "fork": False}]
        if "registry.npmjs.org" in url:
            return {"total": 1, "objects": [{"package": {"name": "tool"}}]}
        if "gdeltproject.org" in url:
            return {"articles": [{"title": "Public article"}]}
        if "crossref.org" in url:
            return {"message": {"total-results": 1, "items": [{"DOI": "10/test"}]}}
        if "openlibrary.org" in url:
            return {"numFound": 1, "docs": [{"title": "Public book"}]}
        if "stackexchange.com" in url:
            return {"quota_remaining": 299, "items": [{"question_id": 1}]}
        if "ebi.ac.uk" in url:
            return {"hitCount": 1, "resultList": {"result": [{"id": "PMC1"}]}}
        if "googleapis.com" in url:
            return {"totalItems": 1, "items": [{"id": "volume-1"}]}
        if "hn.algolia.com" in url:
            return {"nbHits": 1, "hits": [{"objectID": "1"}]}
        raise AssertionError(f"Unexpected stub URL: {url}")

    def get_text(self, url: str, **kwargs) -> str:
        self.requests.append(("text", url, kwargs))
        return json.dumps({"url": "https://example.com/", "status": "200"})


COLLECT_CASES = [
    (DomainCertSpotterCollector, {"domain": "Example.COM"}),
    (DomainCommonCrawlCollector, {"domain": "Example.COM"}),
    (UrlCommonCrawlCollector, {"url": "https://example.com"}),
    (IpShodanInternetDbCollector, {"ip": "8.8.8.8"}),
    (BlueskyUserCollector, {"username": "alice.example"}),
    (HackerNewsUserCollector, {"username": "alice"}),
    (GitHubRepositoriesCollector, {"username": "alice"}),
    (NpmMaintainerCollector, {"username": "alice"}),
    (GdeltNewsSearchCollector, {"keyword": "open source intelligence"}),
    (CrossrefSearchCollector, {"keyword": "open source intelligence"}),
    (OpenLibrarySearchCollector, {"keyword": "open source intelligence"}),
    (StackExchangeSearchCollector, {"keyword": "open source intelligence"}),
    (EuropePmcSearchCollector, {"keyword": "open source intelligence"}),
    (GoogleBooksSearchCollector, {"keyword": "open source intelligence"}),
    (HackerNewsSearchCollector, {"keyword": "open source intelligence"}),
]


@pytest.mark.parametrize(("collector_type", "query"), COLLECT_CASES)
def test_extended_collector_normalizes_and_returns_traceable_item(
    collector_type,
    query: dict,
) -> None:
    client = StubClient()
    collector = collector_type(client)

    validated = collector.validate_query(query)
    items = collector.collect(query)

    assert validated[collector.query_field]
    assert collector.passive is True
    assert collector.requires_api_key is False
    assert len(items) == 1
    assert items[0].locator.startswith("https://")
    assert items[0].source_metadata["provider"]
    assert json.loads(items[0].content)
    assert client.requests


def test_registry_includes_all_extended_collectors_as_available() -> None:
    descriptions = CollectorRegistry().describe()
    by_name = {item["name"]: item for item in descriptions}

    assert len(descriptions) == len(by_name)
    assert NEW_COLLECTOR_NAMES <= by_name.keys()
    assert all(by_name[name]["available"] for name in NEW_COLLECTOR_NAMES)
    assert all(by_name[name]["passive"] for name in NEW_COLLECTOR_NAMES)
    assert all(not by_name[name]["requires_api_key"] for name in NEW_COLLECTOR_NAMES)
