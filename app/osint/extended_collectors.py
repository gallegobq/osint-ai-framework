"""Additional passive collectors backed by documented public APIs.

All endpoints are fixed HTTPS providers and every response remains bounded by
``SafeHttpClient``.  These collectors only read public indexes; they do not
probe target infrastructure, authenticate as third parties or bypass controls.
"""

import json
from urllib.parse import quote

from app.core.settings import settings
from app.osint.contracts import CollectedItem, Collector
from app.osint.domain import normalize_domain
from app.osint.http import SafeHttpClient
from app.osint.targets import (
    normalize_ip,
    normalize_keyword,
    normalize_public_url,
    normalize_username,
)


def _item(
    *,
    source_type: str,
    locator: str,
    kind: str,
    title: str,
    data: object,
    provider: str,
) -> CollectedItem:
    raw_data = data if isinstance(data, dict) else {"results": data}
    return CollectedItem(
        source_type=source_type,
        locator=locator,
        kind=kind,
        title=title,
        content=json.dumps(data, ensure_ascii=False, sort_keys=True),
        raw_data=raw_data,
        source_metadata={"provider": provider},
    )


def _keyword_item(
    *,
    keyword: str,
    results: object,
    source_type: str,
    locator: str,
    kind: str,
    provider: str,
    extra: dict | None = None,
) -> CollectedItem:
    data = {"keyword": keyword, "results": results, **(extra or {})}
    return _item(
        source_type=source_type,
        locator=locator,
        kind=kind,
        title=f"{provider} search for {keyword}",
        data=data,
        provider=provider,
    )


class DomainCertSpotterCollector(Collector):
    name = "domain_certspotter"
    description = "Finds certificate-transparency issuances and DNS names via Cert Spotter."
    target_types = frozenset({"domain", "hostname"})
    query_field = "domain"

    def __init__(self, client: SafeHttpClient | None = None):
        self.client = client or SafeHttpClient()

    def validate_query(self, query: dict) -> dict:
        return {"domain": normalize_domain(query.get("domain"))}

    def collect(self, query: dict) -> list[CollectedItem]:
        domain = self.validate_query(query)["domain"]
        locator = "https://api.certspotter.com/v1/issuances"
        payload = self.client.get_json(
            locator,
            params={
                "domain": domain,
                "include_subdomains": "true",
                "expand": ["dns_names", "issuer"],
            },
            allowed_hosts={"api.certspotter.com"},
        )
        results = payload if isinstance(payload, list) else []
        data = {
            "domain": domain,
            "results": results[: settings.osint_max_items_per_collector],
        }
        return [
            _item(
                source_type="certificate_transparency",
                locator=locator,
                kind="certspotter_issuances",
                title=f"Cert Spotter issuances for {domain}",
                data=data,
                provider="SSLMate Cert Spotter",
            )
        ]


class _CommonCrawlCollector(Collector):
    index_catalog_url = "https://index.commoncrawl.org/collinfo.json"
    index_host = "index.commoncrawl.org"

    def __init__(self, client: SafeHttpClient | None = None):
        self.client = client or SafeHttpClient()

    def _records(self, value: str, match_type: str) -> tuple[str, list[dict]]:
        catalog = self.client.get_json(
            self.index_catalog_url,
            allowed_hosts={self.index_host},
        )
        if not isinstance(catalog, list) or not catalog:
            raise ValueError("Common Crawl did not return an index catalog.")
        index_id = catalog[0].get("id") if isinstance(catalog[0], dict) else None
        if not isinstance(index_id, str) or not index_id.startswith("CC-MAIN-"):
            raise ValueError("Common Crawl returned an invalid current index.")

        endpoint = f"https://{self.index_host}/{index_id}-index"
        text = self.client.get_text(
            endpoint,
            params={
                "url": value,
                "matchType": match_type,
                "output": "json",
                "filter": "status:200",
                "collapse": "urlkey",
                "pageSize": 1,
                "page": 0,
            },
            allowed_hosts={self.index_host},
        )
        records: list[dict] = []
        for line in text.splitlines():
            if len(records) >= settings.osint_max_items_per_collector:
                break
            try:
                record = json.loads(line)
            except json.JSONDecodeError:
                continue
            if isinstance(record, dict):
                records.append(record)
        return index_id, records


class DomainCommonCrawlCollector(_CommonCrawlCollector):
    name = "domain_commoncrawl"
    description = "Finds archived public URLs for a domain in the newest Common Crawl index."
    target_types = frozenset({"domain", "hostname"})
    query_field = "domain"

    def validate_query(self, query: dict) -> dict:
        return {"domain": normalize_domain(query.get("domain"))}

    def collect(self, query: dict) -> list[CollectedItem]:
        domain = self.validate_query(query)["domain"]
        index_id, records = self._records(domain, "domain")
        return [
            _item(
                source_type="web_archive_index",
                locator=self.index_catalog_url,
                kind="commoncrawl_domain_urls",
                title=f"Common Crawl URLs for {domain}",
                data={"domain": domain, "index": index_id, "results": records},
                provider="Common Crawl",
            )
        ]


class UrlCommonCrawlCollector(_CommonCrawlCollector):
    name = "url_commoncrawl"
    description = "Finds exact archived captures of a public URL in the newest Common Crawl index."
    target_types = frozenset({"url"})
    query_field = "url"

    def validate_query(self, query: dict) -> dict:
        return {"url": normalize_public_url(query.get("url"))}

    def collect(self, query: dict) -> list[CollectedItem]:
        url = self.validate_query(query)["url"]
        index_id, records = self._records(url, "exact")
        return [
            _item(
                source_type="web_archive_index",
                locator=self.index_catalog_url,
                kind="commoncrawl_url_captures",
                title=f"Common Crawl captures for {url}",
                data={"url": url, "index": index_id, "results": records},
                provider="Common Crawl",
            )
        ]


class IpShodanInternetDbCollector(Collector):
    name = "ip_shodan_internetdb"
    description = "Retrieves Shodan InternetDB ports, hostnames, CPEs, tags and CVE identifiers without a key."
    target_types = frozenset({"ip"})
    query_field = "ip"

    def __init__(self, client: SafeHttpClient | None = None):
        self.client = client or SafeHttpClient()

    def validate_query(self, query: dict) -> dict:
        return {"ip": normalize_ip(query.get("ip"))}

    def collect(self, query: dict) -> list[CollectedItem]:
        ip = self.validate_query(query)["ip"]
        locator = f"https://internetdb.shodan.io/{quote(ip, safe='')}"
        payload = self.client.get_json(
            locator,
            allowed_hosts={"internetdb.shodan.io"},
        )
        return [
            _item(
                source_type="internet_asset_index",
                locator=locator,
                kind="shodan_internetdb_host",
                title=f"Shodan InternetDB record for {ip}",
                data=payload,
                provider="Shodan InternetDB",
            )
        ]


class BlueskyUserCollector(Collector):
    name = "username_bluesky"
    description = "Retrieves a public Bluesky profile by handle or DID."
    target_types = frozenset({"username"})
    query_field = "username"

    def __init__(self, client: SafeHttpClient | None = None):
        self.client = client or SafeHttpClient()

    def validate_query(self, query: dict) -> dict:
        return {"username": normalize_username(query.get("username"))}

    def collect(self, query: dict) -> list[CollectedItem]:
        username = self.validate_query(query)["username"]
        locator = "https://public.api.bsky.app/xrpc/app.bsky.actor.getProfile"
        payload = self.client.get_json(
            locator,
            params={"actor": username},
            allowed_hosts={"public.api.bsky.app"},
        )
        return [
            _item(
                source_type="social_profile",
                locator=locator,
                kind="bluesky_profile",
                title=f"Bluesky public profile for {username}",
                data=payload,
                provider="Bluesky",
            )
        ]


class HackerNewsUserCollector(Collector):
    name = "username_hackernews"
    description = "Retrieves public Hacker News account metadata and submitted item IDs."
    target_types = frozenset({"username"})
    query_field = "username"

    def __init__(self, client: SafeHttpClient | None = None):
        self.client = client or SafeHttpClient()

    def validate_query(self, query: dict) -> dict:
        return {"username": normalize_username(query.get("username"))}

    def collect(self, query: dict) -> list[CollectedItem]:
        username = self.validate_query(query)["username"]
        locator = (
            "https://hacker-news.firebaseio.com/v0/user/"
            f"{quote(username, safe='')}.json"
        )
        payload = self.client.get_json(
            locator,
            allowed_hosts={"hacker-news.firebaseio.com"},
        )
        return [
            _item(
                source_type="community_profile",
                locator=locator,
                kind="hackernews_user",
                title=f"Hacker News public profile for {username}",
                data=payload,
                provider="Hacker News",
            )
        ]


class GitHubRepositoriesCollector(Collector):
    name = "username_github_repositories"
    description = "Lists recently updated public GitHub repositories owned by a username."
    target_types = frozenset({"username"})
    query_field = "username"

    def __init__(self, client: SafeHttpClient | None = None):
        self.client = client or SafeHttpClient()

    def validate_query(self, query: dict) -> dict:
        return {"username": normalize_username(query.get("username"))}

    def collect(self, query: dict) -> list[CollectedItem]:
        username = self.validate_query(query)["username"]
        locator = (
            f"https://api.github.com/users/{quote(username, safe='')}/repos"
        )
        payload = self.client.get_json(
            locator,
            params={
                "per_page": min(settings.osint_max_items_per_collector, 100),
                "sort": "updated",
                "direction": "desc",
            },
            headers={"Accept": "application/vnd.github+json"},
            allowed_hosts={"api.github.com"},
        )
        return [
            _item(
                source_type="code_repository_index",
                locator=locator,
                kind="github_public_repositories",
                title=f"GitHub public repositories for {username}",
                data={"username": username, "results": payload},
                provider="GitHub",
            )
        ]


class NpmMaintainerCollector(Collector):
    name = "username_npm_maintainer"
    description = "Searches public npm packages whose metadata names the username as maintainer."
    target_types = frozenset({"username"})
    query_field = "username"

    def __init__(self, client: SafeHttpClient | None = None):
        self.client = client or SafeHttpClient()

    def validate_query(self, query: dict) -> dict:
        return {"username": normalize_username(query.get("username"))}

    def collect(self, query: dict) -> list[CollectedItem]:
        username = self.validate_query(query)["username"]
        locator = "https://registry.npmjs.org/-/v1/search"
        payload = self.client.get_json(
            locator,
            params={
                "text": f"maintainer:{username}",
                "size": min(settings.osint_max_items_per_collector, 250),
            },
            allowed_hosts={"registry.npmjs.org"},
        )
        results = payload.get("objects", []) if isinstance(payload, dict) else []
        return [
            _item(
                source_type="package_registry",
                locator=locator,
                kind="npm_maintained_packages",
                title=f"npm public packages maintained by {username}",
                data={
                    "username": username,
                    "total": payload.get("total") if isinstance(payload, dict) else None,
                    "results": results,
                },
                provider="npm",
            )
        ]


class _KeywordCollector(Collector):
    target_types = frozenset({"keyword"})
    query_field = "keyword"

    def __init__(self, client: SafeHttpClient | None = None):
        self.client = client or SafeHttpClient()

    def validate_query(self, query: dict) -> dict:
        return {"keyword": normalize_keyword(query.get("keyword"))}


class GdeltNewsSearchCollector(_KeywordCollector):
    name = "keyword_gdelt_news"
    description = "Searches GDELT's global public news index for matching articles."

    def collect(self, query: dict) -> list[CollectedItem]:
        keyword = self.validate_query(query)["keyword"]
        locator = "https://api.gdeltproject.org/api/v2/doc/doc"
        payload = self.client.get_json(
            locator,
            params={
                "query": keyword,
                "mode": "ArtList",
                "maxrecords": min(settings.osint_max_items_per_collector, 250),
                "format": "json",
                "sort": "HybridRel",
            },
            allowed_hosts={"api.gdeltproject.org"},
        )
        results = payload.get("articles", []) if isinstance(payload, dict) else []
        return [
            _keyword_item(
                keyword=keyword,
                results=results,
                source_type="news_index",
                locator=locator,
                kind="gdelt_articles",
                provider="GDELT",
            )
        ]


class CrossrefSearchCollector(_KeywordCollector):
    name = "keyword_crossref"
    description = "Searches Crossref public scholarly and professional work metadata."

    def collect(self, query: dict) -> list[CollectedItem]:
        keyword = self.validate_query(query)["keyword"]
        locator = "https://api.crossref.org/works"
        payload = self.client.get_json(
            locator,
            params={
                "query.bibliographic": keyword,
                "rows": min(settings.osint_max_items_per_collector, 100),
            },
            allowed_hosts={"api.crossref.org"},
        )
        message = payload.get("message", {}) if isinstance(payload, dict) else {}
        results = message.get("items", []) if isinstance(message, dict) else []
        return [
            _keyword_item(
                keyword=keyword,
                results=results,
                source_type="scholarly_index",
                locator=locator,
                kind="crossref_works",
                provider="Crossref",
                extra={"total": message.get("total-results") if isinstance(message, dict) else None},
            )
        ]


class OpenLibrarySearchCollector(_KeywordCollector):
    name = "keyword_openlibrary"
    description = "Searches Open Library's public catalog for books, editions and authors."

    def collect(self, query: dict) -> list[CollectedItem]:
        keyword = self.validate_query(query)["keyword"]
        locator = "https://openlibrary.org/search.json"
        payload = self.client.get_json(
            locator,
            params={
                "q": keyword,
                "limit": min(settings.osint_max_items_per_collector, 100),
                "fields": "key,title,author_name,first_publish_year,isbn,publisher,language",
            },
            allowed_hosts={"openlibrary.org"},
        )
        results = payload.get("docs", []) if isinstance(payload, dict) else []
        return [
            _keyword_item(
                keyword=keyword,
                results=results,
                source_type="library_catalog",
                locator=locator,
                kind="openlibrary_books",
                provider="Open Library",
                extra={"total": payload.get("numFound") if isinstance(payload, dict) else None},
            )
        ]


class StackExchangeSearchCollector(_KeywordCollector):
    name = "keyword_stackexchange"
    description = "Searches public Stack Overflow questions through the Stack Exchange API."

    def collect(self, query: dict) -> list[CollectedItem]:
        keyword = self.validate_query(query)["keyword"]
        locator = "https://api.stackexchange.com/2.3/search/advanced"
        payload = self.client.get_json(
            locator,
            params={
                "q": keyword,
                "site": "stackoverflow",
                "pagesize": min(settings.osint_max_items_per_collector, 100),
                "order": "desc",
                "sort": "relevance",
            },
            allowed_hosts={"api.stackexchange.com"},
        )
        results = payload.get("items", []) if isinstance(payload, dict) else []
        return [
            _keyword_item(
                keyword=keyword,
                results=results,
                source_type="technical_community",
                locator=locator,
                kind="stackoverflow_questions",
                provider="Stack Exchange",
                extra={"quota_remaining": payload.get("quota_remaining") if isinstance(payload, dict) else None},
            )
        ]


class EuropePmcSearchCollector(_KeywordCollector):
    name = "keyword_europepmc"
    description = "Searches Europe PMC public biomedical literature and preprint metadata."

    def collect(self, query: dict) -> list[CollectedItem]:
        keyword = self.validate_query(query)["keyword"]
        locator = "https://www.ebi.ac.uk/europepmc/webservices/rest/search"
        payload = self.client.get_json(
            locator,
            params={
                "query": keyword,
                "format": "json",
                "pageSize": min(settings.osint_max_items_per_collector, 100),
                "resultType": "lite",
            },
            allowed_hosts={"www.ebi.ac.uk"},
        )
        result_list = payload.get("resultList", {}) if isinstance(payload, dict) else {}
        results = result_list.get("result", []) if isinstance(result_list, dict) else []
        return [
            _keyword_item(
                keyword=keyword,
                results=results,
                source_type="biomedical_index",
                locator=locator,
                kind="europepmc_works",
                provider="Europe PMC",
                extra={"total": payload.get("hitCount") if isinstance(payload, dict) else None},
            )
        ]


class GoogleBooksSearchCollector(_KeywordCollector):
    name = "keyword_google_books"
    description = "Searches public Google Books volume metadata."

    def collect(self, query: dict) -> list[CollectedItem]:
        keyword = self.validate_query(query)["keyword"]
        locator = "https://www.googleapis.com/books/v1/volumes"
        payload = self.client.get_json(
            locator,
            params={
                "q": keyword,
                "maxResults": min(settings.osint_max_items_per_collector, 40),
                "orderBy": "relevance",
                "langRestrict": settings.osint_search_language,
            },
            allowed_hosts={"www.googleapis.com"},
        )
        results = payload.get("items", []) if isinstance(payload, dict) else []
        return [
            _keyword_item(
                keyword=keyword,
                results=results,
                source_type="book_index",
                locator=locator,
                kind="google_books_volumes",
                provider="Google Books",
                extra={"total": payload.get("totalItems") if isinstance(payload, dict) else None},
            )
        ]


class HackerNewsSearchCollector(_KeywordCollector):
    name = "keyword_hackernews"
    description = "Searches public Hacker News stories and comments through the Algolia index."

    def collect(self, query: dict) -> list[CollectedItem]:
        keyword = self.validate_query(query)["keyword"]
        locator = "https://hn.algolia.com/api/v1/search"
        payload = self.client.get_json(
            locator,
            params={
                "query": keyword,
                "hitsPerPage": min(settings.osint_max_items_per_collector, 100),
            },
            allowed_hosts={"hn.algolia.com"},
        )
        results = payload.get("hits", []) if isinstance(payload, dict) else []
        return [
            _keyword_item(
                keyword=keyword,
                results=results,
                source_type="community_index",
                locator=locator,
                kind="hackernews_items",
                provider="Hacker News Search",
                extra={"total": payload.get("nbHits") if isinstance(payload, dict) else None},
            )
        ]
