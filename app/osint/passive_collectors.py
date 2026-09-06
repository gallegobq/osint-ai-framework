import ipaddress
import json
from urllib.parse import quote

from app.core.settings import settings
from app.osint.contracts import CollectedItem, Collector
from app.osint.domain import normalize_domain
from app.osint.http import SafeHttpClient
from app.osint.targets import (
    normalize_asn,
    normalize_ip,
    normalize_keyword,
    normalize_public_url,
    normalize_username,
)


def _json_item(
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


class DomainDnsRecordsCollector(Collector):
    name = "domain_dns_records"
    description = "Queries A, AAAA, MX, NS, TXT, CNAME, SOA and CAA via DNS-over-HTTPS."
    target_types = frozenset({"domain", "hostname"})
    query_field = "domain"
    record_types = ("A", "AAAA", "MX", "NS", "TXT", "CNAME", "SOA", "CAA")

    def __init__(self, client: SafeHttpClient | None = None):
        self.client = client or SafeHttpClient()

    def validate_query(self, query: dict) -> dict:
        return {"domain": normalize_domain(query.get("domain"))}

    def collect(self, query: dict) -> list[CollectedItem]:
        domain = self.validate_query(query)["domain"]
        records: dict[str, dict] = {}
        for record_type in self.record_types:
            payload = self.client.get_json(
                "https://dns.google/resolve",
                params={
                    "name": domain,
                    "type": record_type,
                    "do": "1",
                    "edns_client_subnet": "0.0.0.0/0",
                },
                allowed_hosts={"dns.google"},
            )
            if not isinstance(payload, dict):
                raise ValueError("Unexpected DNS-over-HTTPS response.")
            records[record_type] = {
                "status": payload.get("Status"),
                "dnssec_validated": payload.get("AD", False),
                "answers": (payload.get("Answer") or [])[
                    : settings.osint_max_items_per_collector
                ],
                "comment": payload.get("Comment"),
            }
        data = {"domain": domain, "records": records}
        return [
            _json_item(
                source_type="dns_over_https",
                locator=f"https://dns.google/resolve?name={quote(domain)}",
                kind="dns_record_set",
                title=f"Complete DNS record set for {domain}",
                data=data,
                provider="Google Public DNS",
            )
        ]


class DomainCertificateTransparencyCollector(Collector):
    name = "domain_certificate_transparency"
    description = "Finds certificate transparency entries and public subdomain names."
    target_types = frozenset({"domain", "hostname"})
    query_field = "domain"

    def __init__(self, client: SafeHttpClient | None = None):
        self.client = client or SafeHttpClient()

    def validate_query(self, query: dict) -> dict:
        return {"domain": normalize_domain(query.get("domain"))}

    def collect(self, query: dict) -> list[CollectedItem]:
        domain = self.validate_query(query)["domain"]
        payload = self.client.get_json(
            "https://crt.sh/",
            params={"q": f"%.{domain}", "output": "json"},
            allowed_hosts={"crt.sh"},
        )
        if not isinstance(payload, list):
            raise ValueError("Unexpected certificate transparency response.")
        entries: list[dict] = []
        seen_ids: set[object] = set()
        names: set[str] = set()
        for row in payload:
            if not isinstance(row, dict):
                continue
            certificate_id = row.get("id")
            if certificate_id in seen_ids:
                continue
            seen_ids.add(certificate_id)
            for value in str(row.get("name_value", "")).splitlines():
                candidate = value.lower().removeprefix("*.").rstrip(".")
                if candidate == domain or candidate.endswith(f".{domain}"):
                    names.add(candidate)
            entries.append(
                {
                    "id": certificate_id,
                    "issuer_name": row.get("issuer_name"),
                    "common_name": row.get("common_name"),
                    "name_value": row.get("name_value"),
                    "not_before": row.get("not_before"),
                    "not_after": row.get("not_after"),
                    "entry_timestamp": row.get("entry_timestamp"),
                }
            )
            if len(entries) >= settings.osint_max_items_per_collector:
                break
        data = {
            "domain": domain,
            "certificate_entries": entries,
            "discovered_names": sorted(names),
            "truncated": len(payload) > len(entries),
        }
        return [
            _json_item(
                source_type="certificate_transparency",
                locator=f"https://crt.sh/?q=%25.{quote(domain)}&output=json",
                kind="certificate_transparency",
                title=f"Certificate transparency for {domain}",
                data=data,
                provider="crt.sh",
            )
        ]


class DomainWaybackCollector(Collector):
    name = "domain_wayback"
    description = "Lists public historical captures from the Wayback Machine CDX index."
    target_types = frozenset({"domain", "hostname"})
    query_field = "domain"

    def __init__(self, client: SafeHttpClient | None = None):
        self.client = client or SafeHttpClient()

    def validate_query(self, query: dict) -> dict:
        return {"domain": normalize_domain(query.get("domain"))}

    def collect(self, query: dict) -> list[CollectedItem]:
        domain = self.validate_query(query)["domain"]
        payload = self.client.get_json(
            "https://web.archive.org/cdx/search/cdx",
            params={
                "url": domain,
                "matchType": "domain",
                "output": "json",
                "fl": "timestamp,original,statuscode,mimetype,digest",
                "filter": "statuscode:200",
                "collapse": "urlkey",
                "limit": settings.osint_max_items_per_collector,
            },
            allowed_hosts={"web.archive.org"},
        )
        captures: list[dict] = []
        if isinstance(payload, list) and payload:
            header = payload[0]
            if isinstance(header, list):
                for row in payload[1:]:
                    if isinstance(row, list):
                        captures.append(dict(zip(header, row)))
        data = {"domain": domain, "captures": captures}
        return [
            _json_item(
                source_type="web_archive",
                locator=f"https://web.archive.org/cdx/search/cdx?url={quote(domain)}",
                kind="historical_urls",
                title=f"Historical web captures for {domain}",
                data=data,
                provider="Internet Archive",
            )
        ]


class UrlWaybackCollector(Collector):
    name = "url_wayback"
    description = "Lists public historical captures for one HTTP(S) URL."
    target_types = frozenset({"url"})
    query_field = "url"

    def __init__(self, client: SafeHttpClient | None = None):
        self.client = client or SafeHttpClient()

    def validate_query(self, query: dict) -> dict:
        return {"url": normalize_public_url(query.get("url"))}

    def collect(self, query: dict) -> list[CollectedItem]:
        url = self.validate_query(query)["url"]
        payload = self.client.get_json(
            "https://web.archive.org/cdx/search/cdx",
            params={
                "url": url,
                "output": "json",
                "fl": "timestamp,original,statuscode,mimetype,digest",
                "limit": settings.osint_max_items_per_collector,
            },
            allowed_hosts={"web.archive.org"},
        )
        rows: list[dict] = []
        if isinstance(payload, list) and payload and isinstance(payload[0], list):
            rows = [
                dict(zip(payload[0], row))
                for row in payload[1:]
                if isinstance(row, list)
            ]
        data = {"url": url, "captures": rows}
        return [
            _json_item(
                source_type="web_archive",
                locator="https://web.archive.org/cdx/search/cdx",
                kind="historical_urls",
                title=f"Historical web captures for {url}",
                data=data,
                provider="Internet Archive",
            )
        ]


class UrlscanDomainCollector(Collector):
    name = "domain_urlscan"
    description = "Searches existing public urlscan.io observations for a domain."
    target_types = frozenset({"domain", "hostname"})
    query_field = "domain"

    def __init__(self, client: SafeHttpClient | None = None):
        self.client = client or SafeHttpClient()

    def validate_query(self, query: dict) -> dict:
        return {"domain": normalize_domain(query.get("domain"))}

    def collect(self, query: dict) -> list[CollectedItem]:
        domain = self.validate_query(query)["domain"]
        headers = {}
        if settings.urlscan_api_key and settings.urlscan_api_key.get_secret_value():
            headers["api-key"] = settings.urlscan_api_key.get_secret_value()
        payload = self.client.get_json(
            "https://urlscan.io/api/v1/search/",
            params={
                "q": f"page.domain:{domain}",
                "size": min(settings.osint_max_items_per_collector, 100),
            },
            headers=headers,
            allowed_hosts={"urlscan.io"},
        )
        if not isinstance(payload, dict):
            raise ValueError("Unexpected urlscan.io response.")
        data = {
            "domain": domain,
            "total": payload.get("total"),
            "results": (payload.get("results") or [])[
                : settings.osint_max_items_per_collector
            ],
        }
        return [
            _json_item(
                source_type="urlscan",
                locator=f"https://urlscan.io/search/#domain:{quote(domain)}",
                kind="url_observations",
                title=f"Public URL observations for {domain}",
                data=data,
                provider="urlscan.io",
            )
        ]


class IpRdapCollector(Collector):
    name = "ip_rdap"
    description = "Retrieves public registration data for an IP address through RDAP."
    target_types = frozenset({"ip"})
    query_field = "ip"

    def __init__(self, client: SafeHttpClient | None = None):
        self.client = client or SafeHttpClient()

    def validate_query(self, query: dict) -> dict:
        return {"ip": normalize_ip(query.get("ip"))}

    def collect(self, query: dict) -> list[CollectedItem]:
        ip = self.validate_query(query)["ip"]
        locator = f"https://rdap.org/ip/{quote(ip)}"
        data = self.client.get_json(
            locator,
            allowed_hosts={"rdap.org"},
            allow_public_redirects=True,
        )
        return [
            _json_item(
                source_type="rdap",
                locator=locator,
                kind="ip_registration",
                title=f"RDAP registration for {ip}",
                data=data,
                provider="RDAP.org",
            )
        ]


class IpReverseDnsCollector(Collector):
    name = "ip_reverse_dns"
    description = "Resolves the public PTR hostname associated with an IP address."
    target_types = frozenset({"ip"})
    query_field = "ip"

    def __init__(self, client: SafeHttpClient | None = None):
        self.client = client or SafeHttpClient()

    def validate_query(self, query: dict) -> dict:
        return {"ip": normalize_ip(query.get("ip"))}

    def collect(self, query: dict) -> list[CollectedItem]:
        ip = self.validate_query(query)["ip"]
        reverse_name = ipaddress.ip_address(ip).reverse_pointer
        payload = self.client.get_json(
            "https://dns.google/resolve",
            params={
                "name": reverse_name,
                "type": "PTR",
                "do": "1",
                "edns_client_subnet": "0.0.0.0/0",
            },
            allowed_hosts={"dns.google"},
        )
        answers = payload.get("Answer", []) if isinstance(payload, dict) else []
        hostnames = sorted(
            {
                str(answer.get("data", "")).rstrip(".")
                for answer in answers
                if isinstance(answer, dict) and answer.get("data")
            }
        )
        data = {
            "ip": ip,
            "reverse_name": reverse_name,
            "hostnames": hostnames,
            "dnssec_validated": payload.get("AD", False)
            if isinstance(payload, dict)
            else False,
        }
        return [
            _json_item(
                source_type="dns",
                locator=f"dns://{ip}",
                kind="reverse_dns",
                title=f"Reverse DNS for {ip}",
                data=data,
                provider="Google Public DNS",
            )
        ]


class IpRipeStatCollector(Collector):
    name = "ip_ripestat"
    description = "Retrieves routing, prefix and registry context from RIPEstat."
    target_types = frozenset({"ip"})
    query_field = "ip"

    def __init__(self, client: SafeHttpClient | None = None):
        self.client = client or SafeHttpClient()

    def validate_query(self, query: dict) -> dict:
        return {"ip": normalize_ip(query.get("ip"))}

    def collect(self, query: dict) -> list[CollectedItem]:
        ip = self.validate_query(query)["ip"]
        results = {}
        for endpoint in ("network-info", "prefix-overview", "rir"):
            payload = self.client.get_json(
                f"https://stat.ripe.net/data/{endpoint}/data.json",
                params={"resource": ip, "sourceapp": "osint-ai-framework"},
                allowed_hosts={"stat.ripe.net"},
            )
            results[endpoint] = payload.get("data") if isinstance(payload, dict) else payload
        data = {"ip": ip, "ripestat": results}
        return [
            _json_item(
                source_type="internet_registry",
                locator=f"https://stat.ripe.net/{quote(ip)}",
                kind="ip_network_context",
                title=f"RIPEstat network context for {ip}",
                data=data,
                provider="RIPE NCC",
            )
        ]


class AsnRdapCollector(Collector):
    name = "asn_rdap"
    description = "Retrieves public registration data for an ASN through RDAP."
    target_types = frozenset({"asn"})
    query_field = "asn"

    def __init__(self, client: SafeHttpClient | None = None):
        self.client = client or SafeHttpClient()

    def validate_query(self, query: dict) -> dict:
        return {"asn": normalize_asn(query.get("asn"))}

    def collect(self, query: dict) -> list[CollectedItem]:
        asn = self.validate_query(query)["asn"]
        locator = f"https://rdap.org/autnum/{asn[2:]}"
        data = self.client.get_json(
            locator,
            allowed_hosts={"rdap.org"},
            allow_public_redirects=True,
        )
        return [
            _json_item(
                source_type="rdap",
                locator=locator,
                kind="asn_registration",
                title=f"RDAP registration for {asn}",
                data=data,
                provider="RDAP.org",
            )
        ]


class AsnRipeStatCollector(Collector):
    name = "asn_ripestat"
    description = "Retrieves overview, prefixes and routing status for an ASN."
    target_types = frozenset({"asn"})
    query_field = "asn"

    def __init__(self, client: SafeHttpClient | None = None):
        self.client = client or SafeHttpClient()

    def validate_query(self, query: dict) -> dict:
        return {"asn": normalize_asn(query.get("asn"))}

    def collect(self, query: dict) -> list[CollectedItem]:
        asn = self.validate_query(query)["asn"]
        results = {}
        for endpoint in ("as-overview", "announced-prefixes", "routing-status"):
            payload = self.client.get_json(
                f"https://stat.ripe.net/data/{endpoint}/data.json",
                params={"resource": asn, "sourceapp": "osint-ai-framework"},
                allowed_hosts={"stat.ripe.net"},
            )
            results[endpoint] = payload.get("data") if isinstance(payload, dict) else payload
        data = {"asn": asn, "ripestat": results}
        return [
            _json_item(
                source_type="internet_registry",
                locator=f"https://stat.ripe.net/{quote(asn)}",
                kind="asn_network_context",
                title=f"RIPEstat routing context for {asn}",
                data=data,
                provider="RIPE NCC",
            )
        ]


class AsnPeeringDbCollector(Collector):
    name = "asn_peeringdb"
    description = "Retrieves public network and peering metadata for an ASN."
    target_types = frozenset({"asn"})
    query_field = "asn"

    def __init__(self, client: SafeHttpClient | None = None):
        self.client = client or SafeHttpClient()

    def validate_query(self, query: dict) -> dict:
        return {"asn": normalize_asn(query.get("asn"))}

    def collect(self, query: dict) -> list[CollectedItem]:
        asn = self.validate_query(query)["asn"]
        payload = self.client.get_json(
            "https://www.peeringdb.com/api/net",
            params={"asn": int(asn[2:]), "depth": 1},
            allowed_hosts={"www.peeringdb.com"},
        )
        data = {"asn": asn, "peeringdb": payload}
        return [
            _json_item(
                source_type="peering_directory",
                locator=f"https://www.peeringdb.com/search?q={quote(asn)}",
                kind="asn_peering",
                title=f"PeeringDB information for {asn}",
                data=data,
                provider="PeeringDB",
            )
        ]


class WikidataSearchCollector(Collector):
    name = "keyword_wikidata"
    description = "Searches public Wikidata entities for people, organizations and topics."
    target_types = frozenset({"keyword"})
    query_field = "keyword"

    def __init__(self, client: SafeHttpClient | None = None):
        self.client = client or SafeHttpClient()

    def validate_query(self, query: dict) -> dict:
        return {"keyword": normalize_keyword(query.get("keyword"))}

    def collect(self, query: dict) -> list[CollectedItem]:
        keyword = self.validate_query(query)["keyword"]
        payload = self.client.get_json(
            "https://www.wikidata.org/w/api.php",
            params={
                "action": "wbsearchentities",
                "search": keyword,
                "language": settings.osint_search_language,
                "format": "json",
                "limit": min(settings.osint_max_items_per_collector, 50),
            },
            allowed_hosts={"www.wikidata.org"},
        )
        results = payload.get("search", []) if isinstance(payload, dict) else []
        data = {"keyword": keyword, "results": results}
        return [
            _json_item(
                source_type="knowledge_graph",
                locator="https://www.wikidata.org/w/api.php",
                kind="wikidata_entities",
                title=f"Wikidata search for {keyword}",
                data=data,
                provider="Wikidata",
            )
        ]


class WikipediaSearchCollector(Collector):
    name = "keyword_wikipedia"
    description = "Searches public Wikipedia article metadata in the configured language."
    target_types = frozenset({"keyword"})
    query_field = "keyword"

    def __init__(self, client: SafeHttpClient | None = None):
        self.client = client or SafeHttpClient()

    def validate_query(self, query: dict) -> dict:
        return {"keyword": normalize_keyword(query.get("keyword"))}

    def collect(self, query: dict) -> list[CollectedItem]:
        keyword = self.validate_query(query)["keyword"]
        host = f"{settings.osint_search_language}.wikipedia.org"
        payload = self.client.get_json(
            f"https://{host}/w/api.php",
            params={
                "action": "query",
                "list": "search",
                "srsearch": keyword,
                "format": "json",
                "srlimit": min(settings.osint_max_items_per_collector, 50),
            },
            allowed_hosts={host},
        )
        results = (
            payload.get("query", {}).get("search", [])
            if isinstance(payload, dict)
            else []
        )
        data = {"keyword": keyword, "results": results}
        return [
            _json_item(
                source_type="encyclopedia",
                locator=f"https://{host}/w/api.php",
                kind="wikipedia_articles",
                title=f"Wikipedia search for {keyword}",
                data=data,
                provider="Wikipedia",
            )
        ]


class OpenAlexSearchCollector(Collector):
    name = "keyword_openalex"
    description = "Searches public scholarly works and authors through OpenAlex."
    target_types = frozenset({"keyword"})
    query_field = "keyword"

    def __init__(self, client: SafeHttpClient | None = None):
        self.client = client or SafeHttpClient()

    def validate_query(self, query: dict) -> dict:
        return {"keyword": normalize_keyword(query.get("keyword"))}

    def collect(self, query: dict) -> list[CollectedItem]:
        keyword = self.validate_query(query)["keyword"]
        payload = self.client.get_json(
            "https://api.openalex.org/works",
            params={
                "search": keyword,
                "per-page": min(settings.osint_max_items_per_collector, 50),
                "select": "id,doi,title,display_name,publication_year,type,authorships,primary_location",
            },
            allowed_hosts={"api.openalex.org"},
        )
        data = {
            "keyword": keyword,
            "meta": payload.get("meta") if isinstance(payload, dict) else None,
            "results": payload.get("results", []) if isinstance(payload, dict) else [],
        }
        return [
            _json_item(
                source_type="scholarly_index",
                locator="https://api.openalex.org/works",
                kind="scholarly_works",
                title=f"OpenAlex search for {keyword}",
                data=data,
                provider="OpenAlex",
            )
        ]


class GitHubUserCollector(Collector):
    name = "username_github"
    description = "Retrieves the public profile metadata for a GitHub username."
    target_types = frozenset({"username"})
    query_field = "username"

    def __init__(self, client: SafeHttpClient | None = None):
        self.client = client or SafeHttpClient()

    def validate_query(self, query: dict) -> dict:
        return {"username": normalize_username(query.get("username"))}

    def collect(self, query: dict) -> list[CollectedItem]:
        username = self.validate_query(query)["username"]
        locator = f"https://api.github.com/users/{quote(username)}"
        payload = self.client.get_json(
            locator,
            headers={"Accept": "application/vnd.github+json"},
            allowed_hosts={"api.github.com"},
        )
        return [
            _json_item(
                source_type="developer_profile",
                locator=locator,
                kind="github_user",
                title=f"GitHub public profile for {username}",
                data=payload,
                provider="GitHub",
            )
        ]


class GitLabUserCollector(Collector):
    name = "username_gitlab"
    description = "Searches public GitLab.com profiles for an exact username."
    target_types = frozenset({"username"})
    query_field = "username"

    def __init__(self, client: SafeHttpClient | None = None):
        self.client = client or SafeHttpClient()

    def validate_query(self, query: dict) -> dict:
        return {"username": normalize_username(query.get("username"))}

    def collect(self, query: dict) -> list[CollectedItem]:
        username = self.validate_query(query)["username"]
        payload = self.client.get_json(
            "https://gitlab.com/api/v4/users",
            params={"username": username},
            allowed_hosts={"gitlab.com"},
        )
        return [
            _json_item(
                source_type="developer_profile",
                locator="https://gitlab.com/api/v4/users",
                kind="gitlab_user",
                title=f"GitLab public profile for {username}",
                data={"username": username, "results": payload},
                provider="GitLab",
            )
        ]
