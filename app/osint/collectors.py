import json
import socket

from app.osint.contracts import CollectedItem, Collector
from app.osint.domain import normalize_domain
from app.osint.http import SafeHttpClient


class DomainDnsCollector(Collector):
    name = "domain_dns"
    description = "Resolves public A and AAAA records for a domain."
    target_types = frozenset({"domain", "hostname"})
    query_field = "domain"

    def validate_query(self, query: dict) -> dict:
        return {"domain": normalize_domain(query.get("domain"))}

    def collect(self, query: dict) -> list[CollectedItem]:
        normalized = self.validate_query(query)
        domain = normalized["domain"]
        records = socket.getaddrinfo(domain, None, type=socket.SOCK_STREAM)
        addresses = sorted({record[4][0] for record in records})
        data = {"domain": domain, "addresses": addresses}
        return [
            CollectedItem(
                source_type="dns",
                locator=f"dns://{domain}",
                kind="dns_records",
                title=f"DNS records for {domain}",
                content=json.dumps(data, ensure_ascii=False, sort_keys=True),
                raw_data=data,
            )
        ]


class DomainRdapCollector(Collector):
    name = "domain_rdap"
    description = "Retrieves public registration data through RDAP."
    target_types = frozenset({"domain"})
    query_field = "domain"

    def __init__(self, client: SafeHttpClient | None = None):
        self.client = client or SafeHttpClient()

    def validate_query(self, query: dict) -> dict:
        return {"domain": normalize_domain(query.get("domain"))}

    def collect(self, query: dict) -> list[CollectedItem]:
        normalized = self.validate_query(query)
        domain = normalized["domain"]
        locator = f"https://rdap.org/domain/{domain}"
        data = self.client.get_json(
            locator,
            allowed_hosts={"rdap.org"},
            allow_public_redirects=True,
        )

        return [
            CollectedItem(
                source_type="rdap",
                locator=locator,
                kind="domain_registration",
                title=f"RDAP registration for {domain}",
                content=json.dumps(data, ensure_ascii=False, sort_keys=True),
                raw_data=data,
                source_metadata={"provider": "RDAP.org"},
            )
        ]
