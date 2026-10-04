import ipaddress
from dataclasses import dataclass
from urllib.parse import quote

import httpx

from app.core.exceptions import BadRequestException
from app.core.settings import settings
from app.osint.contracts import CollectedItem, Collector, DiscoveredTarget
from app.osint.domain import normalize_domain
from app.osint.http import SafeHttpClient
from app.osint.passive_collectors import _json_item
from app.osint.targets import (
    normalize_hash,
    normalize_hostname,
    normalize_ip,
    normalize_keyword,
    normalize_username,
)


@dataclass(frozen=True, slots=True)
class DnsModuleSpec:
    name: str
    description: str
    record_type: str
    prefix: str = ""
    answer_prefix: str | None = None


DNS_MODULE_SPECS = (
    DnsModuleSpec("domain_dns_google_ds", "Retrieves DNSSEC DS records.", "DS"),
    DnsModuleSpec(
        "domain_dns_google_dnskey", "Retrieves DNSSEC public keys.", "DNSKEY"
    ),
    DnsModuleSpec(
        "domain_dns_google_https", "Retrieves HTTPS service-binding records.", "HTTPS"
    ),
    DnsModuleSpec(
        "domain_dns_dmarc",
        "Checks the public DMARC policy record.",
        "TXT",
        prefix="_dmarc",
        answer_prefix="v=DMARC1",
    ),
    DnsModuleSpec(
        "domain_dns_spf",
        "Checks the public SPF policy record.",
        "TXT",
        answer_prefix="v=spf1",
    ),
    DnsModuleSpec(
        "domain_dns_mta_sts",
        "Checks the public MTA-STS discovery record.",
        "TXT",
        prefix="_mta-sts",
        answer_prefix="v=STSv1",
    ),
    DnsModuleSpec(
        "domain_dns_tls_reporting",
        "Checks the public SMTP TLS reporting policy.",
        "TXT",
        prefix="_smtp._tls",
        answer_prefix="v=TLSRPTv1",
    ),
    DnsModuleSpec(
        "domain_dns_bimi_default",
        "Checks the default BIMI selector record.",
        "TXT",
        prefix="default._bimi",
        answer_prefix="v=BIMI1",
    ),
)

COMMON_SRV_PREFIXES = (
    "_autodiscover._tcp",
    "_caldav._tcp",
    "_carddav._tcp",
    "_kerberos._tcp",
    "_ldap._tcp",
    "_minecraft._tcp",
    "_sip._tcp",
    "_sip._udp",
    "_sips._tcp",
    "_xmpp-client._tcp",
    "_xmpp-server._tcp",
)


def _clean_dns_text(value: object) -> str:
    return str(value or "").strip().strip('"')


def _dns_discoveries(record_type: str, answers: list[dict]) -> tuple[DiscoveredTarget, ...]:
    discoveries: list[DiscoveredTarget] = []
    for answer in answers:
        value = _clean_dns_text(answer.get("data"))
        if not value:
            continue
        if record_type in {"A", "AAAA"}:
            discoveries.append(DiscoveredTarget("ip", value, "dns_resolves_to"))
        elif record_type == "MX":
            discoveries.append(
                DiscoveredTarget("hostname", value.split()[-1].rstrip("."), "mail_exchanger")
            )
        elif record_type == "NS":
            discoveries.append(
                DiscoveredTarget("hostname", value.rstrip("."), "name_server")
            )
        elif record_type == "SRV" and len(value.split()) >= 4:
            discoveries.append(
                DiscoveredTarget("hostname", value.split()[-1].rstrip("."), "service_target")
            )
    return tuple(discoveries[: settings.orchestrator_max_discovery_events])


class DnsPolicyCollector(Collector):
    target_types = frozenset({"domain", "hostname"})
    query_field = "domain"
    profiles = frozenset({"footprint", "investigate"})
    provider = "Google Public DNS"
    reference_url = "https://developers.google.com/speed/public-dns/docs/doh/json"
    module_family = "dns"

    def __init__(
        self,
        spec: DnsModuleSpec,
        client: SafeHttpClient | None = None,
    ):
        self.spec = spec
        self.name = spec.name
        self.description = spec.description
        self.client = client or SafeHttpClient()
        emitted = set()
        if spec.record_type in {"A", "AAAA"}:
            emitted.add("ip")
        if spec.record_type in {"MX", "NS", "SRV"}:
            emitted.add("hostname")
        self.emitted_target_types = frozenset(emitted)

    def validate_query(self, query: dict) -> dict:
        return {"domain": normalize_domain(query.get("domain"))}

    def collect(self, query: dict) -> list[CollectedItem]:
        domain = self.validate_query(query)["domain"]
        query_name = f"{self.spec.prefix}.{domain}" if self.spec.prefix else domain
        payload = self.client.get_json(
            "https://dns.google/resolve",
            params={"name": query_name, "type": self.spec.record_type, "do": "1"},
            allowed_hosts={"dns.google"},
        )
        if not isinstance(payload, dict):
            raise ValueError("Unexpected DNS-over-HTTPS response.")
        answers = [
            item
            for item in (payload.get("Answer") or [])
            if isinstance(item, dict)
        ]
        if self.spec.answer_prefix:
            expected = self.spec.answer_prefix.lower()
            answers = [
                item
                for item in answers
                if _clean_dns_text(item.get("data")).lower().startswith(expected)
            ]
        answers = answers[: settings.osint_max_items_per_collector]
        data = {
            "domain": domain,
            "query_name": query_name,
            "record_type": self.spec.record_type,
            "status": payload.get("Status"),
            "dnssec_validated": payload.get("AD", False),
            "answers": answers,
            "policy_present": bool(answers)
            if self.spec.answer_prefix
            else None,
        }
        return [
            _json_item(
                source_type="dns",
                locator=f"dns://{query_name}/{self.spec.record_type}",
                kind=self.name,
                title=f"{self.description.rstrip('.')} for {domain}",
                data=data,
                provider=self.provider,
                discoveries=_dns_discoveries(self.spec.record_type, answers),
            )
        ]


class DnsCommonSrvCollector(Collector):
    name = "domain_dns_common_srv"
    description = "Checks a bounded set of common DNS SRV service records."
    target_types = frozenset({"domain", "hostname"})
    query_field = "domain"
    profiles = frozenset({"footprint", "investigate"})
    emitted_target_types = frozenset({"hostname"})
    provider = "Google Public DNS"
    reference_url = "https://www.rfc-editor.org/rfc/rfc2782"
    module_family = "dns"

    def __init__(self, client: SafeHttpClient | None = None):
        self.client = client or SafeHttpClient()

    def validate_query(self, query: dict) -> dict:
        return {"domain": normalize_domain(query.get("domain"))}

    def collect(self, query: dict) -> list[CollectedItem]:
        domain = self.validate_query(query)["domain"]
        records: list[dict] = []
        discoveries: list[DiscoveredTarget] = []
        for prefix in COMMON_SRV_PREFIXES:
            remaining = settings.osint_max_items_per_collector - sum(
                len(record["answers"]) for record in records
            )
            if remaining <= 0:
                break
            query_name = f"{prefix}.{domain}"
            payload = self.client.get_json(
                "https://dns.google/resolve",
                params={"name": query_name, "type": "SRV", "do": "1"},
                allowed_hosts={"dns.google"},
            )
            if not isinstance(payload, dict):
                raise ValueError("Unexpected DNS-over-HTTPS response.")
            answers = [
                item
                for item in (payload.get("Answer") or [])
                if isinstance(item, dict)
            ][:remaining]
            if not answers:
                continue
            records.append(
                {
                    "query_name": query_name,
                    "dnssec_validated": payload.get("AD", False),
                    "answers": answers,
                }
            )
            discoveries.extend(_dns_discoveries("SRV", answers))

        return [
            _json_item(
                source_type="dns",
                locator=f"dns://{domain}/SRV",
                kind=self.name,
                title=f"Common DNS SRV services for {domain}",
                data={"domain": domain, "records": records},
                provider=self.provider,
                discoveries=tuple(
                    discoveries[: settings.orchestrator_max_discovery_events]
                ),
            )
        ]


@dataclass(frozen=True, slots=True)
class IpFeedSpec:
    name: str
    description: str
    provider: str
    feed_url: str
    reference_url: str

    @property
    def allowed_host(self) -> str:
        return self.feed_url.split("/", 3)[2]


IP_FEED_SPECS = (
    IpFeedSpec(
        "ip_tor_exit_nodes",
        "Checks the Tor Project bulk exit-node list.",
        "Tor Project",
        "https://check.torproject.org/torbulkexitlist",
        "https://check.torproject.org/exit-addresses",
    ),
    IpFeedSpec(
        "ip_feodo_tracker",
        "Checks abuse.ch Feodo Tracker's botnet C2 blocklist.",
        "abuse.ch Feodo Tracker",
        "https://feodotracker.abuse.ch/downloads/ipblocklist.txt",
        "https://feodotracker.abuse.ch/blocklist/",
    ),
    IpFeedSpec(
        "ip_ipsum_level3",
        "Checks IPsum's confidence-filtered malicious-IP feed.",
        "IPsum",
        "https://raw.githubusercontent.com/stamparm/ipsum/master/levels/3.txt",
        "https://github.com/stamparm/ipsum",
    ),
    IpFeedSpec(
        "ip_emerging_threats_compromised",
        "Checks the Emerging Threats compromised-IP rules feed.",
        "Proofpoint Emerging Threats",
        "https://rules.emergingthreats.net/blockrules/compromised-ips.txt",
        "https://rules.emergingthreats.net/",
    ),
    IpFeedSpec(
        "ip_cins_army",
        "Checks the CINS Army malicious-IP list.",
        "CINS Army",
        "https://cinsscore.com/list/ci-badguys.txt",
        "https://cinsscore.com/",
    ),
)


class IpFeedMembershipCollector(Collector):
    target_types = frozenset({"ip"})
    query_field = "ip"
    profiles = frozenset({"investigate"})
    module_family = "threat_feed"

    def __init__(
        self,
        spec: IpFeedSpec,
        client: SafeHttpClient | None = None,
    ):
        self.spec = spec
        self.name = spec.name
        self.description = spec.description
        self.provider = spec.provider
        self.reference_url = spec.reference_url
        self.client = client or SafeHttpClient()

    def validate_query(self, query: dict) -> dict:
        return {"ip": normalize_ip(query.get("ip"))}

    def collect(self, query: dict) -> list[CollectedItem]:
        ip = self.validate_query(query)["ip"]
        body = self.client.get_text(
            self.spec.feed_url,
            allowed_hosts={self.spec.allowed_host},
        )
        match = None
        entries_checked = 0
        for line in body.splitlines():
            candidate = line.strip()
            if not candidate or candidate.startswith("#"):
                continue
            token = candidate.split()[0].split(",", 1)[0]
            try:
                normalized = ipaddress.ip_address(token).compressed
            except ValueError:
                continue
            entries_checked += 1
            if normalized == ip:
                match = candidate[:500]
                break
        if entries_checked == 0:
            raise RuntimeError("Threat feed did not contain valid IP entries.")
        data = {
            "ip": ip,
            "listed": match is not None,
            "matched_entry": match,
            "entries_checked": entries_checked,
        }
        return [
            _json_item(
                source_type="threat_intelligence",
                locator=self.spec.reference_url,
                kind=self.name,
                title=f"{self.provider} status for {ip}",
                data=data,
                provider=self.provider,
            )
        ]


class IpApiGeoCollector(Collector):
    name = "ip_ipapi_geo"
    description = "Retrieves public geolocation, network and ASN context from ipapi.co."
    target_types = frozenset({"ip"})
    query_field = "ip"
    profiles = frozenset({"footprint", "investigate"})
    emitted_target_types = frozenset({"asn", "hostname"})
    provider = "ipapi.co"
    reference_url = "https://ipapi.co/api/"
    module_family = "network_enrichment"

    def __init__(self, client: SafeHttpClient | None = None):
        self.client = client or SafeHttpClient()

    def validate_query(self, query: dict) -> dict:
        return {"ip": normalize_ip(query.get("ip"))}

    def collect(self, query: dict) -> list[CollectedItem]:
        ip = self.validate_query(query)["ip"]
        endpoint = f"https://ipapi.co/{quote(ip)}/json/"
        payload = self.client.get_json(endpoint, allowed_hosts={"ipapi.co"})
        if not isinstance(payload, dict) or payload.get("error"):
            raise RuntimeError("ipapi.co returned an error response.")
        discoveries = []
        if payload.get("asn"):
            discoveries.append(DiscoveredTarget("asn", str(payload["asn"]), "announced_by"))
        if payload.get("hostname"):
            discoveries.append(
                DiscoveredTarget("hostname", str(payload["hostname"]), "observed_hostname")
            )
        return [
            _json_item(
                source_type="network_geolocation",
                locator=endpoint,
                kind=self.name,
                title=f"ipapi.co network context for {ip}",
                data=payload,
                provider=self.provider,
                discoveries=tuple(discoveries),
            )
        ]


class CirclHashlookupCollector(Collector):
    name = "hash_circl_hashlookup"
    description = "Checks whether a file hash is present in CIRCL's known-file corpus."
    target_types = frozenset({"hash"})
    query_field = "hash"
    profiles = frozenset({"investigate"})
    provider = "CIRCL hashlookup"
    reference_url = "https://circl.lu/services/hashlookup/"
    module_family = "file_intelligence"

    def __init__(self, client: SafeHttpClient | None = None):
        self.client = client or SafeHttpClient()

    def validate_query(self, query: dict) -> dict:
        return {"hash": normalize_hash(query.get("hash"))}

    def collect(self, query: dict) -> list[CollectedItem]:
        file_hash = self.validate_query(query)["hash"]
        algorithm = {32: "md5", 40: "sha1", 64: "sha256"}[len(file_hash)]
        endpoint = (
            f"https://hashlookup.circl.lu/lookup/{algorithm}/{quote(file_hash)}"
        )
        found = True
        try:
            payload = self.client.get_json(
                endpoint,
                allowed_hosts={"hashlookup.circl.lu"},
            )
        except httpx.HTTPStatusError as exc:
            if exc.response.status_code != 404:
                raise
            found = False
            payload = {}
        if not isinstance(payload, dict):
            raise ValueError("Unexpected CIRCL hashlookup response.")
        data = {
            "hash": file_hash,
            "algorithm": algorithm,
            "found": found,
            "record": payload if found else None,
        }
        return [
            _json_item(
                source_type="file_intelligence",
                locator=endpoint,
                kind=self.name,
                title=f"CIRCL known-file context for {file_hash}",
                data=data,
                provider=self.provider,
            )
        ]


class SslblCertificateHashCollector(Collector):
    name = "hash_sslbl_certificate"
    description = (
        "Checks a SHA-1 TLS certificate fingerprint against abuse.ch SSLBL."
    )
    target_types = frozenset({"hash"})
    query_field = "hash"
    profiles = frozenset({"investigate"})
    provider = "abuse.ch SSLBL"
    reference_url = "https://sslbl.abuse.ch/blacklist/"
    module_family = "threat_feed"
    capability_id = "hash_reputation:sslbl-certificate"
    feed_url = "https://sslbl.abuse.ch/blacklist/sslblacklist.csv"
    minimum_entries = 100
    maximum_entries = 50_000

    def __init__(self, client: SafeHttpClient | None = None):
        self.client = client or SafeHttpClient()

    def validate_query(self, query: dict) -> dict:
        fingerprint = normalize_hash(query.get("hash"))
        if len(fingerprint) != 40:
            raise BadRequestException(
                "SSLBL certificate fingerprints must use SHA-1."
            )
        return {"hash": fingerprint}

    def collect(self, query: dict) -> list[CollectedItem]:
        fingerprint = self.validate_query(query)["hash"]
        body = self.client.get_text(
            self.feed_url,
            headers={"Accept": "text/csv"},
            allowed_hosts={"sslbl.abuse.ch"},
        )
        if not isinstance(body, str):
            raise ValueError("Unexpected SSLBL certificate-feed response.")

        fingerprints: set[str] = set()
        rejected_entries = 0
        matched_entry = None
        raw_entries = 0
        for line in body.splitlines():
            candidate = line.strip()
            if not candidate or candidate.startswith("#"):
                continue
            raw_entries += 1
            if raw_entries > self.maximum_entries:
                raise RuntimeError(
                    "SSLBL certificate feed exceeded the safe entry limit."
                )
            fields = candidate.split(",", 2)
            if len(fields) != 3:
                rejected_entries += 1
                continue
            try:
                normalized = normalize_hash(fields[1])
            except BadRequestException:
                rejected_entries += 1
                continue
            if len(normalized) != 40:
                rejected_entries += 1
                continue
            fingerprints.add(normalized)
            if normalized == fingerprint:
                matched_entry = {
                    "listing_date": fields[0].strip()[:100],
                    "reason": fields[2].strip()[:500],
                }

        if len(fingerprints) < self.minimum_entries:
            raise RuntimeError(
                "SSLBL certificate feed did not contain enough valid entries."
            )
        return [
            _json_item(
                source_type="threat_intelligence",
                locator=self.feed_url,
                kind=self.name,
                title=f"SSLBL certificate status for {fingerprint}",
                data={
                    "hash": fingerprint,
                    "algorithm": "sha1",
                    "listed": matched_entry is not None,
                    "listing": matched_entry,
                    "entries_checked": len(fingerprints),
                    "rejected_entries": rejected_entries,
                },
                provider=self.provider,
            )
        ]


class KeybaseUserCollector(Collector):
    name = "username_keybase"
    description = "Retrieves a public Keybase identity profile by username."
    target_types = frozenset({"username"})
    query_field = "username"
    profiles = frozenset({"investigate"})
    provider = "Keybase"
    reference_url = "https://keybase.io/docs/api/1.0/call/user/lookup"
    module_family = "identity"

    def __init__(self, client: SafeHttpClient | None = None):
        self.client = client or SafeHttpClient()

    def validate_query(self, query: dict) -> dict:
        return {"username": normalize_username(query.get("username"))}

    def collect(self, query: dict) -> list[CollectedItem]:
        username = self.validate_query(query)["username"]
        payload = self.client.get_json(
            "https://keybase.io/_/api/1.0/user/lookup.json",
            params={"usernames": username},
            allowed_hosts={"keybase.io"},
        )
        if not isinstance(payload, dict):
            raise ValueError("Unexpected Keybase response.")
        status = payload.get("status") or {}
        if isinstance(status, dict) and status.get("code") not in {None, 0}:
            raise RuntimeError("Keybase returned an error response.")
        raw_profiles = payload.get("them") or []
        profiles = (
            [profile for profile in raw_profiles if isinstance(profile, dict)]
            if isinstance(raw_profiles, list)
            else []
        )
        data = {
            "username": username,
            "found": bool(profiles),
            "profiles": profiles[:1],
        }
        return [
            _json_item(
                source_type="public_identity",
                locator=f"https://keybase.io/{quote(username)}",
                kind=self.name,
                title=f"Keybase profile for {username}",
                data=data,
                provider=self.provider,
            )
        ]


class GleifOrganizationCollector(Collector):
    name = "keyword_gleif"
    description = "Searches GLEIF's public LEI records for an organization name."
    target_types = frozenset({"keyword"})
    query_field = "keyword"
    profiles = frozenset({"investigate"})
    provider = "GLEIF"
    reference_url = "https://www.gleif.org/en/lei-data/gleif-api"
    module_family = "organization"

    def __init__(self, client: SafeHttpClient | None = None):
        self.client = client or SafeHttpClient()

    def validate_query(self, query: dict) -> dict:
        return {"keyword": normalize_keyword(query.get("keyword"))}

    def collect(self, query: dict) -> list[CollectedItem]:
        keyword = self.validate_query(query)["keyword"]
        payload = self.client.get_json(
            "https://api.gleif.org/api/v1/lei-records",
            params={
                "filter[entity.legalName]": keyword,
                "page[size]": min(settings.osint_max_items_per_collector, 20),
            },
            allowed_hosts={"api.gleif.org"},
        )
        if not isinstance(payload, dict):
            raise ValueError("Unexpected GLEIF response.")
        records = payload.get("data") or []
        data = {
            "keyword": keyword,
            "records": records[: settings.osint_max_items_per_collector]
            if isinstance(records, list)
            else [],
            "meta": payload.get("meta"),
        }
        return [
            _json_item(
                source_type="organization_registry",
                locator="https://search.gleif.org/",
                kind=self.name,
                title=f"GLEIF organization records for {keyword}",
                data=data,
                provider=self.provider,
            )
        ]


class HackerTargetDomainCollector(Collector):
    name = "domain_hackertarget_hostsearch"
    description = "Retrieves passive hostname and address pairs from HackerTarget."
    target_types = frozenset({"domain", "hostname"})
    query_field = "domain"
    profiles = frozenset({"footprint", "investigate"})
    emitted_target_types = frozenset({"hostname", "ip"})
    provider = "HackerTarget"
    reference_url = "https://hackertarget.com/recon-ng-tutorial/"
    module_family = "passive_dns"

    def __init__(self, client: SafeHttpClient | None = None):
        self.client = client or SafeHttpClient()

    def validate_query(self, query: dict) -> dict:
        return {"domain": normalize_domain(query.get("domain"))}

    def collect(self, query: dict) -> list[CollectedItem]:
        domain = self.validate_query(query)["domain"]
        body = self.client.get_text(
            "https://api.hackertarget.com/hostsearch/",
            params={"q": domain},
            allowed_hosts={"api.hackertarget.com"},
        )
        normalized_body = body.strip().lower()
        if normalized_body.startswith("error") or any(
            marker in normalized_body
            for marker in ("api count exceeded", "invalid query", "no api key")
        ):
            raise RuntimeError("HackerTarget returned an error response.")
        rows = []
        discoveries = []
        for line in body.splitlines():
            if "," not in line:
                continue
            raw_hostname, raw_ip = (part.strip() for part in line.split(",", 1))
            try:
                hostname = normalize_hostname(raw_hostname)
                ip = normalize_ip(raw_ip)
            except BadRequestException:
                continue
            rows.append({"hostname": hostname, "ip": ip})
            discoveries.extend(
                (
                    DiscoveredTarget("hostname", hostname, "passive_dns"),
                    DiscoveredTarget("ip", ip, "resolves_to"),
                )
            )
            if len(rows) >= settings.osint_max_items_per_collector:
                break
        if not rows and normalized_body and not normalized_body.startswith(
            "no records found"
        ):
            raise RuntimeError("HackerTarget returned an unexpected response.")
        data = {"domain": domain, "results": rows}
        return [
            _json_item(
                source_type="passive_dns",
                locator=f"https://hackertarget.com/find-dns-host-records/?q={quote(domain)}",
                kind=self.name,
                title=f"HackerTarget passive hosts for {domain}",
                data=data,
                provider=self.provider,
                discoveries=tuple(
                    discoveries[: settings.orchestrator_max_discovery_events]
                ),
            )
        ]


def public_module_pack(client: SafeHttpClient | None = None) -> list[Collector]:
    return [
        *(DnsPolicyCollector(spec, client) for spec in DNS_MODULE_SPECS),
        DnsCommonSrvCollector(client),
        *(IpFeedMembershipCollector(spec, client) for spec in IP_FEED_SPECS),
        IpApiGeoCollector(client),
        CirclHashlookupCollector(client),
        SslblCertificateHashCollector(client),
        KeybaseUserCollector(client),
        GleifOrganizationCollector(client),
        HackerTargetDomainCollector(client),
    ]
