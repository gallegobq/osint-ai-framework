from urllib.parse import quote

from pydantic import SecretStr

from app.core.settings import settings
from app.osint.contracts import CollectedItem, Collector
from app.osint.domain import normalize_domain
from app.osint.http import SafeHttpClient
from app.osint.passive_collectors import _json_item
from app.osint.targets import normalize_hash, normalize_ip


def _secret_available(value: SecretStr | None) -> bool:
    return bool(value and value.get_secret_value())


class ShodanIpCollector(Collector):
    name = "ip_shodan"
    description = "Retrieves Shodan host intelligence for a public IP address."
    target_types = frozenset({"ip"})
    query_field = "ip"
    requires_api_key = True

    def __init__(self, client: SafeHttpClient | None = None):
        self.client = client or SafeHttpClient()

    def availability(self) -> tuple[bool, str | None]:
        available = _secret_available(settings.shodan_api_key)
        return available, None if available else "Configure SHODAN_API_KEY."

    def validate_query(self, query: dict) -> dict:
        return {"ip": normalize_ip(query.get("ip"))}

    def collect(self, query: dict) -> list[CollectedItem]:
        ip = self.validate_query(query)["ip"]
        key = settings.shodan_api_key
        if not _secret_available(key):
            raise RuntimeError("Shodan is not configured.")
        endpoint = f"https://api.shodan.io/shodan/host/{quote(ip)}"
        payload = self.client.get_json(
            endpoint,
            params={"key": key.get_secret_value(), "minify": "true"},
            allowed_hosts={"api.shodan.io"},
        )
        return [
            _json_item(
                source_type="threat_intelligence",
                locator=f"https://www.shodan.io/host/{quote(ip)}",
                kind="shodan_host",
                title=f"Shodan host intelligence for {ip}",
                data=payload,
                provider="Shodan",
            )
        ]


class _VirusTotalCollector(Collector):
    requires_api_key = True
    endpoint_collection: str
    target_type: str

    def __init__(self, client: SafeHttpClient | None = None):
        self.client = client or SafeHttpClient()

    def availability(self) -> tuple[bool, str | None]:
        available = _secret_available(settings.virustotal_api_key)
        return available, None if available else "Configure VIRUSTOTAL_API_KEY."

    def _collect(self, value: str, title: str, kind: str) -> list[CollectedItem]:
        key = settings.virustotal_api_key
        if not _secret_available(key):
            raise RuntimeError("VirusTotal is not configured.")
        endpoint = (
            f"https://www.virustotal.com/api/v3/{self.endpoint_collection}/"
            f"{quote(value)}"
        )
        payload = self.client.get_json(
            endpoint,
            headers={"x-apikey": key.get_secret_value()},
            allowed_hosts={"www.virustotal.com"},
        )
        return [
            _json_item(
                source_type="threat_intelligence",
                locator=endpoint,
                kind=kind,
                title=title,
                data=payload,
                provider="VirusTotal",
            )
        ]


class VirusTotalDomainCollector(_VirusTotalCollector):
    name = "domain_virustotal"
    description = "Retrieves VirusTotal reputation and context for a domain."
    target_types = frozenset({"domain", "hostname"})
    query_field = "domain"
    endpoint_collection = "domains"

    def validate_query(self, query: dict) -> dict:
        return {"domain": normalize_domain(query.get("domain"))}

    def collect(self, query: dict) -> list[CollectedItem]:
        domain = self.validate_query(query)["domain"]
        return self._collect(
            domain,
            f"VirusTotal domain intelligence for {domain}",
            "virustotal_domain",
        )


class VirusTotalIpCollector(_VirusTotalCollector):
    name = "ip_virustotal"
    description = "Retrieves VirusTotal reputation and context for a public IP."
    target_types = frozenset({"ip"})
    query_field = "ip"
    endpoint_collection = "ip_addresses"

    def validate_query(self, query: dict) -> dict:
        return {"ip": normalize_ip(query.get("ip"))}

    def collect(self, query: dict) -> list[CollectedItem]:
        ip = self.validate_query(query)["ip"]
        return self._collect(
            ip,
            f"VirusTotal IP intelligence for {ip}",
            "virustotal_ip",
        )


class VirusTotalHashCollector(_VirusTotalCollector):
    name = "hash_virustotal"
    description = "Retrieves VirusTotal reputation and context for an MD5, SHA-1, or SHA-256 hash."
    target_types = frozenset({"hash"})
    query_field = "hash"
    endpoint_collection = "files"

    def validate_query(self, query: dict) -> dict:
        return {"hash": normalize_hash(query.get("hash"))}

    def collect(self, query: dict) -> list[CollectedItem]:
        file_hash = self.validate_query(query)["hash"]
        return self._collect(
            file_hash,
            f"VirusTotal file intelligence for {file_hash}",
            "virustotal_file",
        )


class SecurityTrailsDomainCollector(Collector):
    name = "domain_securitytrails"
    description = "Retrieves SecurityTrails domain, DNS and registration context."
    target_types = frozenset({"domain"})
    query_field = "domain"
    requires_api_key = True

    def __init__(self, client: SafeHttpClient | None = None):
        self.client = client or SafeHttpClient()

    def availability(self) -> tuple[bool, str | None]:
        available = _secret_available(settings.securitytrails_api_key)
        return available, None if available else "Configure SECURITYTRAILS_API_KEY."

    def validate_query(self, query: dict) -> dict:
        return {"domain": normalize_domain(query.get("domain"))}

    def collect(self, query: dict) -> list[CollectedItem]:
        domain = self.validate_query(query)["domain"]
        key = settings.securitytrails_api_key
        if not _secret_available(key):
            raise RuntimeError("SecurityTrails is not configured.")
        endpoint = f"https://api.securitytrails.com/v1/domain/{quote(domain)}"
        payload = self.client.get_json(
            endpoint,
            headers={"APIKEY": key.get_secret_value()},
            allowed_hosts={"api.securitytrails.com"},
        )
        return [
            _json_item(
                source_type="domain_intelligence",
                locator=endpoint,
                kind="securitytrails_domain",
                title=f"SecurityTrails intelligence for {domain}",
                data=payload,
                provider="SecurityTrails",
            )
        ]
