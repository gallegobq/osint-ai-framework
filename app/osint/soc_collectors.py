from urllib.parse import quote

from app.osint.contracts import CollectedItem, Collector
from app.osint.http import SafeHttpClient
from app.osint.passive_collectors import _json_item
from app.osint.targets import normalize_cve, normalize_email


class NvdCveCollector(Collector):
    name = "cve_nvd"
    description = "Retrieves the authoritative NVD record for a CVE identifier."
    target_types = frozenset({"cve"})
    query_field = "cve"

    def __init__(self, client: SafeHttpClient | None = None):
        self.client = client or SafeHttpClient()

    def validate_query(self, query: dict) -> dict:
        return {"cve": normalize_cve(query.get("cve"))}

    def collect(self, query: dict) -> list[CollectedItem]:
        cve = self.validate_query(query)["cve"]
        payload = self.client.get_json(
            "https://services.nvd.nist.gov/rest/json/cves/2.0",
            params={"cveIds": cve},
            allowed_hosts={"services.nvd.nist.gov"},
        )
        if not isinstance(payload, dict):
            raise ValueError("Unexpected NVD response.")
        vulnerabilities = payload.get("vulnerabilities") or []
        data = {
            "cve": cve,
            "found": bool(vulnerabilities),
            "vulnerabilities": vulnerabilities[:1],
        }
        return [
            _json_item(
                source_type="vulnerability_intelligence",
                locator=f"https://nvd.nist.gov/vuln/detail/{quote(cve)}",
                kind="nvd_cve",
                title=f"NVD vulnerability intelligence for {cve}",
                data=data,
                provider="NIST NVD",
            )
        ]


class CisaKevCollector(Collector):
    name = "cve_cisa_kev"
    description = "Checks whether a CVE appears in CISA's Known Exploited Vulnerabilities catalog."
    target_types = frozenset({"cve"})
    query_field = "cve"
    feed_url = (
        "https://www.cisa.gov/sites/default/files/feeds/"
        "known_exploited_vulnerabilities.json"
    )

    def __init__(self, client: SafeHttpClient | None = None):
        self.client = client or SafeHttpClient()

    def validate_query(self, query: dict) -> dict:
        return {"cve": normalize_cve(query.get("cve"))}

    def collect(self, query: dict) -> list[CollectedItem]:
        cve = self.validate_query(query)["cve"]
        payload = self.client.get_json(
            self.feed_url,
            allowed_hosts={"www.cisa.gov"},
        )
        if not isinstance(payload, dict):
            raise ValueError("Unexpected CISA KEV response.")
        matches = [
            item
            for item in (payload.get("vulnerabilities") or [])
            if isinstance(item, dict)
            and str(item.get("cveID", "")).upper() == cve
        ][:1]
        data = {
            "cve": cve,
            "known_exploited": bool(matches),
            "catalog_version": payload.get("catalogVersion"),
            "date_released": payload.get("dateReleased"),
            "entry": matches[0] if matches else None,
        }
        return [
            _json_item(
                source_type="exploitation_intelligence",
                locator="https://www.cisa.gov/known-exploited-vulnerabilities-catalog",
                kind="cisa_kev",
                title=f"CISA KEV status for {cve}",
                data=data,
                provider="CISA",
            )
        ]


class FirstEpssCollector(Collector):
    name = "cve_epss"
    description = "Retrieves FIRST EPSS exploitation probability and percentile for a CVE."
    target_types = frozenset({"cve"})
    query_field = "cve"

    def __init__(self, client: SafeHttpClient | None = None):
        self.client = client or SafeHttpClient()

    def validate_query(self, query: dict) -> dict:
        return {"cve": normalize_cve(query.get("cve"))}

    def collect(self, query: dict) -> list[CollectedItem]:
        cve = self.validate_query(query)["cve"]
        payload = self.client.get_json(
            "https://api.first.org/data/v1/epss",
            params={"cve": cve},
            allowed_hosts={"api.first.org"},
        )
        if not isinstance(payload, dict):
            raise ValueError("Unexpected FIRST EPSS response.")
        entries = payload.get("data") or []
        data = {
            "cve": cve,
            "found": bool(entries),
            "entry": entries[0] if entries else None,
        }
        return [
            _json_item(
                source_type="exploitation_probability",
                locator=f"https://api.first.org/data/v1/epss?cve={quote(cve)}",
                kind="first_epss",
                title=f"FIRST EPSS score for {cve}",
                data=data,
                provider="FIRST",
            )
        ]


class EmailDomainDnsCollector(Collector):
    name = "email_domain_dns"
    description = "Checks public MX and TXT posture for an email domain without transmitting the local part."
    target_types = frozenset({"email"})
    query_field = "email"
    record_types = ("MX", "TXT")

    def __init__(self, client: SafeHttpClient | None = None):
        self.client = client or SafeHttpClient()

    def validate_query(self, query: dict) -> dict:
        return {"email": normalize_email(query.get("email"))}

    def collect(self, query: dict) -> list[CollectedItem]:
        email = self.validate_query(query)["email"]
        domain = email.rsplit("@", 1)[1]
        records: dict[str, object] = {}
        for record_type in self.record_types:
            payload = self.client.get_json(
                "https://dns.google/resolve",
                params={"name": domain, "type": record_type, "do": "1"},
                allowed_hosts={"dns.google"},
            )
            if not isinstance(payload, dict):
                raise ValueError("Unexpected DNS-over-HTTPS response.")
            records[record_type] = {
                "status": payload.get("Status"),
                "dnssec_validated": payload.get("AD", False),
                "answers": payload.get("Answer") or [],
            }
        data = {"email_domain": domain, "records": records}
        return [
            _json_item(
                source_type="email_domain_posture",
                locator=f"dns://{domain}",
                kind="email_domain_dns",
                title=f"Public mail-domain posture for {domain}",
                data=data,
                provider="Google Public DNS",
            )
        ]
