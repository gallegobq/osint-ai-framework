import ipaddress
from datetime import datetime, timezone

from app.osint.contracts import CollectedItem, Collector
from app.osint.http import SafeHttpClient
from app.osint.passive_collectors import _json_item
from app.osint.routing_history_collector import _timestamp
from app.osint.targets import normalize_ip


class IpRpkiCollector(Collector):
    name = "ip_ripestat_rpki"
    description = "Checks provider-reported RPKI validity for observed IP prefix origins."
    target_types = frozenset({"ip"})
    query_field = "ip"
    provider = "RIPE NCC RIPEstat / Routinator"
    reference_url = "https://data.stat.ripe.net/docs/data-api/api-endpoints/rpki-validation"
    overview_endpoint = "https://stat.ripe.net/data/prefix-overview/data.json"
    endpoint = "https://stat.ripe.net/data/rpki-validation/data.json"
    module_family = "routing_security"
    capability_id = "routing_security:ripe-rpki-ip-origins"
    maximum_origins = 5
    validity_states = frozenset({"valid", "invalid_asn", "invalid_length", "unknown"})

    def __init__(self, client: SafeHttpClient | None = None):
        self.client = client or SafeHttpClient()

    def validate_query(self, query: dict) -> dict:
        return {"ip": normalize_ip(query.get("ip"))}

    def _request(self, endpoint: str, version: str, params: dict) -> dict:
        payload = self.client.get_json(
            endpoint,
            params={**params, "preferred_version": version, "sourceapp": "osint-ai-framework"},
            allowed_hosts={"stat.ripe.net"},
        )
        if (
            not isinstance(payload, dict) or payload.get("status") != "ok"
            or payload.get("version") != version or not isinstance(payload.get("data"), dict)
        ):
            raise ValueError("Unexpected RIPEstat RPKI pipeline response.")
        return payload["data"]

    def collect(self, query: dict) -> list[CollectedItem]:
        ip = self.validate_query(query)["ip"]
        address = ipaddress.ip_address(ip)
        overview = self._request(self.overview_endpoint, "1.3", {
            "resource": ip, "min_peers_seeing": 10, "max_related": 0,
        })
        resource = overview.get("resource")
        if not isinstance(resource, str) or len(resource) > 64:
            raise ValueError("Invalid RIPEstat observed prefix.")
        network = ipaddress.ip_network(resource, strict=True)
        if network.version != address.version or address not in network:
            raise ValueError("RIPEstat returned a prefix unrelated to the target.")
        prefix = network.with_prefixlen
        observed = _timestamp(overview.get("query_time"))
        if observed > datetime.now(timezone.utc):
            raise ValueError("Invalid RIPEstat prefix observation time.")
        announced = overview.get("announced")
        filtered = overview.get("num_filtered_out")
        origins = overview.get("asns")
        if (
            overview.get("type") != "prefix" or not isinstance(announced, bool)
            or not isinstance(filtered, int) or isinstance(filtered, bool)
            or not 0 <= filtered <= 2_147_483_647
            or not isinstance(origins, list) or len(origins) > self.maximum_origins
            or announced != bool(origins)
        ):
            raise ValueError("Invalid, inconsistent or oversized RIPEstat prefix origins.")
        asns = set()
        for origin in origins:
            number = origin.get("asn") if isinstance(origin, dict) else None
            if (
                not isinstance(number, int) or isinstance(number, bool)
                or not 1 <= number <= 4_294_967_295 or number in asns
            ):
                raise ValueError("Invalid or duplicate RIPEstat origin ASN.")
            asns.add(number)
        # Validate the complete overview before making any RPKI lookups. Never
        # emit a partially validated multi-origin result after a provider failure.
        validations = []
        for number in sorted(asns):
            asn = f"AS{number}"
            result = self._request(self.endpoint, "0.3", {"resource": asn, "prefix": prefix})
            state = result.get("status")
            validator = result.get("validator")
            if (
                str(result.get("resource")) not in {asn, str(number)}
                or result.get("prefix") != prefix
                or not isinstance(state, str) or state not in self.validity_states
                or not isinstance(validator, str) or not validator.strip() or len(validator) > 100
            ):
                raise ValueError("Invalid RIPEstat RPKI identity or validity state.")
            validations.append({"origin_asn": asn, "prefix": prefix,
                                "status": state, "validator": validator})
        return [_json_item(
            source_type="routing_security", locator=self.endpoint, kind=self.name,
            title=f"Observed prefix-origin RPKI validity for {ip}", provider=self.provider,
            data={
                "ip": ip, "prefix": prefix, "announced": announced,
                "routing_query_time": observed.isoformat(),
                "validation_checked_at": datetime.now(timezone.utc).isoformat(),
                "num_filtered_out": filtered, "validations": validations,
                "origins_checked": len(validations), "minimum_ris_peers": 10,
                "scope": "Provider-reported RPKI origin validity for the single returned "
                "containing prefix, not local cryptographic verification, route ownership "
                "or evidence of malicious activity or a hijack. Unknown is not invalid. "
                "RIS may filter low-visibility routes; related prefixes are excluded. "
                "Routing observation and current validator lookups are not atomic. "
                "An unannounced prefix has no origin to validate, not an unknown verdict.",
            },
        )]
