import ipaddress
from datetime import datetime

from app.osint.contracts import CollectedItem, Collector
from app.osint.http import SafeHttpClient
from app.osint.passive_collectors import _json_item
from app.osint.targets import normalize_ip


class DshieldSubnetCollector(Collector):
    name = "ip_dshield_subnets"
    description = "Checks public IP membership in DShield's top attacking /24 subnets."
    target_types = frozenset({"ip"})
    query_field = "ip"
    provider = "SANS Internet Storm Center / DShield.org"
    reference_url = "https://isc.sans.edu/feeds_doc.html"
    feed_url = "https://feeds.dshield.org/feeds/block.txt"
    module_family = "threat_feed"
    capability_id = "ip_reputation:dshield-subnets"
    maximum_entries = 100

    def __init__(self, client: SafeHttpClient | None = None):
        self.client = client or SafeHttpClient()

    def validate_query(self, query: dict) -> dict:
        return {"ip": normalize_ip(query.get("ip"))}

    def collect(self, query: dict) -> list[CollectedItem]:
        target = ipaddress.ip_address(self.validate_query(query)["ip"])
        body = self.client.get_text(
            self.feed_url,
            headers={"Accept": "text/plain"},
            allowed_hosts={"feeds.dshield.org"},
        )
        if not isinstance(body, str) or "DShield.org Recommended Block List" not in body:
            raise ValueError("Unexpected DShield subnet-feed response.")

        updated = None
        records = []
        for line in body.splitlines():
            candidate = line.strip()
            if not candidate:
                continue
            if candidate.startswith("#"):
                if candidate[1:].strip().startswith("updated:"):
                    updated = candidate.split("updated:", 1)[1].strip()
                    try:
                        datetime.fromisoformat(updated)
                    except ValueError as exc:
                        raise ValueError("Invalid DShield feed timestamp.") from exc
                continue
            if len(records) >= self.maximum_entries:
                raise RuntimeError("DShield subnet feed exceeded the safe entry limit.")
            fields = candidate.split("\t")
            if len(fields) != 7:
                raise ValueError("Unexpected DShield subnet-feed row.")
            try:
                network = ipaddress.ip_network(f"{fields[0]}/{fields[2]}", strict=True)
                end = ipaddress.ip_address(fields[1])
                reports = int(fields[3])
            except ValueError as exc:
                raise ValueError("Invalid DShield subnet-feed row.") from exc
            if (
                network.version != 4
                or network.prefixlen != 24
                or not network.network_address.is_global
                or end != network.broadcast_address
                or reports < 0
                or reports > 2_147_483_647
            ):
                raise ValueError("Invalid DShield subnet-feed range or report count.")
            records.append((network, reports, fields[4][:200], fields[5][:20]))

        if not records or updated is None:
            raise RuntimeError("DShield subnet feed is empty or lacks its timestamp.")
        matches = [
            {
                "cidr": str(network),
                "reporting_targets": reports,
                "network_name": name,
                "country": country,
            }
            for network, reports, name, country in records
            if target.version == network.version and target in network
        ]
        return [
            _json_item(
                source_type="threat_intelligence",
                locator=self.feed_url,
                kind=self.name,
                title=f"DShield subnet status for {target}",
                data={
                    "ip": str(target),
                    "listed": bool(matches),
                    "matches": matches,
                    "entries_checked": len(records),
                    "feed_updated_at": updated,
                    "match_basis": "subnet_membership",
                    "scope": "Top attacking /24 subnets over the last three days; "
                    "membership does not attribute attacks to an individual IP.",
                    "attribution": "DShield.org; some rights reserved.",
                    "license_url": "https://creativecommons.org/licenses/by-nc-sa/2.5/",
                },
                provider=self.provider,
            )
        ]
