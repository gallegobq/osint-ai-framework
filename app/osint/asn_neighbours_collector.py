from datetime import datetime, timezone

from app.osint.contracts import CollectedItem, Collector, DiscoveredTarget
from app.osint.http import SafeHttpClient
from app.osint.passive_collectors import _json_item
from app.osint.routing_history_collector import _timestamp
from app.osint.targets import normalize_asn


class AsnNeighboursCollector(Collector):
    name = "asn_ripestat_neighbours"
    description = "Retrieves observed ASN path neighbours and RIS uncertainty flags."
    target_types = frozenset({"asn"})
    query_field = "asn"
    emitted_target_types = frozenset({"asn"})
    provider = "RIPE NCC Routing Information Service"
    reference_url = "https://data.stat.ripe.net/docs/data-api/api-endpoints/asn-neighbours"
    endpoint = "https://stat.ripe.net/data/asn-neighbours/data.json"
    module_family = "routing_topology"
    capability_id = "routing_topology:ripe-ris-asn-neighbours"
    maximum_records = 10_000
    maximum_results = 200
    maximum_discoveries = 25

    def __init__(self, client: SafeHttpClient | None = None):
        self.client = client or SafeHttpClient()

    def validate_query(self, query: dict) -> dict:
        return {"asn": normalize_asn(query.get("asn"))}

    def collect(self, query: dict) -> list[CollectedItem]:
        asn = self.validate_query(query)["asn"]
        payload = self.client.get_json(
            self.endpoint,
            params={"resource": asn, "preferred_version": "3.2",
                    "sourceapp": "osint-ai-framework"},
            allowed_hosts={"stat.ripe.net"},
        )
        if (
            not isinstance(payload, dict) or payload.get("status") != "ok"
            or payload.get("version") != "3.2"
        ):
            raise ValueError("Unexpected RIPEstat ASN-neighbours response.")
        data = payload.get("data")
        if (
            not isinstance(data, dict)
            or str(data.get("resource")) not in {asn, asn[2:]}
        ):
            raise ValueError("RIPEstat ASN-neighbours resource mismatch.")
        start = _timestamp(data.get("query_starttime"))
        end = _timestamp(data.get("query_endtime"))
        if not start <= end <= datetime.now(timezone.utc):
            raise ValueError("Invalid RIPEstat ASN-neighbours observation window.")
        records = data.get("neighbours")
        if not isinstance(records, list) or len(records) > self.maximum_records:
            raise ValueError("Invalid or oversized RIPEstat neighbour list.")
        parsed = []
        seen = set()
        positions = {"left": 0, "right": 0, "uncertain": 0}
        for record in records:
            if not isinstance(record, dict):
                raise ValueError("Invalid RIPEstat neighbour record.")
            neighbour = record.get("asn")
            position = record.get("type")
            counts = [record.get(field) for field in ("power", "v4_peers", "v6_peers")]
            if (
                not isinstance(neighbour, int) or isinstance(neighbour, bool)
                or not 1 <= neighbour <= 4_294_967_295
                or not isinstance(position, str) or position not in positions
                or any(not isinstance(value, int) or isinstance(value, bool)
                       or not 0 <= value <= 9_223_372_036_854_775_807 for value in counts)
            ):
                raise ValueError("Invalid RIPEstat neighbour identity, position or counts.")
            seen.add((neighbour, position))
            positions[position] += 1
            parsed.append({
                "asn": f"AS{neighbour}", "position": position,
                "path_count": counts[0], "v4_route_peer_count": counts[1],
                "v6_route_peer_count": counts[2],
            })
        parsed.sort(key=lambda row: (
            row["position"] == "uncertain", -row["path_count"], row["asn"], row["position"],
        ))
        selected = parsed[:self.maximum_results]
        discoveries = []
        discovered = set()
        for row in selected:
            if row["position"] != "uncertain" and row["asn"] != asn and row["asn"] not in discovered:
                if len(discoveries) >= self.maximum_discoveries:
                    break
                discovered.add(row["asn"])
                discoveries.append(DiscoveredTarget("asn", row["asn"], "observed_bgp_neighbour"))
        return [_json_item(
            source_type="routing_topology", locator=self.endpoint, kind=self.name,
            title=f"RIS ASN path neighbours for {asn}", provider=self.provider,
            discoveries=tuple(discoveries),
            data={
                "asn": asn, "neighbours": selected,
                "records_checked": len(records), "unique_asns": len({row[0] for row in seen}),
                "position_record_counts": positions,
                "repeated_asn_position_records": len(records) - len(seen),
                "truncated": len(selected) < len(parsed),
                "omitted_records": len(parsed) - len(selected),
                "query_starttime": start.isoformat(), "query_endtime": end.isoformat(),
                "scope": "Observed AS-path positions, not commercial upstream/downstream "
                "relationships or a complete topology. Uncertain RIS peer artefacts are "
                "retained as such and never emitted as discovery targets. Repeated "
                "ASN/position observations are preserved, not summed into unique edges.",
            },
        )]
