import math
from datetime import datetime, timezone

from app.osint.contracts import CollectedItem, Collector
from app.osint.http import SafeHttpClient
from app.osint.passive_collectors import _json_item
from app.osint.routing_history_collector import _timestamp
from app.osint.targets import normalize_asn


def _metrics(value: object, count: int) -> dict:
    if not isinstance(value, dict):
        raise ValueError("Invalid RIPEstat AS-path metrics.")
    minimum, maximum, total = (value.get(key) for key in ("min", "max", "sum"))
    average = value.get("avg")
    if (
        any(not isinstance(number, int) or isinstance(number, bool)
            or not 0 <= number <= 9_223_372_036_854_775_807
            for number in (minimum, maximum, total))
        or not 0 <= minimum <= maximum <= 1_024
        or isinstance(average, bool) or not isinstance(average, (int, float))
        or not minimum <= average <= maximum or not math.isfinite(average)
        or not minimum * count <= total <= maximum * count
    ):
        raise ValueError("Invalid or inconsistent RIPEstat AS-path metrics.")
    return {"min": minimum, "max": maximum, "sum": total, "avg": average}


class AsPathLengthCollector(Collector):
    name = "asn_ripestat_path_length"
    description = "Retrieves RIS AS-path lengths with and without AS prepending."
    target_types = frozenset({"asn"})
    query_field = "asn"
    provider = "RIPE NCC Routing Information Service"
    reference_url = "https://data.stat.ripe.net/docs/data-api/api-endpoints/as-path-length"
    endpoint = "https://stat.ripe.net/data/as-path-length/data.json"
    module_family = "routing_metrics"
    capability_id = "routing_metrics:ripe-ris-as-path-length"
    maximum_collectors = 128

    def __init__(self, client: SafeHttpClient | None = None):
        self.client = client or SafeHttpClient()

    def validate_query(self, query: dict) -> dict:
        return {"asn": normalize_asn(query.get("asn"))}

    def collect(self, query: dict) -> list[CollectedItem]:
        asn = self.validate_query(query)["asn"]
        payload = self.client.get_json(
            self.endpoint,
            params={"resource": asn, "preferred_version": "2.1", "sort_by": "number",
                    "sourceapp": "osint-ai-framework"},
            allowed_hosts={"stat.ripe.net"},
        )
        if (
            not isinstance(payload, dict) or payload.get("status") != "ok"
            or payload.get("version") != "2.1"
        ):
            raise ValueError("Unexpected RIPEstat AS-path-length response.")
        data = payload.get("data")
        if not isinstance(data, dict) or str(data.get("resource")) not in {asn, asn[2:]}:
            raise ValueError("RIPEstat AS-path-length resource mismatch.")
        observed = _timestamp(data.get("query_time"))
        if observed > datetime.now(timezone.utc):
            raise ValueError("Invalid RIPEstat AS-path-length observation time.")
        stats = data.get("stats")
        if not isinstance(stats, list) or len(stats) > self.maximum_collectors:
            raise ValueError("Invalid or oversized RIPEstat collector metrics.")
        records = []
        seen = set()
        for row in stats:
            if not isinstance(row, dict):
                raise ValueError("Invalid RIPEstat collector record.")
            number, count, location = (row.get(key) for key in ("number", "count", "location"))
            if (
                not isinstance(number, int) or isinstance(number, bool)
                or not 0 <= number <= 65_535 or number in seen
                or not isinstance(count, int) or isinstance(count, bool)
                or not 1 <= count <= 2_147_483_647
                or not isinstance(location, str) or not location.strip() or len(location) > 300
            ):
                raise ValueError("Invalid RIPEstat collector identity or route count.")
            stripped = _metrics(row.get("stripped"), count)
            unstripped = _metrics(row.get("unstripped"), count)
            if any(unstripped[key] < stripped[key] for key in ("min", "max", "sum")):
                raise ValueError("Inconsistent RIPEstat AS-prepending metrics.")
            seen.add(number)
            records.append({
                "rrc_id": number, "route_count": count, "collector_location": location,
                "excluding_prepending": stripped, "including_prepending": unstripped,
            })
        records.sort(key=lambda row: row["rrc_id"])
        return [_json_item(
            source_type="routing_metrics", locator=self.endpoint, kind=self.name,
            title=f"RIS AS-path lengths for {asn}", provider=self.provider,
            data={
                "asn": asn, "query_time": observed.isoformat(), "collectors": records,
                "observed": bool(records), "collectors_checked": len(records),
                "scope": "RIS AS-path entries excluding the RIS peer AS, not physical hops, "
                "latency, malicious activity or exhaustive Internet reachability. "
                "Locations describe route collectors, not the target ASN.",
            },
        )]
