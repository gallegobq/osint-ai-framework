import ipaddress
import math
from datetime import datetime, timedelta, timezone

from app.osint.contracts import CollectedItem, Collector
from app.osint.http import SafeHttpClient
from app.osint.passive_collectors import _json_item
from app.osint.targets import normalize_ip


def _timestamp(value: object) -> datetime:
    if not isinstance(value, str) or not 10 <= len(value) <= 32:
        raise ValueError("Invalid RIPEstat routing timestamp.")
    try:
        parsed = datetime.fromisoformat(value)
    except ValueError as exc:
        raise ValueError("Invalid RIPEstat routing timestamp.") from exc
    return parsed.replace(tzinfo=timezone.utc) if parsed.tzinfo is None else parsed


class IpRoutingHistoryCollector(Collector):
    name = "ip_ripestat_routing_history"
    description = "Retrieves seven days of observed prefix-origin BGP timelines from RIS."
    target_types = frozenset({"ip"})
    query_field = "ip"
    provider = "RIPE NCC Routing Information Service"
    reference_url = "https://data.stat.ripe.net/docs/data-api/api-endpoints/routing-history"
    endpoint = "https://stat.ripe.net/data/routing-history/data.json"
    module_family = "routing_history"
    capability_id = "routing_history:ripe-ris-ip"
    maximum_routes = 100
    maximum_timelines = 1_000

    def __init__(self, client: SafeHttpClient | None = None):
        self.client = client or SafeHttpClient()

    def validate_query(self, query: dict) -> dict:
        return {"ip": normalize_ip(query.get("ip"))}

    def collect(self, query: dict) -> list[CollectedItem]:
        ip = self.validate_query(query)["ip"]
        address = ipaddress.ip_address(ip)
        end = datetime.now(timezone.utc).replace(microsecond=0)
        start = end - timedelta(days=7)
        payload = self.client.get_json(
            self.endpoint,
            params={
                "resource": ip,
                "starttime": start.strftime("%Y-%m-%dT%H:%M:%S"),
                "endtime": end.strftime("%Y-%m-%dT%H:%M:%S"),
                "max_rows": self.maximum_routes,
                "min_peers": 10,
                "include_first_hop": "false",
                "sourceapp": "osint-ai-framework",
            },
            allowed_hosts={"stat.ripe.net"},
        )
        if not isinstance(payload, dict) or payload.get("status") != "ok":
            raise ValueError("Unexpected RIPEstat routing-history response.")
        data = payload.get("data")
        if not isinstance(data, dict) or data.get("resource") != ip:
            raise ValueError("RIPEstat routing-history resource mismatch.")
        query_start = _timestamp(data.get("query_starttime"))
        query_end = _timestamp(data.get("query_endtime"))
        if not start <= query_start < query_end <= end:
            raise ValueError("RIPEstat returned an invalid routing-history window.")
        origins = data.get("by_origin")
        if not isinstance(origins, list) or len(origins) > self.maximum_routes:
            raise ValueError("Invalid RIPEstat routing-history origins.")
        routes = []
        timeline_count = 0
        for origin in origins:
            if not isinstance(origin, dict):
                raise ValueError("Invalid RIPEstat routing-history origin.")
            asn = origin.get("origin")
            prefixes = origin.get("prefixes")
            if (
                not isinstance(asn, str) or not asn.isascii() or not asn.isdigit()
                or not 1 <= len(asn) <= 10 or not 1 <= int(asn) <= 4_294_967_295
                or not isinstance(prefixes, list) or not prefixes
                or len(routes) + len(prefixes) > self.maximum_routes
            ):
                raise ValueError("Invalid or oversized RIPEstat routing-history routes.")
            for prefix in prefixes:
                if not isinstance(prefix, dict) or not isinstance(prefix.get("prefix"), str):
                    raise ValueError("Invalid RIPEstat routing-history prefix.")
                network = ipaddress.ip_network(prefix["prefix"], strict=True)
                if network.version != address.version or address not in network:
                    raise ValueError("RIPEstat returned a prefix unrelated to the target.")
                timelines = prefix.get("timelines")
                if not isinstance(timelines, list) or not timelines:
                    raise ValueError("Invalid RIPEstat routing-history timelines.")
                timeline_count += len(timelines)
                if timeline_count > self.maximum_timelines:
                    raise RuntimeError("RIPEstat routing history exceeded the timeline limit.")
                periods = []
                for timeline in timelines:
                    if not isinstance(timeline, dict):
                        raise ValueError("Invalid RIPEstat routing-history period.")
                    period_start = _timestamp(timeline.get("starttime"))
                    period_end = _timestamp(timeline.get("endtime"))
                    peers = timeline.get("full_peers_seeing")
                    if (
                        not query_start <= period_start <= period_end <= query_end
                        or isinstance(peers, bool) or not isinstance(peers, (int, float))
                        or not math.isfinite(peers) or not 0 <= peers <= 1_000_000
                    ):
                        raise ValueError("Invalid RIPEstat routing period or visibility.")
                    periods.append({
                        "starttime": period_start.isoformat(),
                        "endtime": period_end.isoformat(),
                        "full_peers_seeing": peers,
                    })
                routes.append({
                    "origin_asn": f"AS{int(asn)}", "prefix": network.with_prefixlen,
                    "timelines": periods,
                })
        return [_json_item(
            source_type="routing_history", locator=self.endpoint, kind=self.name,
            title=f"RIS routing history for {ip}", provider=self.provider,
            data={
                "ip": ip, "observed": bool(routes), "routes": routes,
                "query_starttime": query_start.isoformat(),
                "query_endtime": query_end.isoformat(),
                "requested_window_days": 7, "route_limit_requested": self.maximum_routes,
                "scope": "RIS observations only; low-visibility routes are excluded. "
                "The provider's row limit is soft; this is not exhaustive routing history "
                "or evidence of ownership, malicious activity or a hijack.",
            },
        )]
