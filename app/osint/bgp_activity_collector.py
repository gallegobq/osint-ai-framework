import math
from datetime import datetime, timedelta, timezone

from app.osint.contracts import CollectedItem, Collector
from app.osint.http import SafeHttpClient
from app.osint.passive_collectors import _json_item
from app.osint.routing_history_collector import _timestamp
from app.osint.targets import normalize_asn


class AsnBgpActivityCollector(Collector):
    name = "asn_ripestat_bgp_activity"
    description = "Retrieves 24 hours of observed ASN BGP announcement counts from RIS."
    target_types = frozenset({"asn"})
    query_field = "asn"
    provider = "RIPE NCC Routing Information Service"
    reference_url = "https://data.stat.ripe.net/docs/data-api/api-endpoints/bgp-update-activity"
    endpoint = "https://stat.ripe.net/data/bgp-update-activity/data.json"
    module_family = "routing_activity"
    capability_id = "routing_activity:ripe-ris-asn-announcements"
    maximum_samples = 24

    def __init__(self, client: SafeHttpClient | None = None):
        self.client = client or SafeHttpClient()

    def validate_query(self, query: dict) -> dict:
        return {"asn": normalize_asn(query.get("asn"))}

    def collect(self, query: dict) -> list[CollectedItem]:
        asn = self.validate_query(query)["asn"]
        payload = self.client.get_json(
            self.endpoint,
            params={"resource": asn, "preferred_version": "1.5", "num_hours": 24,
                    "max_samples": self.maximum_samples, "min_sampling_period": 3600,
                    "hide_empty_samples": "false", "sourceapp": "osint-ai-framework"},
            allowed_hosts={"stat.ripe.net"},
        )
        if (not isinstance(payload, dict) or payload.get("status") != "ok"
                or payload.get("version") != "1.5"):
            raise ValueError("Unexpected RIPEstat BGP-activity response.")
        data = payload.get("data")
        if (not isinstance(data, dict) or data.get("resource") not in (asn, asn[2:])
                or data.get("resource_type") != "asn"):
            raise ValueError("RIPEstat BGP-activity resource mismatch.")
        start, end = _timestamp(data.get("query_starttime")), _timestamp(data.get("query_endtime"))
        if not start < end <= datetime.now(timezone.utc) or end - start > timedelta(hours=24):
            raise ValueError("Invalid RIPEstat BGP-activity window.")
        period = data.get("sampling_period")
        if (isinstance(period, bool) or not isinstance(period, (int, float))
                or not math.isfinite(period) or not 3600 <= period <= 86400):
            raise ValueError("Invalid RIPEstat BGP-activity sampling period.")
        rows = data.get("updates")
        if not isinstance(rows, list) or len(rows) > self.maximum_samples:
            raise ValueError("Invalid or oversized RIPEstat BGP-activity samples.")
        samples = []
        previous_end = start
        for row in rows:
            if not isinstance(row, dict):
                raise ValueError("Invalid RIPEstat BGP-activity sample.")
            sample_start = _timestamp(row.get("starttime"))
            sample_end = sample_start + timedelta(seconds=period)
            count = row.get("announcements")
            if (not previous_end <= sample_start < sample_end <= end
                    or (sample_start - start).total_seconds() % period != 0
                    or isinstance(count, bool) or not isinstance(count, int)
                    or not 0 <= count <= 2**63 - 1
                    or "withdrawals" not in row or row["withdrawals"] is not None):
                raise ValueError("Invalid RIPEstat BGP-activity chronology or counts.")
            previous_end = sample_end
            samples.append({"starttime": sample_start.astimezone(timezone.utc).isoformat(),
                            "announcements": count, "withdrawals": None})
        return [_json_item(
            source_type="routing_activity", locator=self.endpoint, kind=self.name,
            title=f"RIS BGP announcement activity for {asn}", provider=self.provider,
            data={
                "asn": asn, "samples": samples, "records_checked": len(rows),
                "query_starttime": start.astimezone(timezone.utc).isoformat(),
                "query_endtime": end.astimezone(timezone.utc).isoformat(),
                "sampling_period_seconds": period, "requested_window_hours": 24,
                "sample_limit": self.maximum_samples,
                "sampled_announcements": sum(row["announcements"] for row in samples),
                "withdrawals_available": False, "sampled_withdrawals": None,
                "complete_sample_coverage": len(samples) * period == (end - start).total_seconds(),
                "scope": "Aggregated RIS observations, not unique routes or network-wide "
                "events. The provider window can lag current time. Missing samples are "
                "not inferred as zero. ASN withdrawals are unavailable, never zero. "
                "Announcement volume alone does not prove an outage, hijack, malicious "
                "activity, ownership or route stability. No raw update stream or target contact.",
            },
        )]
