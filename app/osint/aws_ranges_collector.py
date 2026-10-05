import ipaddress
from datetime import datetime

from app.osint.contracts import CollectedItem
from app.osint.http import SafeHttpClient
from app.osint.network_range_collectors import (
    PublicNetworkRangeCollector,
    _parse_public_network,
)


class AwsRangeCollector(PublicNetworkRangeCollector):
    name = "ip_aws_ranges"
    description = "Checks public IP membership in AWS's published service ranges."
    provider = "Amazon Web Services"
    reference_url = "https://docs.aws.amazon.com/vpc/latest/userguide/aws-ip-ranges.html"
    capability_id = "network_range:aws"
    endpoint = "https://ip-ranges.amazonaws.com/ip-ranges.json"
    maximum_records = 30_000
    maximum_matches = 128
    maximum_response_bytes = 8_000_000

    def __init__(self, client: SafeHttpClient | None = None):
        self.client = client or SafeHttpClient(max_bytes=self.maximum_response_bytes)

    def collect(self, query: dict) -> list[CollectedItem]:
        ip = self.validate_query(query)["ip"]
        address = ipaddress.ip_address(ip)
        payload = self.client.get_json(
            self.endpoint,
            allowed_hosts={"ip-ranges.amazonaws.com"},
        )
        if not isinstance(payload, dict):
            raise ValueError("Unexpected AWS range response.")
        token = payload.get("syncToken")
        created = payload.get("createDate")
        if (
            not isinstance(token, str)
            or not token.isascii()
            or not token.isdigit()
            or not 1 <= len(token) <= 20
            or not isinstance(created, str)
            or len(created) != 19
        ):
            raise ValueError("Invalid AWS publication metadata.")
        try:
            datetime.strptime(created, "%Y-%m-%d-%H-%M-%S")
        except ValueError as exc:
            raise ValueError("Invalid AWS publication date.") from exc

        groups = [(4, "prefixes", "ip_prefix"), (6, "ipv6_prefixes", "ipv6_prefix")]
        total = 0
        matches = set()
        checked = 0
        for version, key, prefix_key in groups:
            records = payload.get(key)
            if not isinstance(records, list) or len(records) < 10:
                raise ValueError("Incomplete AWS range response.")
            total += len(records)
            if total > self.maximum_records:
                raise RuntimeError("AWS range feed exceeded the safe record limit.")
            for record in records:
                if not isinstance(record, dict):
                    raise ValueError("Invalid AWS range record.")
                network = _parse_public_network(record.get(prefix_key))
                metadata = [record.get(field) for field in (
                    "service", "region", "network_border_group",
                )]
                if network.version != version or any(
                    not isinstance(value, str) or not value.strip() or len(value) > 100
                    for value in metadata
                ):
                    raise ValueError("Invalid AWS range metadata or address family.")
                if version == address.version:
                    checked += 1
                    if address in network:
                        matches.add((network.with_prefixlen, *metadata))
                        if len(matches) > self.maximum_matches:
                            raise RuntimeError("AWS range feed exceeded the safe match limit.")

        return [self._item(
            ip=ip,
            locator=self.endpoint,
            data={
                "listed": bool(matches),
                "matched_entries": [
                    {"prefix": prefix, "service": service, "region": region,
                     "network_border_group": border}
                    for prefix, service, region, border in sorted(matches)
                ],
                "address_family": f"IPv{address.version}",
                "records_checked": total,
                "prefixes_checked": checked,
                "feed_sync_token": token,
                "feed_created_at": created,
                "scope": "Published AWS ranges only; BYOIP and some services are absent. "
                "Overlapping service labels do not identify the actual workload.",
            },
        )]
