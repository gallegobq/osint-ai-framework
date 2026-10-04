import ipaddress

from app.osint.contracts import CollectedItem, Collector
from app.osint.http import SafeHttpClient
from app.osint.passive_collectors import _json_item
from app.osint.targets import normalize_ip


MAX_FEED_NETWORKS = 10_000
IpNetwork = ipaddress.IPv4Network | ipaddress.IPv6Network


def _parse_networks(
    values: object,
    *,
    version: int,
    minimum: int = 1,
) -> list[IpNetwork]:
    if (
        not isinstance(values, list)
        or len(values) > MAX_FEED_NETWORKS
        or any(not isinstance(value, str) for value in values)
    ):
        raise ValueError("Unexpected public network-range response.")
    networks: list[IpNetwork] = []
    seen: set[str] = set()
    for value in values:
        try:
            network = ipaddress.ip_network(value.strip(), strict=True)
        except ValueError as exc:
            raise ValueError("Unexpected public network-range response.") from exc
        if network.version != version or not network.is_global:
            raise ValueError("Unexpected public network-range response.")
        canonical = network.with_prefixlen
        if canonical not in seen:
            seen.add(canonical)
            networks.append(network)
    if len(networks) < minimum:
        raise RuntimeError("Public network-range feed did not contain enough entries.")
    return networks


def _best_match(ip: str, networks: list[IpNetwork]) -> IpNetwork | None:
    address = ipaddress.ip_address(ip)
    matches = [network for network in networks if address in network]
    return max(matches, key=lambda network: network.prefixlen, default=None)


class PublicNetworkRangeCollector(Collector):
    target_types = frozenset({"ip"})
    query_field = "ip"
    profiles = frozenset({"footprint", "investigate"})
    module_family = "network_attribution"

    def validate_query(self, query: dict) -> dict:
        return {"ip": normalize_ip(query.get("ip"))}

    def _item(
        self,
        *,
        ip: str,
        locator: str,
        data: dict[str, object],
    ) -> CollectedItem:
        return _json_item(
            source_type="network_attribution",
            locator=locator,
            kind=self.name,
            title=f"{self.provider} network-range attribution for {ip}",
            data={"ip": ip, **data},
            provider=str(self.provider),
        )


class CloudflareRangeCollector(PublicNetworkRangeCollector):
    name = "ip_cloudflare_ranges"
    description = "Checks whether a public IP belongs to Cloudflare's published ranges."
    provider = "Cloudflare"
    reference_url = "https://www.cloudflare.com/ips/"
    capability_id = "network_range:cloudflare"

    def __init__(self, client: SafeHttpClient | None = None):
        self.client = client or SafeHttpClient()

    def collect(self, query: dict) -> list[CollectedItem]:
        ip = self.validate_query(query)["ip"]
        version = ipaddress.ip_address(ip).version
        endpoint = f"https://www.cloudflare.com/ips-v{version}"
        body = self.client.get_text(
            endpoint,
            headers={"Accept": "text/plain"},
            allowed_hosts={"www.cloudflare.com"},
        )
        if not isinstance(body, str):
            raise ValueError("Unexpected Cloudflare network-range response.")
        values = [
            line.strip()
            for line in body.splitlines()
            if line.strip() and not line.lstrip().startswith("#")
        ]
        networks = _parse_networks(values, version=version, minimum=5)
        match = _best_match(ip, networks)
        return [
            self._item(
                ip=ip,
                locator=endpoint,
                data={
                    "listed": match is not None,
                    "matched_prefix": match.with_prefixlen if match else None,
                    "address_family": f"IPv{version}",
                    "prefixes_checked": len(networks),
                },
            )
        ]


class FastlyRangeCollector(PublicNetworkRangeCollector):
    name = "ip_fastly_ranges"
    description = "Checks whether a public IP belongs to Fastly's published ranges."
    provider = "Fastly"
    reference_url = "https://api.fastly.com/public-ip-list"
    capability_id = "network_range:fastly"
    endpoint = "https://api.fastly.com/public-ip-list"

    def __init__(self, client: SafeHttpClient | None = None):
        self.client = client or SafeHttpClient()

    def collect(self, query: dict) -> list[CollectedItem]:
        ip = self.validate_query(query)["ip"]
        payload = self.client.get_json(
            self.endpoint,
            allowed_hosts={"api.fastly.com"},
        )
        if not isinstance(payload, dict):
            raise ValueError("Unexpected Fastly network-range response.")
        ipv4 = _parse_networks(payload.get("addresses"), version=4)
        ipv6 = _parse_networks(payload.get("ipv6_addresses"), version=6)
        version = ipaddress.ip_address(ip).version
        networks = ipv4 if version == 4 else ipv6
        match = _best_match(ip, networks)
        return [
            self._item(
                ip=ip,
                locator=self.endpoint,
                data={
                    "listed": match is not None,
                    "matched_prefix": match.with_prefixlen if match else None,
                    "address_family": f"IPv{version}",
                    "prefixes_checked": len(networks),
                },
            )
        ]


class GoogleCloudRangeCollector(PublicNetworkRangeCollector):
    name = "ip_google_cloud_ranges"
    description = "Checks whether a public IP belongs to Google Cloud's published ranges."
    provider = "Google Cloud"
    reference_url = "https://www.gstatic.com/ipranges/cloud.json"
    capability_id = "network_range:google-cloud"
    endpoint = "https://www.gstatic.com/ipranges/cloud.json"

    def __init__(self, client: SafeHttpClient | None = None):
        self.client = client or SafeHttpClient()

    def collect(self, query: dict) -> list[CollectedItem]:
        ip = self.validate_query(query)["ip"]
        payload = self.client.get_json(
            self.endpoint,
            allowed_hosts={"www.gstatic.com"},
        )
        if not isinstance(payload, dict):
            raise ValueError("Unexpected Google Cloud network-range response.")
        sync_token = payload.get("syncToken")
        creation_time = payload.get("creationTime")
        prefixes = payload.get("prefixes")
        if (
            not isinstance(sync_token, str)
            or not sync_token
            or not isinstance(creation_time, str)
            or not creation_time
            or not isinstance(prefixes, list)
            or not 10 <= len(prefixes) <= MAX_FEED_NETWORKS
            or any(not isinstance(item, dict) for item in prefixes)
        ):
            raise ValueError("Unexpected Google Cloud network-range response.")

        parsed: list[tuple[IpNetwork, dict[str, str]]] = []
        seen: set[str] = set()
        for item in prefixes:
            available = [
                key for key in ("ipv4Prefix", "ipv6Prefix") if key in item
            ]
            service = item.get("service")
            scope = item.get("scope")
            if (
                len(available) != 1
                or not isinstance(item[available[0]], str)
                or service != "Google Cloud"
                or not isinstance(scope, str)
                or not scope
            ):
                raise ValueError("Unexpected Google Cloud network-range response.")
            try:
                network = ipaddress.ip_network(
                    item[available[0]].strip(),
                    strict=True,
                )
            except ValueError as exc:
                raise ValueError(
                    "Unexpected Google Cloud network-range response."
                ) from exc
            if not network.is_global or network.with_prefixlen in seen:
                raise ValueError("Unexpected Google Cloud network-range response.")
            seen.add(network.with_prefixlen)
            parsed.append(
                (
                    network,
                    {
                        "prefix": network.with_prefixlen,
                        "service": service,
                        "scope": scope,
                    },
                )
            )

        address = ipaddress.ip_address(ip)
        matches = [
            (network, metadata)
            for network, metadata in parsed
            if network.version == address.version and address in network
        ]
        matched = max(
            matches,
            key=lambda value: value[0].prefixlen,
            default=None,
        )
        return [
            self._item(
                ip=ip,
                locator=self.endpoint,
                data={
                    "listed": matched is not None,
                    "matched_entry": matched[1] if matched else None,
                    "address_family": f"IPv{address.version}",
                    "prefixes_checked": sum(
                        network.version == address.version
                        for network, _metadata in parsed
                    ),
                    "feed_sync_token": sync_token,
                    "feed_created_at": creation_time,
                },
            )
        ]


def public_network_range_collectors(
    client: SafeHttpClient | None = None,
) -> list[Collector]:
    return [
        CloudflareRangeCollector(client),
        FastlyRangeCollector(client),
        GoogleCloudRangeCollector(client),
    ]
