import csv
import ipaddress

from app.osint.contracts import CollectedItem, Collector
from app.osint.http import SafeHttpClient
from app.osint.passive_collectors import _json_item
from app.osint.targets import normalize_ip


MAX_FEED_NETWORKS = 10_000
IpNetwork = ipaddress.IPv4Network | ipaddress.IPv6Network


def _parse_public_network(value: object) -> IpNetwork:
    if not isinstance(value, str):
        raise ValueError("Unexpected public network-range response.")
    try:
        network = ipaddress.ip_network(value.strip(), strict=True)
    except ValueError as exc:
        raise ValueError("Unexpected public network-range response.") from exc
    if not network.is_global:
        raise ValueError("Unexpected public network-range response.")
    return network


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
        network = _parse_public_network(value)
        if network.version != version:
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


class GitHubRangeCollector(PublicNetworkRangeCollector):
    name = "ip_github_ranges"
    description = "Checks whether a public IP belongs to GitHub's published ranges."
    provider = "GitHub"
    reference_url = (
        "https://docs.github.com/en/authentication/keeping-your-account-and-data-secure/"
        "about-githubs-ip-addresses"
    )
    capability_id = "network_range:github"
    endpoint = "https://api.github.com/meta"
    range_keys = (
        "hooks",
        "web",
        "api",
        "git",
        "packages",
        "pages",
        "importer",
        "actions",
        "actions_macos",
        "dependabot",
        "codespaces",
        "copilot",
        "github_enterprise_importer",
    )
    required_range_keys = frozenset({"hooks", "web", "api", "git", "pages", "actions"})

    def __init__(self, client: SafeHttpClient | None = None):
        self.client = client or SafeHttpClient()

    def collect(self, query: dict) -> list[CollectedItem]:
        ip = self.validate_query(query)["ip"]
        payload = self.client.get_json(
            self.endpoint,
            headers={"Accept": "application/vnd.github+json"},
            allowed_hosts={"api.github.com"},
        )
        if not isinstance(payload, dict) or not self.required_range_keys <= payload.keys():
            raise ValueError("Unexpected GitHub network-range response.")

        entries: dict[str, tuple[IpNetwork, set[str]]] = {}
        raw_count = 0
        categories_checked = 0
        for category in self.range_keys:
            values = payload.get(category)
            if values is None:
                continue
            if not isinstance(values, list) or any(
                not isinstance(value, str) for value in values
            ):
                raise ValueError("Unexpected GitHub network-range response.")
            raw_count += len(values)
            categories_checked += 1
            if raw_count > MAX_FEED_NETWORKS:
                raise ValueError("Unexpected GitHub network-range response.")
            for value in values:
                network = _parse_public_network(value)
                canonical = network.with_prefixlen
                if canonical not in entries:
                    entries[canonical] = (network, set())
                entries[canonical][1].add(category)
        if raw_count < 10 or not entries:
            raise RuntimeError("GitHub network-range feed did not contain enough entries.")

        address = ipaddress.ip_address(ip)
        matches = [
            value
            for value in entries.values()
            if value[0].version == address.version and address in value[0]
        ]
        matched = max(matches, key=lambda value: value[0].prefixlen, default=None)
        return [
            self._item(
                ip=ip,
                locator=self.endpoint,
                data={
                    "listed": matched is not None,
                    "matched_entry": {
                        "prefix": matched[0].with_prefixlen,
                        "services": sorted(matched[1]),
                    }
                    if matched
                    else None,
                    "address_family": f"IPv{address.version}",
                    "prefixes_checked": sum(
                        network.version == address.version
                        for network, _services in entries.values()
                    ),
                    "categories_checked": categories_checked,
                },
            )
        ]


class OracleCloudRangeCollector(PublicNetworkRangeCollector):
    name = "ip_oracle_cloud_ranges"
    description = "Checks whether a public IP belongs to Oracle Cloud's published ranges."
    provider = "Oracle Cloud Infrastructure"
    reference_url = (
        "https://docs.oracle.com/en-us/iaas/Content/General/Concepts/addressranges.htm"
    )
    capability_id = "network_range:oracle-cloud"
    endpoint = "https://docs.oracle.com/en-us/iaas/tools/public_ip_ranges.json"

    def __init__(self, client: SafeHttpClient | None = None):
        self.client = client or SafeHttpClient()

    def collect(self, query: dict) -> list[CollectedItem]:
        ip = self.validate_query(query)["ip"]
        payload = self.client.get_json(
            self.endpoint,
            allowed_hosts={"docs.oracle.com"},
        )
        if not isinstance(payload, dict):
            raise ValueError("Unexpected Oracle Cloud network-range response.")
        updated_at = payload.get("last_updated_timestamp")
        regions = payload.get("regions")
        if (
            not isinstance(updated_at, str)
            or not updated_at
            or not isinstance(regions, list)
            or not 1 <= len(regions) <= 500
            or any(not isinstance(region, dict) for region in regions)
        ):
            raise ValueError("Unexpected Oracle Cloud network-range response.")

        parsed: list[tuple[IpNetwork, dict[str, object]]] = []
        seen: set[str] = set()
        for region_entry in regions:
            region = region_entry.get("region")
            ipv4_entries = region_entry.get("cidrs")
            ipv6_entries = region_entry.get("ipv6_cidrs")
            if (
                not isinstance(region, str)
                or not region
                or not isinstance(ipv4_entries, list)
                or not isinstance(ipv6_entries, list)
            ):
                raise ValueError("Unexpected Oracle Cloud network-range response.")
            for entry in [*ipv4_entries, *ipv6_entries]:
                if not isinstance(entry, dict):
                    raise ValueError("Unexpected Oracle Cloud network-range response.")
                tags = entry.get("tags")
                if (
                    not isinstance(tags, list)
                    or not tags
                    or any(not isinstance(tag, str) or not tag for tag in tags)
                ):
                    raise ValueError("Unexpected Oracle Cloud network-range response.")
                network = _parse_public_network(entry.get("cidr"))
                canonical = network.with_prefixlen
                if canonical in seen:
                    raise ValueError("Unexpected Oracle Cloud network-range response.")
                seen.add(canonical)
                parsed.append(
                    (
                        network,
                        {
                            "prefix": canonical,
                            "region": region,
                            "tags": sorted(set(tags)),
                        },
                    )
                )
                if len(parsed) > MAX_FEED_NETWORKS:
                    raise ValueError("Unexpected Oracle Cloud network-range response.")
        if len(parsed) < 10:
            raise RuntimeError("Oracle Cloud network-range feed did not contain enough entries.")

        address = ipaddress.ip_address(ip)
        matches = [
            value
            for value in parsed
            if value[0].version == address.version and address in value[0]
        ]
        matched = max(matches, key=lambda value: value[0].prefixlen, default=None)
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
                    "feed_updated_at": updated_at,
                },
            )
        ]


class AtlassianRangeCollector(PublicNetworkRangeCollector):
    name = "ip_atlassian_ranges"
    description = "Checks whether a public IP belongs to Atlassian Cloud's published ranges."
    provider = "Atlassian Cloud"
    reference_url = (
        "https://support.atlassian.com/organization-administration/docs/"
        "ip-addresses-and-domains-for-atlassian-cloud-products/"
    )
    capability_id = "network_range:atlassian-cloud"
    endpoint = "https://ip-ranges.atlassian.com/"

    def __init__(self, client: SafeHttpClient | None = None):
        self.client = client or SafeHttpClient()

    def collect(self, query: dict) -> list[CollectedItem]:
        ip = self.validate_query(query)["ip"]
        payload = self.client.get_json(
            self.endpoint,
            allowed_hosts={"ip-ranges.atlassian.com"},
        )
        if not isinstance(payload, dict):
            raise ValueError("Unexpected Atlassian network-range response.")
        sync_token = payload.get("syncToken")
        creation_date = payload.get("creationDate")
        items = payload.get("items")
        if (
            not isinstance(sync_token, (str, int))
            or isinstance(sync_token, bool)
            or not str(sync_token)
            or not isinstance(creation_date, str)
            or not creation_date
            or not isinstance(items, list)
            or not 10 <= len(items) <= MAX_FEED_NETWORKS
            or any(not isinstance(item, dict) for item in items)
        ):
            raise ValueError("Unexpected Atlassian network-range response.")

        parsed: list[tuple[IpNetwork, dict[str, object]]] = []
        for item in items:
            product = item.get("product")
            direction = item.get("direction")
            perimeter = item.get("perimeter")
            region = item.get("region")
            lists = (product, direction, region)
            if (
                any(
                    not isinstance(values, list)
                    or not values
                    or any(
                        not isinstance(value, str) or not value for value in values
                    )
                    for values in lists
                )
                or not isinstance(perimeter, str)
                or not perimeter
            ):
                raise ValueError("Unexpected Atlassian network-range response.")
            network = _parse_public_network(item.get("cidr"))
            parsed.append(
                (
                    network,
                    {
                        "products": product,
                        "directions": direction,
                        "perimeter": perimeter,
                        "regions": region,
                    },
                )
            )

        address = ipaddress.ip_address(ip)
        matches = [
            value
            for value in parsed
            if value[0].version == address.version and address in value[0]
        ]
        best_prefix = max(
            (value[0].prefixlen for value in matches),
            default=None,
        )
        best = [value for value in matches if value[0].prefixlen == best_prefix]
        matched_entry = None
        if best:
            matched_entry = {
                "prefix": best[0][0].with_prefixlen,
                "products": sorted(
                    {value for _network, data in best for value in data["products"]}
                ),
                "directions": sorted(
                    {value for _network, data in best for value in data["directions"]}
                ),
                "perimeters": sorted(
                    {str(data["perimeter"]) for _network, data in best}
                ),
                "regions": sorted(
                    {value for _network, data in best for value in data["regions"]}
                ),
            }
        return [
            self._item(
                ip=ip,
                locator=self.endpoint,
                data={
                    "listed": matched_entry is not None,
                    "matched_entry": matched_entry,
                    "address_family": f"IPv{address.version}",
                    "prefixes_checked": len(
                        {
                            network.with_prefixlen
                            for network, _metadata in parsed
                            if network.version == address.version
                        }
                    ),
                    "feed_sync_token": str(sync_token),
                    "feed_created_at": creation_date,
                },
            )
        ]


class GoogleServicesRangeCollector(PublicNetworkRangeCollector):
    name = "ip_google_services_ranges"
    description = "Checks whether a public IP belongs to Google's published service ranges."
    provider = "Google"
    reference_url = "https://www.gstatic.com/ipranges/goog.json"
    capability_id = "network_range:google-services"
    endpoint = "https://www.gstatic.com/ipranges/goog.json"

    def __init__(self, client: SafeHttpClient | None = None):
        self.client = client or SafeHttpClient()

    def collect(self, query: dict) -> list[CollectedItem]:
        ip = self.validate_query(query)["ip"]
        payload = self.client.get_json(
            self.endpoint,
            allowed_hosts={"www.gstatic.com"},
        )
        if not isinstance(payload, dict):
            raise ValueError("Unexpected Google services network-range response.")
        sync_token = payload.get("syncToken")
        creation_time = payload.get("creationTime")
        prefixes = payload.get("prefixes")
        if (
            not isinstance(sync_token, (str, int))
            or isinstance(sync_token, bool)
            or not str(sync_token)
            or not isinstance(creation_time, str)
            or not creation_time
            or not isinstance(prefixes, list)
            or not 10 <= len(prefixes) <= MAX_FEED_NETWORKS
            or any(not isinstance(item, dict) for item in prefixes)
        ):
            raise ValueError("Unexpected Google services network-range response.")

        parsed: list[IpNetwork] = []
        seen: set[str] = set()
        for item in prefixes:
            available = [
                key for key in ("ipv4Prefix", "ipv6Prefix") if key in item
            ]
            if len(available) != 1:
                raise ValueError("Unexpected Google services network-range response.")
            network = _parse_public_network(item[available[0]])
            canonical = network.with_prefixlen
            if canonical in seen:
                raise ValueError("Unexpected Google services network-range response.")
            seen.add(canonical)
            parsed.append(network)

        address = ipaddress.ip_address(ip)
        matches = [
            network
            for network in parsed
            if network.version == address.version and address in network
        ]
        matched = max(matches, key=lambda network: network.prefixlen, default=None)
        return [
            self._item(
                ip=ip,
                locator=self.endpoint,
                data={
                    "listed": matched is not None,
                    "matched_prefix": matched.with_prefixlen if matched else None,
                    "address_family": f"IPv{address.version}",
                    "prefixes_checked": sum(
                        network.version == address.version for network in parsed
                    ),
                    "feed_sync_token": str(sync_token),
                    "feed_created_at": creation_time,
                },
            )
        ]


class DigitalOceanRangeCollector(PublicNetworkRangeCollector):
    name = "ip_digitalocean_ranges"
    description = "Checks whether a public IP belongs to DigitalOcean's geofeed ranges."
    provider = "DigitalOcean"
    reference_url = "https://www.digitalocean.com/geo/google.csv"
    capability_id = "network_range:digitalocean"
    endpoint = "https://www.digitalocean.com/geo/google.csv"

    def __init__(self, client: SafeHttpClient | None = None):
        self.client = client or SafeHttpClient()

    def collect(self, query: dict) -> list[CollectedItem]:
        ip = self.validate_query(query)["ip"]
        body = self.client.get_text(
            self.endpoint,
            headers={"Accept": "text/csv"},
            allowed_hosts={"www.digitalocean.com"},
        )
        if not isinstance(body, str):
            raise ValueError("Unexpected DigitalOcean network-range response.")
        rows = [
            row
            for row in csv.reader(body.splitlines())
            if row and any(value.strip() for value in row)
        ]
        if not 10 <= len(rows) <= MAX_FEED_NETWORKS:
            raise RuntimeError(
                "DigitalOcean network-range feed did not contain enough entries."
            )

        parsed: list[tuple[IpNetwork, dict[str, str | None]]] = []
        seen: set[str] = set()
        for row in rows:
            if len(row) != 5 or any(len(value) > 200 for value in row):
                raise ValueError("Unexpected DigitalOcean network-range response.")
            prefix, country, region, city, postal_code = (
                value.strip() for value in row
            )
            if len(country) != 2 or not country.isalpha():
                raise ValueError("Unexpected DigitalOcean network-range response.")
            network = _parse_public_network(prefix)
            canonical = network.with_prefixlen
            if canonical in seen:
                raise ValueError("Unexpected DigitalOcean network-range response.")
            seen.add(canonical)
            parsed.append(
                (
                    network,
                    {
                        "prefix": canonical,
                        "country_code": country.upper(),
                        "region_code": region or None,
                        "city": city or None,
                        "postal_code": postal_code or None,
                    },
                )
            )

        address = ipaddress.ip_address(ip)
        matches = [
            value
            for value in parsed
            if value[0].version == address.version and address in value[0]
        ]
        matched = max(matches, key=lambda value: value[0].prefixlen, default=None)
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
                },
            )
        ]


class Microsoft365RangeCollector(PublicNetworkRangeCollector):
    name = "ip_microsoft_365_ranges"
    description = "Checks whether a public IP belongs to Microsoft 365's endpoints."
    provider = "Microsoft 365"
    reference_url = (
        "https://learn.microsoft.com/en-us/microsoft-365/enterprise/"
        "urls-and-ip-address-ranges"
    )
    capability_id = "network_range:microsoft-365"
    client_request_id = "0f4e6d29-9c4b-4f81-b12e-cae1036ddc56"
    endpoint = (
        "https://endpoints.office.com/endpoints/worldwide"
        f"?clientrequestid={client_request_id}"
    )

    def __init__(self, client: SafeHttpClient | None = None):
        self.client = client or SafeHttpClient()

    def collect(self, query: dict) -> list[CollectedItem]:
        ip = self.validate_query(query)["ip"]
        payload = self.client.get_json(
            self.endpoint,
            allowed_hosts={"endpoints.office.com"},
        )
        if (
            not isinstance(payload, list)
            or not 10 <= len(payload) <= 1_000
            or any(not isinstance(item, dict) for item in payload)
        ):
            raise ValueError("Unexpected Microsoft 365 network-range response.")

        entries: dict[
            str,
            tuple[IpNetwork, set[tuple[str, str, str, bool]]],
        ] = {}
        raw_count = 0
        for item in payload:
            record_id = item.get("id")
            service_area = item.get("serviceArea")
            display_name = item.get("serviceAreaDisplayName")
            category = item.get("category")
            required = item.get("required")
            if (
                not isinstance(record_id, int)
                or isinstance(record_id, bool)
                or not isinstance(service_area, str)
                or not service_area
                or not isinstance(display_name, str)
                or not display_name
                or not isinstance(category, str)
                or not category
                or not isinstance(required, bool)
            ):
                raise ValueError("Unexpected Microsoft 365 network-range response.")
            values = item.get("ips")
            if values is None:
                continue
            if not isinstance(values, list) or any(
                not isinstance(value, str) for value in values
            ):
                raise ValueError("Unexpected Microsoft 365 network-range response.")
            raw_count += len(values)
            if raw_count > MAX_FEED_NETWORKS:
                raise ValueError("Unexpected Microsoft 365 network-range response.")
            for value in values:
                network = _parse_public_network(value)
                canonical = network.with_prefixlen
                if canonical not in entries:
                    entries[canonical] = (network, set())
                entries[canonical][1].add(
                    (service_area, display_name, category, required)
                )
        if raw_count < 10 or not entries:
            raise RuntimeError(
                "Microsoft 365 network-range feed did not contain enough entries."
            )

        address = ipaddress.ip_address(ip)
        matches = [
            value
            for value in entries.values()
            if value[0].version == address.version and address in value[0]
        ]
        matched = max(matches, key=lambda value: value[0].prefixlen, default=None)
        matched_entry = None
        if matched:
            metadata = matched[1]
            matched_entry = {
                "prefix": matched[0].with_prefixlen,
                "service_areas": sorted({value[0] for value in metadata}),
                "service_names": sorted({value[1] for value in metadata}),
                "categories": sorted({value[2] for value in metadata}),
                "required": any(value[3] for value in metadata),
            }
        return [
            self._item(
                ip=ip,
                locator=self.endpoint,
                data={
                    "listed": matched_entry is not None,
                    "matched_entry": matched_entry,
                    "address_family": f"IPv{address.version}",
                    "prefixes_checked": sum(
                        network.version == address.version
                        for network, _metadata in entries.values()
                    ),
                    "records_checked": len(payload),
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
        GitHubRangeCollector(client),
        OracleCloudRangeCollector(client),
        AtlassianRangeCollector(client),
        GoogleServicesRangeCollector(client),
        DigitalOceanRangeCollector(client),
        Microsoft365RangeCollector(client),
    ]
