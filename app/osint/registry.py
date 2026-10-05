from app.core.exceptions import BadRequestException, ServiceUnavailableException
from app.osint.collectors import DomainDnsCollector, DomainRdapCollector
from app.osint.active_collectors import SandboxTlsHttpBaselineCollector
from app.osint.aws_ranges_collector import AwsRangeCollector
from app.osint.asn_neighbours_collector import AsnNeighboursCollector
from app.osint.contracts import Collector
from app.osint.dshield_collector import DshieldSubnetCollector
from app.osint.extended_collectors import (
    BlueskyUserCollector,
    CrossrefSearchCollector,
    DomainCertSpotterCollector,
    DomainCommonCrawlCollector,
    EuropePmcSearchCollector,
    GdeltNewsSearchCollector,
    GitHubRepositoriesCollector,
    GoogleBooksSearchCollector,
    HackerNewsSearchCollector,
    HackerNewsUserCollector,
    IpShodanInternetDbCollector,
    NpmMaintainerCollector,
    OpenLibrarySearchCollector,
    StackExchangeSearchCollector,
    UrlCommonCrawlCollector,
)
from app.osint.keyed_collectors import (
    SecurityTrailsDomainCollector,
    ShodanIpCollector,
    VirusTotalDomainCollector,
    VirusTotalHashCollector,
    VirusTotalIpCollector,
)
from app.osint.network_range_collectors import public_network_range_collectors
from app.osint.passive_collectors import (
    AsnPeeringDbCollector,
    AsnRdapCollector,
    AsnRipeStatCollector,
    DomainCertificateTransparencyCollector,
    DomainDnsRecordsCollector,
    DomainWaybackCollector,
    GitHubUserCollector,
    GitLabUserCollector,
    IpRdapCollector,
    IpReverseDnsCollector,
    IpRipeStatCollector,
    OpenAlexSearchCollector,
    UrlWaybackCollector,
    UrlscanDomainCollector,
    WikidataSearchCollector,
    WikipediaSearchCollector,
)
from app.osint.public_module_pack import public_module_pack
from app.osint.routing_history_collector import IpRoutingHistoryCollector
from app.osint.url_feed_collectors import public_url_feed_collectors
from app.osint.soc_collectors import (
    CisaKevCollector,
    EmailDomainDnsCollector,
    FirstEpssCollector,
    NvdCveCollector,
)
from app.osint.vulnerability_collectors import public_vulnerability_collectors


SPIDERFOOT_REFERENCE_MODULES = 232
LINTERNA_MODULE_PARITY_TARGET = 233
SPIDERFOOT_REFERENCE_DATE = "2026-10-03"
SPIDERFOOT_REFERENCE_COMMIT = "0f815a203afebf05c98b605dba5cf0475a0ee5fd"
SPIDERFOOT_REFERENCE_URL = (
    "https://github.com/smicallef/spiderfoot/blob/"
    f"{SPIDERFOOT_REFERENCE_COMMIT}/README.md#modules--integrations"
)
PARITY_CERTIFIED = False


def default_collectors() -> list[Collector]:
    return [
        SandboxTlsHttpBaselineCollector(),
        DomainDnsCollector(),
        DomainDnsRecordsCollector(),
        DomainRdapCollector(),
        DomainCertificateTransparencyCollector(),
        DomainCertSpotterCollector(),
        DomainWaybackCollector(),
        DomainCommonCrawlCollector(),
        UrlscanDomainCollector(),
        IpRdapCollector(),
        IpReverseDnsCollector(),
        IpRipeStatCollector(),
        IpShodanInternetDbCollector(),
        AsnRdapCollector(),
        AsnRipeStatCollector(),
        AsnPeeringDbCollector(),
        UrlWaybackCollector(),
        UrlCommonCrawlCollector(),
        WikidataSearchCollector(),
        WikipediaSearchCollector(),
        OpenAlexSearchCollector(),
        GdeltNewsSearchCollector(),
        CrossrefSearchCollector(),
        OpenLibrarySearchCollector(),
        StackExchangeSearchCollector(),
        EuropePmcSearchCollector(),
        GoogleBooksSearchCollector(),
        HackerNewsSearchCollector(),
        GitHubUserCollector(),
        GitHubRepositoriesCollector(),
        GitLabUserCollector(),
        BlueskyUserCollector(),
        HackerNewsUserCollector(),
        NpmMaintainerCollector(),
        NvdCveCollector(),
        CisaKevCollector(),
        FirstEpssCollector(),
        EmailDomainDnsCollector(),
        ShodanIpCollector(),
        VirusTotalDomainCollector(),
        VirusTotalIpCollector(),
        VirusTotalHashCollector(),
        SecurityTrailsDomainCollector(),
        *public_module_pack(),
        *public_vulnerability_collectors(),
        *public_network_range_collectors(),
        *public_url_feed_collectors(),
        DshieldSubnetCollector(),
        AwsRangeCollector(),
        IpRoutingHistoryCollector(),
        AsnNeighboursCollector(),
    ]


class CollectorRegistry:
    def __init__(self, collectors: list[Collector] | None = None):
        instances = default_collectors() if collectors is None else collectors
        names = [collector.name for collector in instances]
        if len(names) != len(set(names)):
            raise ValueError("Collector names must be unique.")
        capability_ids = [
            collector.capability_id or collector.name for collector in instances
        ]
        if len(capability_ids) != len(set(capability_ids)):
            raise ValueError("Collector capability IDs must be unique.")
        self._collectors = {collector.name: collector for collector in instances}

    def get(self, name: str, *, require_available: bool = True) -> Collector:
        collector = self._collectors.get(name)
        if collector is None:
            raise BadRequestException(f"Unknown collector: {name}.")
        available, reason = collector.availability()
        if require_available and not available:
            raise ServiceUnavailableException(
                reason or f"Collector {name} is not configured."
            )
        return collector

    def available(self) -> list[Collector]:
        return [
            collector
            for collector in self._collectors.values()
            if collector.availability()[0]
        ]

    def describe(self) -> list[dict[str, object]]:
        return [
            item.describe()
            for item in sorted(self._collectors.values(), key=lambda value: value.name)
        ]

    def benchmark(self) -> dict[str, object]:
        descriptions = self.describe()
        registered = len(descriptions)
        configured = sum(bool(item["available"]) for item in descriptions)
        passive = sum(bool(item["passive"]) for item in descriptions)
        capability_ids = {
            str(item["capability_id"]) for item in descriptions
        }
        families = sorted(
            {
                str(item["module_family"])
                for item in descriptions
                if item.get("module_family")
            }
        )
        return {
            "registered_modules": registered,
            "configured_modules": configured,
            "passive_modules": passive,
            "unique_capabilities": len(capability_ids),
            "capability_integrity_passed": len(capability_ids) == registered,
            "module_families": families,
            "spiderfoot_reference_modules": SPIDERFOOT_REFERENCE_MODULES,
            "parity_target": LINTERNA_MODULE_PARITY_TARGET,
            "remaining_to_target": max(
                LINTERNA_MODULE_PARITY_TARGET - registered,
                0,
            ),
            "catalog_target_met": registered >= LINTERNA_MODULE_PARITY_TARGET,
            "parity_certified": PARITY_CERTIFIED,
            "parity_achieved": (
                registered >= LINTERNA_MODULE_PARITY_TARGET
                and len(capability_ids) == registered
                and PARITY_CERTIFIED
            ),
            "reference_date": SPIDERFOOT_REFERENCE_DATE,
            "reference_commit": SPIDERFOOT_REFERENCE_COMMIT,
            "reference_url": SPIDERFOOT_REFERENCE_URL,
            "runtime_health": "not_measured_by_catalog_benchmark",
            "counting_method": (
                "Unique registered executable capabilities; configuration availability "
                "is reported separately and runtime health requires live probes."
            ),
        }
