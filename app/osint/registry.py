from app.core.exceptions import BadRequestException, ServiceUnavailableException
from app.osint.collectors import DomainDnsCollector, DomainRdapCollector
from app.osint.active_collectors import SandboxTlsHttpBaselineCollector
from app.osint.contracts import Collector
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
from app.osint.soc_collectors import (
    CisaKevCollector,
    EmailDomainDnsCollector,
    FirstEpssCollector,
    NvdCveCollector,
)


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
    ]


class CollectorRegistry:
    def __init__(self, collectors: list[Collector] | None = None):
        instances = default_collectors() if collectors is None else collectors
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
