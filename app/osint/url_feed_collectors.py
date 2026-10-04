from dataclasses import dataclass

from app.core.exceptions import BadRequestException
from app.osint.contracts import CollectedItem, Collector
from app.osint.http import SafeHttpClient
from app.osint.passive_collectors import _json_item
from app.osint.targets import normalize_public_url


MAX_URL_FEED_ENTRIES = 50_000


@dataclass(frozen=True, slots=True)
class UrlFeedSpec:
    name: str
    description: str
    provider: str
    feed_url: str
    reference_url: str
    capability_id: str
    minimum_entries: int

    @property
    def allowed_host(self) -> str:
        return self.feed_url.split("/", 3)[2]


URL_FEED_SPECS = (
    UrlFeedSpec(
        name="url_openphish_feed",
        description="Checks a public URL against OpenPhish's community feed.",
        provider="OpenPhish",
        feed_url=(
            "https://raw.githubusercontent.com/openphish/public_feed/"
            "refs/heads/main/feed.txt"
        ),
        reference_url="https://openphish.com/",
        capability_id="url_reputation:openphish-feed",
        minimum_entries=100,
    ),
    UrlFeedSpec(
        name="url_urlhaus_recent",
        description="Checks a public URL against URLhaus's recent malware feed.",
        provider="abuse.ch URLhaus",
        feed_url="https://urlhaus.abuse.ch/downloads/text_recent/",
        reference_url="https://urlhaus.abuse.ch/api/#urlhaus-downloads",
        capability_id="url_reputation:urlhaus-recent",
        minimum_entries=1_000,
    ),
)


class UrlFeedMembershipCollector(Collector):
    target_types = frozenset({"url"})
    query_field = "url"
    profiles = frozenset({"investigate"})
    module_family = "threat_feed"

    def __init__(
        self,
        spec: UrlFeedSpec,
        client: SafeHttpClient | None = None,
    ):
        self.spec = spec
        self.name = spec.name
        self.description = spec.description
        self.provider = spec.provider
        self.reference_url = spec.reference_url
        self.capability_id = spec.capability_id
        self.client = client or SafeHttpClient()

    def validate_query(self, query: dict) -> dict:
        return {"url": normalize_public_url(query.get("url"))}

    def collect(self, query: dict) -> list[CollectedItem]:
        target = self.validate_query(query)["url"]
        body = self.client.get_text(
            self.spec.feed_url,
            headers={"Accept": "text/plain"},
            allowed_hosts={self.spec.allowed_host},
        )
        if not isinstance(body, str):
            raise ValueError("Unexpected public URL-feed response.")
        raw_entries = [
            line.strip()
            for line in body.splitlines()
            if line.strip() and not line.lstrip().startswith("#")
        ]
        if (
            len(raw_entries) < self.spec.minimum_entries
            or len(raw_entries) > MAX_URL_FEED_ENTRIES
        ):
            raise RuntimeError("Public URL feed did not contain a safe number of entries.")

        normalized_entries: set[str] = set()
        rejected_entries = 0
        for entry in raw_entries:
            try:
                normalized_entries.add(normalize_public_url(entry))
            except BadRequestException:
                rejected_entries += 1
        if len(normalized_entries) < self.spec.minimum_entries:
            raise RuntimeError("Public URL feed did not contain enough valid entries.")

        return [
            _json_item(
                source_type="threat_intelligence",
                locator=self.spec.feed_url,
                kind=self.name,
                title=f"{self.provider} status for {target}",
                data={
                    "url": target,
                    "listed": target in normalized_entries,
                    "entries_checked": len(normalized_entries),
                    "rejected_entries": rejected_entries,
                },
                provider=self.provider,
            )
        ]


def public_url_feed_collectors(
    client: SafeHttpClient | None = None,
) -> list[Collector]:
    return [
        UrlFeedMembershipCollector(spec, client)
        for spec in URL_FEED_SPECS
    ]
