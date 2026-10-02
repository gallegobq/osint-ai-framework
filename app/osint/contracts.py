from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime

from app.osint.profiles import ScanProfile


DISCOVERY_TARGET_TYPES = frozenset(
    {
        "domain",
        "hostname",
        "ip",
        "asn",
        "url",
        "username",
        "email",
        "hash",
        "cve",
        "keyword",
    }
)


@dataclass(frozen=True, slots=True)
class DiscoveredTarget:
    target_type: str
    value: str
    relation: str = "related"

    def __post_init__(self) -> None:
        if self.target_type not in DISCOVERY_TARGET_TYPES:
            raise ValueError("Unsupported discovered target type.")
        if not isinstance(self.value, str) or not self.value.strip():
            raise ValueError("Discovered target value must be a non-empty string.")
        if len(self.value) > 2048:
            raise ValueError("Discovered target value exceeds 2048 characters.")
        if not self.relation or len(self.relation) > 100:
            raise ValueError("Discovery relation must contain 1 to 100 characters.")


@dataclass(frozen=True, slots=True)
class CollectedItem:
    source_type: str
    locator: str
    kind: str
    title: str
    content: str
    raw_data: dict = field(default_factory=dict)
    source_metadata: dict = field(default_factory=dict)
    observed_at: datetime | None = None
    discoveries: tuple[DiscoveredTarget, ...] = ()


class Collector(ABC):
    name: str
    description: str
    target_types: frozenset[str] = frozenset()
    query_field: str = "target"
    passive: bool = True
    requires_api_key: bool = False
    profiles: frozenset[str] = frozenset({ScanProfile.INVESTIGATE.value})
    emitted_target_types: frozenset[str] = frozenset()

    def availability(self) -> tuple[bool, str | None]:
        """Return runtime availability without exposing secret configuration."""

        return True, None

    def describe(self) -> dict[str, object]:
        available, reason = self.availability()
        return {
            "name": self.name,
            "description": self.description,
            "target_types": sorted(self.target_types),
            "query_field": self.query_field,
            "passive": self.passive,
            "requires_api_key": self.requires_api_key,
            "profiles": self.supported_profiles(),
            "emitted_target_types": sorted(self.emitted_target_types),
            "available": available,
            "unavailable_reason": reason,
        }

    def supports_profile(self, profile: ScanProfile | str) -> bool:
        selected = ScanProfile(profile)
        if selected in {ScanProfile.AUTO, ScanProfile.ALL}:
            return True
        if selected is ScanProfile.PASSIVE:
            return self.passive
        return selected.value in self.profiles

    def supported_profiles(self) -> list[str]:
        supported = {
            ScanProfile.AUTO.value,
            ScanProfile.ALL.value,
            *self.profiles,
        }
        if self.passive:
            supported.add(ScanProfile.PASSIVE.value)
        return sorted(supported)

    @abstractmethod
    def validate_query(self, query: dict) -> dict:
        """Validate and normalize an untrusted collection query."""

    @abstractmethod
    def collect(self, query: dict) -> list[CollectedItem]:
        """Collect public data and return normalized immutable items."""
