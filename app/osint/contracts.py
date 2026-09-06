from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime


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


class Collector(ABC):
    name: str
    description: str
    target_types: frozenset[str] = frozenset()
    query_field: str = "target"
    passive: bool = True
    requires_api_key: bool = False

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
            "available": available,
            "unavailable_reason": reason,
        }

    @abstractmethod
    def validate_query(self, query: dict) -> dict:
        """Validate and normalize an untrusted collection query."""

    @abstractmethod
    def collect(self, query: dict) -> list[CollectedItem]:
        """Collect public data and return normalized immutable items."""
