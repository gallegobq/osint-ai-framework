from unittest.mock import Mock

import pytest
from pydantic import ValidationError

from app.core.exceptions import BadRequestException
from app.llm.contracts import LLMProvider
from app.osint.planner import SearchPlanner
from app.osint.registry import CollectorRegistry
from app.osint.targets import (
    infer_targets,
    normalize_asn,
    normalize_cve,
    normalize_email,
    normalize_hash,
    normalize_hostname,
    normalize_ip,
    normalize_public_url,
)
from app.schemas.orchestration import SearchRunCreate


class FakeProvider(LLMProvider):
    name = "fake-ollama"

    def __init__(self, response: dict):
        self.response = response

    def generate_json(
        self,
        prompt: str,
        schema: dict | None = None,
    ) -> dict:
        assert "untrusted data" in prompt
        assert schema is not None
        return self.response


def test_public_target_normalization() -> None:
    assert normalize_ip("8.8.8.8") == "8.8.8.8"
    assert normalize_asn("as15169") == "AS15169"
    assert normalize_public_url("HTTPS://Example.COM/path#fragment") == (
        "https://example.com/path"
    )
    assert normalize_hostname("Sub.Example.COM") == "sub.example.com"
    assert normalize_email("Analyst@Example.COM") == "Analyst@example.com"
    assert normalize_cve("cve-2021-44228") == "CVE-2021-44228"
    assert normalize_hash("A" * 32) == "a" * 32


@pytest.mark.parametrize("value", ["127.0.0.1", "10.0.0.1", "::1"])
def test_private_ip_targets_are_rejected(value: str) -> None:
    with pytest.raises(BadRequestException):
        normalize_ip(value)


def test_search_requires_authorization_confirmation() -> None:
    with pytest.raises(ValidationError):
        SearchRunCreate(
            objective="Research example.com",
            targets=[{"type": "domain", "value": "example.com"}],
            authorization_confirmed=False,
        )


def test_objective_can_infer_typed_targets() -> None:
    assert infer_targets("Revisar https://example.com y AS15169") == [
        {"type": "url", "value": "https://example.com/"},
        {"type": "domain", "value": "example.com"},
        {"type": "asn", "value": "AS15169"},
    ]


def test_objective_infers_soc_observables() -> None:
    inferred = infer_targets(
        "Review SOC@example.com, CVE-2021-44228 and " + "a" * 64
    )

    assert {"type": "email", "value": "SOC@example.com"} in inferred
    assert {"type": "cve", "value": "CVE-2021-44228"} in inferred
    assert {"type": "hash", "value": "a" * 64} in inferred


def test_registry_exposes_available_and_keyed_tools_without_secrets() -> None:
    descriptions = CollectorRegistry().describe()
    assert len(descriptions) >= 37
    assert sum(item["available"] for item in descriptions) >= 33
    shodan = next(item for item in descriptions if item["name"] == "ip_shodan")
    assert shodan["requires_api_key"] is True
    assert "SHODAN_API_KEY" in str(shodan["unavailable_reason"])
    assert "key=" not in str(descriptions)


def test_ollama_plan_is_restricted_to_compatible_allowlisted_tools() -> None:
    provider = FakeProvider(
        {
            "summary": "Use complementary domain sources.",
            "steps": [
                {
                    "collector": "domain_dns_records",
                    "target_index": 0,
                    "reason": "DNS context",
                },
                {
                    "collector": "ip_rdap",
                    "target_index": 0,
                    "reason": "Incompatible and must be removed",
                },
                {
                    "collector": "domain_dns_records",
                    "target_index": 0,
                    "reason": "Duplicate and must be removed",
                },
            ],
        }
    )
    plan = SearchPlanner(CollectorRegistry(), provider).plan(
        objective="Research the public infrastructure",
        targets=[{"type": "domain", "value": "example.com"}],
        max_tools=5,
        allow_active=False,
    )
    assert plan.planner == "fake-ollama"
    assert [step["collector"] for step in plan.steps] == [
        "domain_dns_records"
    ]
    assert plan.steps[0]["query"] == {"domain": "example.com"}


def test_invalid_ollama_output_uses_safe_fallback() -> None:
    provider = Mock(spec=LLMProvider)
    provider.name = "broken"
    provider.generate_json.side_effect = ValueError("invalid JSON")
    plan = SearchPlanner(CollectorRegistry(), provider).plan(
        objective="Research a public domain",
        targets=[{"type": "domain", "value": "example.com"}],
        max_tools=3,
        allow_active=False,
    )
    assert plan.planner == "deterministic-fallback"
    assert len(plan.steps) == 3
    assert all(step["query"] == {"domain": "example.com"} for step in plan.steps)


def test_authorized_active_fallback_selects_sandbox_profile_first() -> None:
    provider = Mock(spec=LLMProvider)
    provider.name = "broken"
    provider.generate_json.side_effect = ValueError("invalid JSON")

    plan = SearchPlanner(CollectorRegistry(), provider).plan(
        objective="Validate TLS for the explicitly authorized target",
        targets=[{"type": "domain", "value": "example.com"}],
        max_tools=1,
        allow_active=True,
        operation_mode="pentest",
    )

    assert plan.steps[0]["collector"] == "sandbox_tls_http_baseline"
    assert plan.steps[0]["query"] == {"hostname": "example.com"}
