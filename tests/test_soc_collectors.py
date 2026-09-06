import json

import pytest

from app.core.exceptions import BadRequestException
from app.osint.keyed_collectors import VirusTotalHashCollector
from app.osint.registry import CollectorRegistry
from app.osint.soc_collectors import (
    CisaKevCollector,
    EmailDomainDnsCollector,
    FirstEpssCollector,
    NvdCveCollector,
)
from app.osint.targets import normalize_cve, normalize_email, normalize_hash


class StubClient:
    def __init__(self) -> None:
        self.requests: list[tuple[str, dict]] = []

    def get_json(self, url: str, **kwargs):
        self.requests.append((url, kwargs))
        if "nvd.nist.gov" in url:
            return {"vulnerabilities": [{"cve": {"id": "CVE-2021-44228"}}]}
        if "known_exploited_vulnerabilities" in url:
            return {
                "catalogVersion": "test",
                "dateReleased": "2026-08-01",
                "vulnerabilities": [
                    {"cveID": "CVE-2021-44228", "vendorProject": "Apache"}
                ],
            }
        if "first.org" in url:
            return {
                "data": [
                    {"cve": "CVE-2021-44228", "epss": "0.975", "percentile": "0.999"}
                ]
            }
        if "dns.google" in url:
            return {"Status": 0, "AD": True, "Answer": [{"data": "mail.example.com."}]}
        if "virustotal.com" in url:
            return {"data": {"type": "file"}}
        raise AssertionError(f"Unexpected URL: {url}")


@pytest.mark.parametrize(
    "collector_type",
    [NvdCveCollector, CisaKevCollector, FirstEpssCollector],
)
def test_cve_collectors_return_traceable_intelligence(collector_type) -> None:
    collector = collector_type(StubClient())
    items = collector.collect({"cve": "cve-2021-44228"})

    assert len(items) == 1
    assert items[0].source_metadata["provider"]
    assert json.loads(items[0].content)["cve"] == "CVE-2021-44228"


def test_email_collector_never_transmits_or_stores_local_part() -> None:
    client = StubClient()
    item = EmailDomainDnsCollector(client).collect(
        {"email": "Analyst@Example.com"}
    )[0]

    assert len(client.requests) == 2
    assert all(
        request[1]["params"]["name"] == "example.com"
        for request in client.requests
    )
    assert "analyst" not in item.content.lower()
    assert item.locator == "dns://example.com"


def test_soc_observable_normalization_is_strict() -> None:
    assert normalize_cve("cve-2021-44228") == "CVE-2021-44228"
    assert normalize_email("Analyst@Example.com") == "Analyst@example.com"
    assert normalize_hash("A" * 64) == "a" * 64
    with pytest.raises(BadRequestException):
        normalize_hash("not-a-hash")


def test_registry_exposes_soc_collectors_and_keyed_hash() -> None:
    descriptions = {item["name"]: item for item in CollectorRegistry().describe()}
    public_names = {"cve_nvd", "cve_cisa_kev", "cve_epss", "email_domain_dns"}

    assert public_names <= descriptions.keys()
    assert all(descriptions[name]["available"] for name in public_names)
    assert descriptions["hash_virustotal"]["requires_api_key"] is True


def test_virustotal_hash_collector_uses_files_endpoint(monkeypatch) -> None:
    from pydantic import SecretStr

    client = StubClient()
    monkeypatch.setattr(
        "app.osint.keyed_collectors.settings.virustotal_api_key",
        SecretStr("test-key"),
    )
    VirusTotalHashCollector(client).collect({"hash": "b" * 64})

    assert "/api/v3/files/" in client.requests[0][0]
