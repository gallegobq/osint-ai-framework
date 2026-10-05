import pytest

from app.core.exceptions import BadRequestException
from app.osint.public_module_pack import (
    COMMON_SRV_PREFIXES,
    CirclHashlookupCollector,
    DNS_MODULE_SPECS,
    DnsCommonSrvCollector,
    GleifOrganizationCollector,
    HackerTargetDomainCollector,
    IpApiGeoCollector,
    IpFeedMembershipCollector,
    KeybaseUserCollector,
    SslblCertificateHashCollector,
    DnsPolicyCollector,
    IP_FEED_SPECS,
    public_module_pack,
)
from app.osint.registry import CollectorRegistry, default_collectors


class StubClient:
    def __init__(self):
        self.calls: list[tuple[str, dict | None]] = []

    def get_json(
        self,
        url: str,
        *,
        params: dict | None = None,
        allowed_hosts: set[str],
        **_kwargs,
    ) -> object:
        self.calls.append((url, params))
        if url == "https://dns.google/resolve":
            name = str((params or {}).get("name"))
            record_type = str((params or {}).get("type"))
            if name.startswith("_dmarc."):
                answers = [{"data": '"v=DMARC1; p=reject"'}]
            elif record_type == "SRV" and name.startswith("_sip._tcp."):
                answers = [{"data": "10 5 5060 sip.example.com."}]
            else:
                answers = []
            return {"Status": 0, "AD": True, "Answer": answers}
        if "ipapi.co" in url:
            return {"ip": "8.8.8.8", "asn": "AS15169", "hostname": "dns.google"}
        if "hashlookup.circl.lu" in url:
            return {"SHA-256": "a" * 64, "source": "test corpus"}
        if "keybase.io" in url:
            return {"status": {"code": 0}, "them": [{"id": "alice"}]}
        if "api.gleif.org" in url:
            return {"data": [{"id": "LEI1"}], "meta": {"count": 1}}
        raise AssertionError(f"Unexpected URL: {url}")

    def get_text(
        self,
        url: str,
        *,
        params: dict | None = None,
        allowed_hosts: set[str],
        **_kwargs,
    ) -> str:
        self.calls.append((url, params))
        if "hackertarget" in url:
            return "dns.google,8.8.8.8\n"
        return "# generated fixture\n1.1.1.1\n8.8.8.8\n"


def test_public_module_pack_has_unique_executable_modules() -> None:
    modules = public_module_pack(StubClient())

    assert len(modules) == 20
    assert len({module.name for module in modules}) == 20
    assert all(module.passive for module in modules)
    assert all(module.provider and module.reference_url for module in modules)


def test_registry_benchmark_tracks_spiderfoot_gap_without_inflating_availability() -> None:
    collectors = default_collectors()
    benchmark = CollectorRegistry(collectors).benchmark()

    assert len(collectors) == 84
    assert benchmark["registered_modules"] == 84
    assert benchmark["unique_capabilities"] == 84
    assert benchmark["capability_integrity_passed"] is True
    assert benchmark["spiderfoot_reference_modules"] == 232
    assert benchmark["parity_target"] == 233
    assert benchmark["remaining_to_target"] == 149
    assert benchmark["parity_achieved"] is False
    assert benchmark["configured_modules"] < benchmark["registered_modules"]
    assert len(str(benchmark["reference_commit"])) == 40
    assert benchmark["runtime_health"] == "not_measured_by_catalog_benchmark"


def test_dns_policy_and_common_srv_modules_emit_typed_targets() -> None:
    client = StubClient()
    dmarc_spec = next(spec for spec in DNS_MODULE_SPECS if spec.name == "domain_dns_dmarc")

    dmarc = DnsPolicyCollector(dmarc_spec, client).collect(
        {"domain": "example.com"}
    )[0]
    srv = DnsCommonSrvCollector(client).collect({"domain": "example.com"})[0]

    assert dmarc.raw_data["policy_present"] is True
    assert dmarc.raw_data["query_name"] == "_dmarc.example.com"
    assert len(COMMON_SRV_PREFIXES) <= 12
    assert [(item.target_type, item.value) for item in srv.discoveries] == [
        ("hostname", "sip.example.com")
    ]


def test_ip_feed_membership_is_exact_and_rejects_private_targets() -> None:
    collector = IpFeedMembershipCollector(IP_FEED_SPECS[0], StubClient())

    item = collector.collect({"ip": "8.8.8.8"})[0]

    assert item.raw_data["listed"] is True
    assert item.raw_data["matched_entry"] == "8.8.8.8"
    try:
        collector.collect({"ip": "127.0.0.1"})
    except BadRequestException:
        pass
    else:
        raise AssertionError("Private IPs must be rejected.")


def sslbl_certificate_feed(size: int, *, matched: bool = True) -> str:
    rows = [
        f"2026-10-04 00:00:{index % 60:02d},{index:040x},fixture reason"
        for index in range(size)
    ]
    if matched:
        rows[5] = f"2026-10-04 00:00:05,{'a' * 40},Test C&C"
    return "# Listingdate,SHA1,Listingreason\n" + "\n".join(rows)


class SslblCertificateClient:
    def __init__(self, body: str) -> None:
        self.body = body
        self.calls: list[tuple[str, dict]] = []

    def get_text(self, url: str, **kwargs) -> str:
        self.calls.append((url, kwargs))
        return self.body


def test_sslbl_certificate_match_is_local_and_bounded() -> None:
    client = SslblCertificateClient(sslbl_certificate_feed(100))

    item = SslblCertificateHashCollector(client).collect({"hash": "A" * 40})[0]

    assert item.raw_data == {
        "hash": "a" * 40,
        "algorithm": "sha1",
        "listed": True,
        "listing": {
            "listing_date": "2026-10-04 00:00:05",
            "reason": "Test C&C",
        },
        "entries_checked": 100,
        "rejected_entries": 0,
    }
    assert client.calls == [
        (
            SslblCertificateHashCollector.feed_url,
            {
                "headers": {"Accept": "text/csv"},
                "allowed_hosts": {"sslbl.abuse.ch"},
            },
        )
    ]
    assert "a" * 40 not in client.calls[0][0]


@pytest.mark.parametrize("fingerprint", ["a" * 32, "a" * 64])
def test_sslbl_certificate_rejects_non_sha1_before_fetching(fingerprint) -> None:
    client = SslblCertificateClient(sslbl_certificate_feed(100))

    with pytest.raises(BadRequestException, match="must use SHA-1"):
        SslblCertificateHashCollector(client).collect({"hash": fingerprint})

    assert client.calls == []


def test_sslbl_certificate_rejects_truncated_feed() -> None:
    client = SslblCertificateClient(sslbl_certificate_feed(99))

    with pytest.raises(RuntimeError, match="enough valid entries"):
        SslblCertificateHashCollector(client).collect({"hash": "a" * 40})


def test_sslbl_certificate_rejects_oversized_feed() -> None:
    collector = SslblCertificateHashCollector(
        SslblCertificateClient(
            sslbl_certificate_feed(
                SslblCertificateHashCollector.maximum_entries + 1,
                matched=False,
            )
        )
    )

    with pytest.raises(RuntimeError, match="safe entry limit"):
        collector.collect({"hash": "a" * 40})


def test_public_enrichment_modules_return_bounded_normalized_evidence() -> None:
    client = StubClient()
    ip_item = IpApiGeoCollector(client).collect({"ip": "8.8.8.8"})[0]
    hash_item = CirclHashlookupCollector(client).collect({"hash": "a" * 64})[0]
    keybase_item = KeybaseUserCollector(client).collect({"username": "alice"})[0]
    gleif_item = GleifOrganizationCollector(client).collect(
        {"keyword": "Example Corp"}
    )[0]
    host_item = HackerTargetDomainCollector(client).collect(
        {"domain": "example.com"}
    )[0]

    assert {item.target_type for item in ip_item.discoveries} == {
        "asn",
        "hostname",
    }
    assert hash_item.raw_data["found"] is True
    assert keybase_item.raw_data["found"] is True
    assert len(gleif_item.raw_data["records"]) == 1
    assert {item.target_type for item in host_item.discoveries} == {
        "hostname",
        "ip",
    }


def test_keybase_null_profile_is_not_reported_as_found() -> None:
    class MissingUserClient(StubClient):
        def get_json(self, url: str, **kwargs) -> object:
            if "keybase.io" in url:
                return {"status": {"code": 0}, "them": [None]}
            return super().get_json(url, **kwargs)

    item = KeybaseUserCollector(MissingUserClient()).collect(
        {"username": "missing-user"}
    )[0]

    assert item.raw_data["found"] is False
    assert item.raw_data["profiles"] == []


def test_dead_feed_and_hackertarget_quota_are_not_silent_successes() -> None:
    class DiagnosticClient(StubClient):
        def __init__(self, response: str):
            super().__init__()
            self.response = response

        def get_text(self, url: str, **kwargs) -> str:
            return self.response

    feed = IpFeedMembershipCollector(
        IP_FEED_SPECS[0],
        DiagnosticClient("# deprecated; no entries remain"),
    )
    with pytest.raises(RuntimeError, match="valid IP entries"):
        feed.collect({"ip": "8.8.8.8"})

    host_search = HackerTargetDomainCollector(
        DiagnosticClient("API count exceeded - increase quota")
    )
    with pytest.raises(RuntimeError, match="error response"):
        host_search.collect({"domain": "example.com"})
