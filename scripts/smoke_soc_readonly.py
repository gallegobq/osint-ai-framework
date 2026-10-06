import json
import os
import urllib.request


BASE_URL = os.environ.get("SMOKE_BASE_URL", "http://localhost:8000").rstrip("/")


def request(path: str, *, body: dict | None = None, token: str | None = None):
    data = json.dumps(body).encode() if body is not None else None
    current = urllib.request.Request(f"{BASE_URL}{path}", data=data)
    if data is not None:
        current.add_header("Content-Type", "application/json")
    if token:
        current.add_header("Authorization", f"Bearer {token}")
    with urllib.request.urlopen(current, timeout=20) as response:
        return response.status, json.loads(response.read().decode())


def main() -> int:
    username = os.environ["INITIAL_ADMIN_USERNAME"]
    password = os.environ["INITIAL_ADMIN_PASSWORD"]
    status, tokens = request(
        "/api/v1/auth/login",
        body={"username": username, "password": password, "mfa_code": None},
    )
    assert status == 200
    token = tokens["access_token"]
    _, collectors = request("/api/v1/collectors", token=token)
    by_name = {item["name"]: item for item in collectors}
    assert len(collectors) >= 88
    assert {
        "cve_nvd",
        "cve_cisa_kev",
        "cve_epss",
        "cve_mitre_record",
        "cve_redhat_status",
        "cve_suse_vex",
        "cve_github_advisory",
        "cve_ubuntu_status",
        "cve_debian_status",
        "cve_cisa_ssvc",
        "cve_osv_git_ranges",
        "ip_cloudflare_ranges",
        "ip_fastly_ranges",
        "ip_github_ranges",
        "ip_google_cloud_ranges",
        "ip_google_services_ranges",
        "ip_oracle_cloud_ranges",
        "ip_atlassian_ranges",
        "ip_digitalocean_ranges",
        "ip_microsoft_365_ranges",
        "url_openphish_feed",
        "url_urlhaus_recent",
        "hash_sslbl_certificate",
        "ip_dshield_subnets",
        "ip_aws_ranges",
        "ip_ripestat_routing_history",
        "asn_ripestat_neighbours",
        "asn_ripestat_path_length",
        "ip_ripestat_rpki",
        "email_domain_dns",
    } <= by_name.keys()
    assert "hash" in by_name["hash_virustotal"]["target_types"]
    assert all(item["profiles"] for item in collectors)
    assert by_name["domain_dns"]["emitted_target_types"] == ["ip"]
    _, profiles = request("/api/v1/search-profiles", token=token)
    assert {item["name"] for item in profiles} == {
        "auto",
        "passive",
        "footprint",
        "investigate",
        "all",
    }
    _, user = request("/api/v1/auth/me", token=token)
    assert isinstance(user["mfa_enabled"], bool)
    _, schema = request("/openapi.json")
    paths = schema["paths"]
    expected = {
        "/api/v1/investigations/{investigation_id}/findings",
        "/api/v1/investigations/{investigation_id}/search-schedules",
        "/api/v1/investigations/{investigation_id}/report.stix.json",
        "/api/v1/investigations/{investigation_id}/report.ndjson",
        "/api/v1/search-profiles",
        "/api/v1/search-runs/{run_id}/discoveries",
    }
    assert expected <= paths.keys()
    _, benchmark = request("/api/v1/collectors/benchmark", token=token)
    assert benchmark["registered_modules"] >= 88
    assert benchmark["unique_capabilities"] == benchmark["registered_modules"]
    assert benchmark["parity_target"] == 233
    assert benchmark["remaining_to_target"] == 145
    assert benchmark["runtime_health"] == "not_measured_by_catalog_benchmark"
    print(
        f"SOC read-only smoke passed: collectors={len(collectors)} "
        f"routes={len(paths)}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
