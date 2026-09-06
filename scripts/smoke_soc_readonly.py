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
    assert len(collectors) == 42
    assert {"cve_nvd", "cve_cisa_kev", "cve_epss", "email_domain_dns"} <= by_name.keys()
    assert "hash" in by_name["hash_virustotal"]["target_types"]
    _, user = request("/api/v1/auth/me", token=token)
    assert isinstance(user["mfa_enabled"], bool)
    _, schema = request("/openapi.json")
    paths = schema["paths"]
    expected = {
        "/api/v1/investigations/{investigation_id}/findings",
        "/api/v1/investigations/{investigation_id}/search-schedules",
        "/api/v1/investigations/{investigation_id}/report.stix.json",
        "/api/v1/investigations/{investigation_id}/report.ndjson",
    }
    assert expected <= paths.keys()
    print(
        f"SOC read-only smoke passed: collectors={len(collectors)} "
        f"routes={len(paths)}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
