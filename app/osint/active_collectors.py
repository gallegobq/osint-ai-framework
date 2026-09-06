import json
from urllib.parse import urlsplit

import httpx

from app.core.settings import settings
from app.osint.contracts import CollectedItem, Collector
from app.osint.domain import normalize_domain


class SandboxTlsHttpBaselineCollector(Collector):
    """Low-impact active validation executed by the isolated SOC sandbox."""

    name = "sandbox_tls_http_baseline"
    description = (
        "Performs one authorized TLS negotiation and one HTTP HEAD request on "
        "TCP/443 inside the isolated SOC sandbox."
    )
    target_types = frozenset({"domain", "hostname"})
    query_field = "hostname"
    passive = False

    def availability(self) -> tuple[bool, str | None]:
        if not settings.soc_sandbox_enabled:
            return False, "SOC sandbox is disabled by SOC_SANDBOX_ENABLED."
        parsed = urlsplit(settings.soc_sandbox_url)
        if (
            parsed.scheme != "http"
            or parsed.hostname not in {"sandbox", "localhost", "127.0.0.1"}
            or parsed.username
            or parsed.password
        ):
            return False, "SOC_SANDBOX_URL must reference the local sandbox service."
        return True, None

    def validate_query(self, query: dict) -> dict:
        return {"hostname": normalize_domain(query.get("hostname"))}

    def collect(self, query: dict) -> list[CollectedItem]:
        normalized = self.validate_query(query)
        hostname = normalized["hostname"]
        with httpx.Client(timeout=settings.soc_sandbox_timeout_seconds) as client:
            response = client.post(
                f"{settings.soc_sandbox_url.rstrip('/')}/v1/run",
                json={"tool": "tls_http_baseline", "target": hostname},
            )
            response.raise_for_status()
            data = response.json()
        if not isinstance(data, dict) or data.get("target") != hostname:
            raise RuntimeError("SOC sandbox returned an invalid result contract.")
        return [
            CollectedItem(
                source_type="active_validation",
                locator=f"soc-sandbox://tls-http-baseline/{hostname}",
                kind="tls_http_baseline",
                title=f"Sandboxed TLS and HTTP baseline for {hostname}",
                content=json.dumps(data, ensure_ascii=False, sort_keys=True),
                raw_data=data,
                source_metadata={
                    "execution_boundary": "soc-sandbox",
                    "active": True,
                    "profile": "single-host-low-impact-v1",
                },
            )
        ]
