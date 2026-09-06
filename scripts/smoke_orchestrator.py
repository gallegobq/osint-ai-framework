import time
from uuid import uuid4

import httpx

from app.core.settings import settings


TERMINAL_STATUSES = {"succeeded", "partial", "failed"}


def main() -> None:
    username = settings.initial_admin_username
    password = settings.initial_admin_password
    if username is None or password is None:
        raise RuntimeError("Initial administrator is not configured.")

    suffix = uuid4().hex[:10]
    project_id = None
    investigation_id = None
    headers = None
    with httpx.Client(base_url=settings.smoke_base_url, timeout=30) as client:
        try:
            token_response = client.post(
                "/api/v1/auth/token",
                data={
                    "username": username,
                    "password": password.get_secret_value(),
                },
            )
            token_response.raise_for_status()
            headers = {
                "Authorization": f"Bearer {token_response.json()['access_token']}"
            }

            project_response = client.post(
                "/api/v1/projects",
                headers=headers,
                json={
                    "name": f"Orchestrator Smoke {suffix}",
                    "slug": f"orchestrator-smoke-{suffix}",
                    "description": "Disposable authorized orchestration test.",
                },
            )
            project_response.raise_for_status()
            project_id = project_response.json()["id"]

            investigation_response = client.post(
                f"/api/v1/projects/{project_id}/investigations",
                headers=headers,
                json={
                    "title": f"Authorized example.com search {suffix}",
                    "kind": "domain",
                    "priority": "low",
                },
            )
            investigation_response.raise_for_status()
            investigation_id = investigation_response.json()["id"]

            run_response = client.post(
                f"/api/v1/investigations/{investigation_id}/search-runs",
                headers=headers,
                json={
                    "objective": (
                        "Collect reliable public DNS and registration context "
                        "for example.com"
                    ),
                    "targets": [{"type": "domain", "value": "example.com"}],
                    "max_tools": 3,
                    "allow_active": False,
                    "authorization_confirmed": True,
                    "scope_note": "IANA reserved domain used for testing.",
                },
            )
            run_response.raise_for_status()
            run = run_response.json()

            deadline = time.monotonic() + 180
            while run["status"] not in TERMINAL_STATUSES:
                if time.monotonic() >= deadline:
                    raise RuntimeError("Orchestrated search timed out.")
                time.sleep(1)
                response = client.get(
                    f"/api/v1/search-runs/{run['id']}",
                    headers=headers,
                )
                response.raise_for_status()
                run = response.json()

            summary = run.get("result_summary") or {}
            if run["status"] not in {"succeeded", "partial"}:
                raise RuntimeError("All orchestrated collectors failed.")
            if not summary.get("evidence_ids"):
                raise RuntimeError("Orchestration did not create evidence.")

            evidence_response = client.get(
                f"/api/v1/investigations/{investigation_id}/evidence",
                headers=headers,
            )
            evidence_response.raise_for_status()
            if not evidence_response.json():
                raise RuntimeError("Persisted evidence could not be retrieved.")

            print(
                "Orchestrator smoke passed: "
                f"run={run['id']} status={run['status']} "
                f"planner={run['planner']} "
                f"evidence={len(summary['evidence_ids'])}"
            )
        finally:
            if headers and investigation_id:
                client.patch(
                    f"/api/v1/investigations/{investigation_id}",
                    headers=headers,
                    json={"status": "archived"},
                )
            if headers and project_id:
                client.patch(
                    f"/api/v1/projects/{project_id}",
                    headers=headers,
                    json={"status": "archived"},
                )
            if headers:
                client.post("/api/v1/auth/logout", headers=headers)


if __name__ == "__main__":
    main()
