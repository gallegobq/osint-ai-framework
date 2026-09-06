from uuid import uuid4

import httpx

from app.core.settings import settings


def main() -> None:
    username = settings.initial_admin_username
    password = settings.initial_admin_password
    if username is None or password is None:
        raise RuntimeError("Initial administrator is not configured.")
    suffix = uuid4().hex[:10]

    with httpx.Client(base_url=settings.smoke_base_url, timeout=30) as client:
        token_response = client.post(
            "/api/v1/auth/token",
            data={
                "username": username,
                "password": password.get_secret_value(),
            },
        )
        token_response.raise_for_status()
        headers = {
            "Authorization": (
                f"Bearer {token_response.json()['access_token']}"
            )
        }

        project_response = client.post(
            "/api/v1/projects",
            headers=headers,
            json={
                "name": f"Smoke Test {suffix}",
                "slug": f"smoke-test-{suffix}",
                "description": "Automated disposable verification project.",
            },
        )
        project_response.raise_for_status()
        project = project_response.json()

        investigation_response = client.post(
            f"/api/v1/projects/{project['id']}/investigations",
            headers=headers,
            json={
                "title": f"Smoke Investigation {suffix}",
                "kind": "domain",
                "priority": "low",
            },
        )
        investigation_response.raise_for_status()
        investigation = investigation_response.json()
        assert investigation["operation_mode"] == "attack_surface"

        evidence_response = client.post(
            f"/api/v1/investigations/{investigation['id']}/evidence",
            headers=headers,
            json={
                "collector": "manual",
                "source_type": "smoke_test",
                "locator": f"urn:smoke:{suffix}",
                "kind": "note",
                "title": "Smoke evidence",
                "content": "Synthetic evidence created by the smoke test.",
                "raw_data": {"synthetic": True},
            },
        )
        evidence_response.raise_for_status()

        report_response = client.get(
            f"/api/v1/investigations/{investigation['id']}/report",
            headers=headers,
        )
        report_response.raise_for_status()
        report = report_response.json()
        assert len(report["evidence"]) == 1

        client.patch(
            f"/api/v1/investigations/{investigation['id']}",
            headers=headers,
            json={"status": "archived"},
        ).raise_for_status()
        client.patch(
            f"/api/v1/projects/{project['id']}",
            headers=headers,
            json={"status": "archived"},
        ).raise_for_status()

    print(
        "Smoke test passed: "
        f"project={project['id']} investigation={investigation['id']}"
    )


if __name__ == "__main__":
    main()
