import time
from uuid import uuid4

import httpx

from app.core.settings import settings


def main():
    project_id = investigation_id = None
    headers = None
    suffix = uuid4().hex[:8]
    with httpx.Client(base_url=settings.smoke_base_url, timeout=30) as client:
        try:
            token = client.post("/api/v1/auth/token", data={
                "username": settings.initial_admin_username,
                "password": settings.initial_admin_password.get_secret_value(),
            })
            token.raise_for_status()
            headers = {"Authorization": f"Bearer {token.json()['access_token']}"}
            project = client.post("/api/v1/projects", headers=headers, json={
                "name": f"Chat Smoke {suffix}", "slug": f"chat-smoke-{suffix}",
            })
            project.raise_for_status()
            project_id = project.json()["id"]
            investigation = client.post(f"/api/v1/projects/{project_id}/investigations", headers=headers,
                                        json={"title": "Authorized public chat verification",
                                              "kind": "domain", "priority": "low",
                                              "jurisdiction": "Synthetic test environment",
                                              "legal_basis": "Authorized verification of the IANA reserved example.com domain.",
                                              "data_classification": "internal"})
            investigation.raise_for_status()
            investigation_id = investigation.json()["id"]
            path = f"/api/v1/investigations/{investigation_id}/chat"
            clarification = client.post(path, headers=headers, json={"prompt": "hola"})
            clarification.raise_for_status()
            assert clarification.json()["run"] is None
            unauthorized = client.post(path, headers=headers, json={"prompt": "Investiga example.com"})
            unauthorized.raise_for_status()
            assert unauthorized.json()["run"] is None
            accepted = client.post(path, headers=headers, json={
                "prompt": "Investiga DNS y registro público de example.com", "authorization_confirmed": True,
            })
            accepted.raise_for_status()
            run = accepted.json()["run"]
            assert run["profile"] == "auto" and run["allow_active"] is False
            assert run["max_tools"] <= 12 and run["follow_discoveries"] is False
            assert run["policy"]["chat"]["decisions"]
            deadline = time.monotonic() + settings.llm_timeout_seconds + 240
            while run["status"] not in {"succeeded", "partial", "failed"}:
                if time.monotonic() > deadline:
                    raise RuntimeError("Chat search timed out; inspect the run before archiving the case.")
                time.sleep(2)
                current = client.get(f"/api/v1/search-runs/{run['id']}", headers=headers)
                current.raise_for_status()
                run = current.json()
            assert run["status"] in {"succeeded", "partial"}
            assert run["result_summary"]["evidence_ids"]
            # A follow-up retains context without executing another batch when consent is absent.
            followup = client.post(path, headers=headers, json={
                "prompt": "Ahora revisa su reputación", "parent_run_id": run["id"],
            })
            followup.raise_for_status()
            assert followup.json()["analysis_type"] == "Reputación e indicadores"
            assert followup.json()["run"] is None
            print(f"Chat API smoke passed: run={run['id']} status={run['status']} "
                  f"planner={run['planner']} evidence={len(run['result_summary']['evidence_ids'])}")
        finally:
            # Archive only a completed disposable test case; never an active process.
            if headers and investigation_id:
                runs = client.get(f"/api/v1/investigations/{investigation_id}/search-runs", headers=headers)
                runs.raise_for_status()
                if not any(item["status"] in {"queued", "running"} for item in runs.json()):
                    client.patch(f"/api/v1/investigations/{investigation_id}", headers=headers,
                                 json={"status": "archived"}).raise_for_status()
                    if project_id:
                        client.patch(f"/api/v1/projects/{project_id}", headers=headers,
                                     json={"status": "archived"}).raise_for_status()
            elif headers and project_id:
                client.patch(f"/api/v1/projects/{project_id}", headers=headers,
                             json={"status": "archived"}).raise_for_status()


if __name__ == "__main__":
    main()
