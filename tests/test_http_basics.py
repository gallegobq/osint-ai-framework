from fastapi.testclient import TestClient

from app.core.application import create_app


def test_liveness_and_security_headers() -> None:
    with TestClient(create_app()) as client:
        response = client.get("/api/v1/health")

    assert response.status_code == 200
    assert response.json()["status"] == "ok"
    assert response.headers["x-content-type-options"] == "nosniff"
    assert response.headers["x-frame-options"] == "DENY"
    assert response.headers["x-request-id"]


def test_prometheus_metrics_are_exposed() -> None:
    with TestClient(create_app()) as client:
        client.get("/api/v1/health")
        response = client.get("/api/v1/metrics")

    assert response.status_code == 200
    assert "osint_http_requests_total" in response.text


def test_local_frontend_is_served_with_its_assets() -> None:
    with TestClient(create_app()) as client:
        page = client.get("/")
        script = client.get("/app.js")
        stylesheet = client.get("/styles.css")

    assert page.status_code == 200
    assert "Linterna — OSINT local" in page.text
    assert "Detectar automáticamente" in page.text
    assert "Superficie de ataque" in page.text
    assert "Pentesting autorizado" in page.text
    assert script.status_code == 200
    assert script.headers["content-type"].startswith("text/javascript")
    assert "const targets = targetType ?" in script.text
    assert "max_tools: 40" in script.text
    assert "operation_mode: operationMode" in script.text
    assert stylesheet.status_code == 200
    assert stylesheet.headers["content-type"].startswith("text/css")
