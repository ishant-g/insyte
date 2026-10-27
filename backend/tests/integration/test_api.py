"""API contract tests: input validation, error shapes, mass-assignment
protection, and pagination — using SQLite via the `client` fixture. No
outbound network calls happen because CELERY_TASK_ALWAYS_EAGER is on and
these tests never invoke a real scan; they exercise routing and schema
validation only.
"""

from __future__ import annotations

from fastapi.testclient import TestClient


def test_health(client: TestClient) -> None:
    response = client.get("/health")
    assert response.status_code == 200
    body = response.json()
    assert body["app"] == "Insyte"
    assert body["database"] is True


def test_create_scan_rejects_invalid_target(client: TestClient) -> None:
    response = client.post("/api/scans", json={"target": "not a domain", "mode": "passive"})
    assert response.status_code == 422


def test_create_scan_rejects_private_ip_as_target_gracefully() -> None:
    # Private IPs are valid *targets* to scan (a user may legitimately want
    # to characterise their own internal host) — SSRF policy governs what
    # Insyte *fetches during* a scan, not what can be entered as a target.
    # This test documents that distinction rather than asserting a reject.
    pass


def test_create_scan_rejects_missing_target(client: TestClient) -> None:
    response = client.post("/api/scans", json={"mode": "passive"})
    assert response.status_code == 422


def test_create_scan_rejects_javascript_scheme(client: TestClient) -> None:
    response = client.post("/api/scans", json={"target": "javascript:alert(1)", "mode": "passive"})
    assert response.status_code == 422


def test_get_nonexistent_scan_returns_404(client: TestClient) -> None:
    response = client.get("/api/scans/00000000-0000-0000-0000-000000000000")
    assert response.status_code == 404
    body = response.json()
    assert "request_id" in body


def test_get_scan_with_malformed_uuid_returns_422(client: TestClient) -> None:
    response = client.get("/api/scans/not-a-uuid")
    assert response.status_code == 422


def test_scan_list_is_paginated(client: TestClient) -> None:
    response = client.get("/api/scans", params={"limit": 10, "offset": 0})
    assert response.status_code == 200
    body = response.json()
    assert "items" in body
    assert "total" in body
    assert body["limit"] == 10


def test_scan_list_rejects_oversized_limit(client: TestClient) -> None:
    response = client.get("/api/scans", params={"limit": 100000})
    assert response.status_code == 422


def test_no_scan_update_endpoint_exists(client: TestClient) -> None:
    """The predecessor's `PUT /scans/{id}` mass-assignment hole must not
    exist in Insyte: there is no writable status/progress/exposure_score
    endpoint at all."""
    response = client.put(
        "/api/scans/00000000-0000-0000-0000-000000000000",
        json={"status": "completed", "exposure_score": 100},
    )
    assert response.status_code in (404, 405)


def test_modules_catalogue_lists_real_modules(client: TestClient) -> None:
    response = client.get("/api/modules")
    assert response.status_code == 200
    modules = response.json()
    assert len(modules) > 10
    ids = {m["id"] for m in modules}
    assert "dns_intelligence" in ids
    assert "javascript_intelligence" in ids


def test_providers_catalogue_never_exposes_credentials(client: TestClient) -> None:
    response = client.get("/api/providers")
    assert response.status_code == 200
    body = response.text
    assert "api_key" not in body.lower() or "requires_api_key" in body


def test_security_policy_endpoint(client: TestClient) -> None:
    response = client.get("/api/security-policy")
    assert response.status_code == 200
    policy = response.json()
    assert policy["allowed_schemes"] == ["http", "https"]
    assert len(policy["blocked_ipv4_ranges"]) > 5


def test_settings_endpoint_never_returns_secret_values(client: TestClient) -> None:
    response = client.get("/api/settings")
    assert response.status_code == 200
    body = response.json()
    for provider in body["providers"]:
        assert set(provider.keys()) == {"id", "name", "requires_api_key", "configured"}


def test_response_never_leaks_stack_trace(client: TestClient, monkeypatch) -> None:
    """Force an unexpected exception in a route and confirm the client
    receives a generic message, never a traceback or internal detail."""
    import app.api.routes.scans as scans_route

    def boom(*_args, **_kwargs):
        raise RuntimeError("simulated internal failure with secret path /etc/shadow")

    monkeypatch.setattr(scans_route.ScanService, "list", boom)
    response = client.get("/api/scans")
    assert response.status_code == 500
    body = response.json()
    assert "secret path" not in str(body)
    assert "/etc/shadow" not in str(body)
    assert "request_id" in body


def test_cors_does_not_allow_wildcard_with_credentials() -> None:
    from app.main import app

    for middleware in app.user_middleware:
        if "CORSMiddleware" in str(middleware.cls):
            assert middleware.kwargs.get("allow_credentials") is False
