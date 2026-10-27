"""Auth and per-account credential API contract tests."""

from __future__ import annotations

from fastapi.testclient import TestClient


def _register(client: TestClient, email: str, password: str = "password123") -> str:
    resp = client.post("/api/auth/register", json={"email": email, "password": password})
    assert resp.status_code == 201, resp.text
    return resp.json()["access_token"]


def test_protected_route_requires_auth(anon_client: TestClient) -> None:
    assert anon_client.get("/api/scans").status_code == 401
    assert anon_client.get("/api/credentials").status_code == 401


def test_register_login_me(anon_client: TestClient) -> None:
    token = _register(anon_client, "alice@example.com")
    # duplicate registration is a conflict
    dup = anon_client.post(
        "/api/auth/register", json={"email": "alice@example.com", "password": "password123"}
    )
    assert dup.status_code == 409

    login = anon_client.post(
        "/api/auth/login", json={"email": "alice@example.com", "password": "password123"}
    )
    assert login.status_code == 200
    assert login.json()["user"]["email"] == "alice@example.com"

    bad = anon_client.post(
        "/api/auth/login", json={"email": "alice@example.com", "password": "wrong"}
    )
    assert bad.status_code == 400

    me = anon_client.get("/api/auth/me", headers={"Authorization": f"Bearer {token}"})
    assert me.status_code == 200 and me.json()["email"] == "alice@example.com"


def test_credentials_crud_and_masking(anon_client: TestClient) -> None:
    token = _register(anon_client, "bob@example.com")
    h = {"Authorization": f"Bearer {token}"}

    listed = anon_client.get("/api/credentials", headers=h).json()["providers"]
    shodan = next(p for p in listed if p["provider_id"] == "shodan")
    assert shodan["configured"] is False and shodan["user_configured"] is False

    # set a key
    resp = anon_client.put(
        "/api/credentials/shodan", headers=h, json={"fields": {"api_key": "SHODANKEY123"}}
    )
    assert resp.status_code == 200
    shodan = next(p for p in resp.json()["providers"] if p["provider_id"] == "shodan")
    assert shodan["user_configured"] and shodan["configured"]
    assert shodan["fields"][0]["hint"].startswith("••••")
    # the raw value is never echoed back anywhere in the response
    assert "SHODANKEY123" not in resp.text

    # two-part provider
    anon_client.put(
        "/api/credentials/censys", headers=h,
        json={"fields": {"api_id": "cid", "api_secret": "csec"}},
    )
    listed = anon_client.get("/api/credentials", headers=h).json()["providers"]
    censys = next(p for p in listed if p["provider_id"] == "censys")
    assert censys["configured"]

    # delete
    anon_client.delete("/api/credentials/shodan", headers=h)
    listed = anon_client.get("/api/credentials", headers=h).json()["providers"]
    shodan = next(p for p in listed if p["provider_id"] == "shodan")
    assert shodan["user_configured"] is False

    # unknown provider / field
    assert anon_client.put("/api/credentials/nope", headers=h, json={"fields": {}}).status_code == 404
    assert (
        anon_client.put(
            "/api/credentials/shodan", headers=h, json={"fields": {"bogus": "x"}}
        ).status_code
        == 400
    )


def test_scans_are_scoped_per_account(anon_client: TestClient, monkeypatch) -> None:
    # Don't actually run the scan — this test only cares about ownership
    # scoping, so the Celery dispatch is stubbed to a no-op.
    from app.services.scan.service import ScanService

    monkeypatch.setattr(ScanService, "_dispatch", lambda self, scan: None)

    t1 = _register(anon_client, "owner@example.com")
    r = anon_client.post(
        "/api/scans", headers={"Authorization": f"Bearer {t1}"},
        json={"target": "example.com", "mode": "passive"},
    )
    assert r.status_code == 201, r.text
    scan_id = r.json()["id"]

    # a different account cannot see it
    t2 = _register(anon_client, "other@example.com")
    h2 = {"Authorization": f"Bearer {t2}"}
    assert anon_client.get(f"/api/scans/{scan_id}", headers=h2).status_code == 404
    assert anon_client.get("/api/scans", headers=h2).json()["total"] == 0

    # the owner can
    h1 = {"Authorization": f"Bearer {t1}"}
    assert anon_client.get(f"/api/scans/{scan_id}", headers=h1).status_code == 200
    assert anon_client.get("/api/scans", headers=h1).json()["total"] == 1
