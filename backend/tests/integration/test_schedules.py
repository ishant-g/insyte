"""Scheduled scans API: CRUD, validation, and owner isolation.

Uses the shared `client` (authenticated as tester@example.com) and
`anon_client` fixtures. A second account is registered inline for the
cross-owner tests.
"""

from __future__ import annotations

import uuid

from fastapi.testclient import TestClient


def _register(client: TestClient, email: str) -> str:
    resp = client.post(
        "/api/auth/register",
        json={"email": email, "password": "password123"},
    )
    assert resp.status_code == 201, resp.text
    return resp.json()["access_token"]


def _auth(token: str) -> dict:
    return {"Authorization": f"Bearer {token}"}


def test_create_schedule_returns_201(client: TestClient) -> None:
    resp = client.post(
        "/api/schedules",
        json={"target": "example.com", "interval_hours": 24},
    )
    assert resp.status_code == 201, resp.text
    body = resp.json()
    assert body["target"] == "example.com"
    assert body["mode"] == "passive"
    assert body["interval_hours"] == 24
    assert body["enabled"] is True
    assert body["next_run_at"]
    assert body["last_diff_summary"] == {}


def test_create_schedule_rejects_unknown_module(client: TestClient) -> None:
    resp = client.post(
        "/api/schedules",
        json={"target": "example.com", "modules": ["not_a_module"]},
    )
    assert resp.status_code == 422


def test_create_schedule_rejects_bad_target(client: TestClient) -> None:
    resp = client.post(
        "/api/schedules",
        json={"target": "not a domain"},
    )
    assert resp.status_code == 422


def test_create_schedule_rejects_bad_interval(client: TestClient) -> None:
    resp = client.post(
        "/api/schedules",
        json={"target": "example.com", "interval_hours": 0},
    )
    assert resp.status_code == 422


def test_schedule_owner_isolation(client: TestClient) -> None:
    token_b = _register(client, "second@example.com")

    created = client.post("/api/schedules", json={"target": "example.com"})
    schedule_id = created.json()["id"]

    # Another account reads it as "not found", never "forbidden".
    resp = client.get(f"/api/schedules/{schedule_id}", headers=_auth(token_b))
    assert resp.status_code == 404

    # ... and it does not appear in their list.
    resp = client.get("/api/schedules", headers=_auth(token_b))
    assert resp.status_code == 200
    assert resp.json()["total"] == 0

    # ... and they cannot delete or patch it.
    resp = client.delete(f"/api/schedules/{schedule_id}", headers=_auth(token_b))
    assert resp.status_code == 404
    resp = client.patch(
        f"/api/schedules/{schedule_id}",
        json={"enabled": False},
        headers=_auth(token_b),
    )
    assert resp.status_code == 404


def test_anon_schedule_access_denied(anon_client: TestClient) -> None:
    assert anon_client.get("/api/schedules").status_code == 401
    assert (
        anon_client.post("/api/schedules", json={"target": "example.com"}).status_code
        == 401
    )
    assert (
        anon_client.get(
            f"/api/schedules/{uuid.uuid4()}"
        ).status_code
        == 401
    )


def test_patch_schedule_toggles_enabled(client: TestClient) -> None:
    created = client.post("/api/schedules", json={"target": "example.com"})
    schedule_id = created.json()["id"]

    resp = client.patch(f"/api/schedules/{schedule_id}", json={"enabled": False})
    assert resp.status_code == 200
    assert resp.json()["enabled"] is False

    resp = client.patch(f"/api/schedules/{schedule_id}", json={"enabled": True})
    assert resp.status_code == 200
    assert resp.json()["enabled"] is True


def test_delete_schedule(client: TestClient) -> None:
    created = client.post("/api/schedules", json={"target": "example.com"})
    schedule_id = created.json()["id"]

    resp = client.delete(f"/api/schedules/{schedule_id}")
    assert resp.status_code == 204

    resp = client.get(f"/api/schedules/{schedule_id}")
    assert resp.status_code == 404
