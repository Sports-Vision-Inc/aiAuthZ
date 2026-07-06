from __future__ import annotations


def _admin(fixtures):
    return {"Authorization": f"Bearer {fixtures['admin_token']}"}


def test_get_workspace_policy(client, fixtures):
    r = client.get(
        "/v1/policy",
        params={"scope": "workspace", "id": fixtures["workspace_id"]},
        headers=_admin(fixtures),
    )
    assert r.status_code == 200
    assert "tools" in r.json()


def test_set_user_policy_overrides(client, fixtures):
    r = client.put(
        "/v1/policy",
        json={
            "scope_type": "user",
            "scope_id": fixtures["member"]["id"],
            "policy_yaml": "tools:\n  shell: [member]\ndefault: deny\n",
        },
        headers=_admin(fixtures),
    )
    assert r.status_code == 200
    r2 = client.get(
        "/v1/policy",
        params={"scope": "user", "id": fixtures["member"]["id"]},
        headers=_admin(fixtures),
    )
    assert "member" in r2.json()["tools"]["shell"]


def test_apply_template(client, fixtures):
    r = client.post(
        "/v1/policy/from-template",
        json={
            "template": "open_team",
            "scope_type": "workspace",
            "scope_id": fixtures["workspace_id"],
        },
        headers=_admin(fixtures),
    )
    assert r.status_code == 200


def test_audit_listing(client, fixtures):
    r = client.get("/v1/audit/decisions", headers=_admin(fixtures))
    assert r.status_code == 200
    assert isinstance(r.json(), list)


def test_admin_can_create_org_team_workspace(client, fixtures):
    r = client.post(
        "/v1/admin/orgs", json={"name": "another"}, headers=_admin(fixtures),
    )
    assert r.status_code == 200
    org_id = r.json()["id"]
    r2 = client.post(
        "/v1/admin/teams", json={"org_id": org_id, "name": "t2"}, headers=_admin(fixtures),
    )
    assert r2.status_code == 200
    team_id = r2.json()["id"]
    r3 = client.post(
        "/v1/admin/workspaces", json={"team_id": team_id, "name": "w2"}, headers=_admin(fixtures),
    )
    assert r3.status_code == 200


def test_enroll_then_revoke(client, fixtures):
    r = client.post(
        "/v1/auth/enroll",
        json={"workspace_id": fixtures["workspace_id"], "email": "n@t.co", "role": "member"},
        headers=_admin(fixtures),
    )
    assert r.status_code == 200
    user_id = r.json()["user_id"]
    assert r.json()["hmac_key"]
    r2 = client.post("/v1/auth/revoke", json={"user_id": user_id}, headers=_admin(fixtures))
    assert r2.status_code == 200


def test_dash_summary(client, fixtures):
    r = client.get("/v1/dash/summary", headers=_admin(fixtures))
    assert r.status_code == 200
    assert "counts" in r.json()
