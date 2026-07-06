def test_healthz(client):
    r = client.get("/healthz")
    assert r.status_code == 200
    assert r.json() == {"status": "ok"}


def test_readyz(client):
    r = client.get("/readyz")
    assert r.status_code == 200


def test_version(client):
    r = client.get("/v1/version")
    assert r.status_code == 200
    assert "version" in r.json()


def test_capabilities(client):
    r = client.get("/v1/capabilities")
    assert r.status_code == 200
    body = r.json()
    assert "tools" in body
    assert "shell" in body["tools"]
    assert "mcp" in body["adapters"]
