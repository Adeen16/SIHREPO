from fastapi.testclient import TestClient
from fastapi_app.main import app

client = TestClient(app)

def test_health():
    response = client.get("/health")
    assert response.status_code == 200
    assert response.json() == {"status": "ok", "version": "1.0"}

def test_metrics():
    response = client.get("/metrics")
    assert response.status_code == 200
    assert "packets_per_sec" in response.json()
