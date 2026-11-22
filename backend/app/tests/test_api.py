import pytest
from fastapi.testclient import TestClient
from ..main import app

client = TestClient(app)

def test_health_endpoint():
    response = client.get("/api/v1/health")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "online"
    assert "database_engine" in data

def test_audit_endpoint_weak_password():
    payload = {
        "password": "123",
        "username": "admin",
        "email": "admin@local.host",
        "first_name": "System",
        "last_name": "Admin",
        "organization": "Security Ltd",
        "mode": "BASIC"
    }
    response = client.post("/api/v1/audit", json=payload)
    assert response.status_code == 200
    data = response.json()
    
    # Assert score is low and risk is critical
    assert data["security_score"] < 30
    assert data["risk_level"] == "CRITICAL"
    assert data["dictionary_matched"] is True
    assert len(data["patterns_detected"]) > 0
    assert "xai_explanation" in data
    assert len(data["recommendations"]) > 0

def test_audit_endpoint_strong_password():
    payload = {
        "password": "K3p#9!mQ$8vT_5rWz",
        "username": "user",
        "email": "user@mail.com",
        "mode": "ADVANCED"
    }
    response = client.post("/api/v1/audit", json=payload)
    assert response.status_code == 200
    data = response.json()
    
    # Assert strong password features
    assert data["security_score"] >= 80
    assert data["risk_level"] in ["LOW", "SECURE"]
    assert data["dictionary_matched"] is False
    assert len(data["patterns_detected"]) == 0

def test_compare_endpoint():
    payload = {
        "passwords": ["123", "password", "K3p#9!mQ$8vT_5rWz"],
        "username": "admin"
    }
    response = client.post("/api/v1/compare", json=payload)
    assert response.status_code == 200
    data = response.json()
    
    assert "comparisons" in data
    comps = data["comparisons"]
    assert len(comps) == 3
    
    # The passwords should be ranked: strong password first (rank 1), weak ones last
    assert comps[0]["rank"] == 1
    assert comps[0]["password"] == "K3p#9!mQ$8vT_5rWz"
    assert comps[2]["rank"] == 3
