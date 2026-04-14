import sys
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "backend"))

from fastapi.testclient import TestClient

from narip.main import app


def test_workforce_role_aware_assessment() -> None:
    client = TestClient(app)
    client.post(
        "/v1/workforce/profiles",
        json={
            "employee_id": "e-1",
            "email": "user@company.com",
            "display_name": "Sam",
            "department": "Logistics",
            "role_title": "Shipping Coordinator",
            "last_training_completed_at": "2024-01-01T00:00:00Z",
        },
    )
    r = client.post(
        "/v1/workforce/phishing/assess",
        json={
            "employee_id": "e-1",
            "email": {
                "message_id": "m1",
                "sender": "tracking@carrier-fake.com",
                "subject": "Shipment on hold — customs fee",
                "body_text": "Your container is delayed. Pay customs via this DHL portal.",
                "urls": ["https://fake-dhl.example/track"],
            },
        },
    )
    assert r.status_code == 200
    data = r.json()
    assert data["role_cluster"] == "logistics"
    assert 0 <= data["training_gap_score"] <= 100
    assert data["phishing_probability"] >= 0


def test_simulation_updates_dashboard() -> None:
    client = TestClient(app)
    client.post(
        "/v1/workforce/profiles",
        json={
            "employee_id": "e-2",
            "email": "fin@company.com",
            "department": "Finance",
            "role_title": "AP Clerk",
        },
    )
    for _ in range(3):
        client.post(
            "/v1/workforce/phishing/simulation",
            json={
                "employee_id": "e-2",
                "campaign_id": "c1",
                "clicked_link": True,
                "submitted_credentials": False,
                "reported_phish": False,
            },
        )
    s = client.get("/v1/workforce/dashboard/summary").json()
    assert s["total_profiles"] >= 2
    assert "avg_training_gap" in s
