import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "backend"))

from fastapi.testclient import TestClient

from narip.main import app


def test_falcon_ingest_scores_and_case() -> None:
    client = TestClient(app)
    body = {
        "metadata": {
            "eventType": "DetectionSummaryEvent",
            "eventCreationTime": 1_710_000_000_000,
        },
        "event": {
            "ComputerName": "CORP-WKS-01",
            "UserName": "jsmith",
            "CommandLine": "powershell.exe -enc JABBA",
            "FileName": "powershell.exe",
            "Severity": 85,
            "DetectName": "Suspicious PowerShell",
            "RemoteAddress": "203.0.113.50",
            "LocalIP": "10.0.0.14",
            "RemotePort": 443,
            "BytesSent": 120000,
        },
    }
    r = client.post("/v1/ingest/falcon/event", json=body)
    assert r.status_code == 200
    data = r.json()
    assert "unified" in data
    assert data.get("case_id")
    assert data["canonical"]["vendor"] == "crowdstrike_falcon"


def test_splunk_hec_without_token() -> None:
    client = TestClient(app)
    body = {
        "sourcetype": "cim:endpoint:process",
        "event": {
            "dest_nt_host": "srv-db-1",
            "user": "dbadmin",
            "CommandLine": "psexec \\\\finance-dc cmd",
            "process_name": "psexec.exe",
            "src_ip": "10.2.2.2",
            "dest_ip": "10.3.3.3",
            "dst_port": 445,
        },
    }
    r = client.post("/v1/ingest/splunk/hec", json=body)
    assert r.status_code == 200
    assert r.json()["canonical"]["vendor"] == "splunk_cim"


def test_automation_cases_list() -> None:
    client = TestClient(app)
    r = client.get("/v1/automation/cases")
    assert r.status_code == 200
    assert isinstance(r.json(), list)


def test_threat_intel_load() -> None:
    client = TestClient(app)
    r = client.post(
        "/v1/threat-intel/indicators",
        json={"indicators": [{"type": "IPv4", "indicator": "192.0.2.10"}]},
    )
    assert r.status_code == 200
    assert r.json().get("loaded") == 1
