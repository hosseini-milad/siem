from uuid import uuid4

import pytest
from fastapi.testclient import TestClient
from pymongo import MongoClient

from app.core.config import Settings
from app.main import create_app


@pytest.fixture
def client():
    settings = Settings(mongodb_database=f"siem_test_{uuid4().hex}")
    mongo = MongoClient(settings.mongodb_uri, serverSelectionTimeoutMS=3000)
    try:
        with TestClient(create_app(settings)) as test_client:
            yield test_client
    finally:
        mongo.drop_database(settings.mongodb_database)
        mongo.close()


def event(**changes):
    return {"timestamp": "2026-11-16T13:30:00+03:30", "source": "firewall-01",
            "level": "WARNING", "message": "Connection denied",
            "attributes": {"source_ip": "192.0.2.10", "port": 22}, **changes}


def test_storage_and_readback(client):
    response = client.post("/api/v1/logs", json=event())
    assert response.status_code == 201
    row = response.json()
    assert row["timestamp"] == "2026-11-16T10:00:00Z"
    assert row["attributes"]["port"] == 22
    assert row["received_at"].endswith("Z")
    assert client.get(f'/api/v1/logs/{row["id"]}').json() == row
    # Verify the actual MongoDB document, rather than only echoing the POST body.
    stored = client.app.state.database.log_events.find_one({"_id": row["id"]})
    assert stored["message"] == row["message"]
    assert client.get(f"/api/v1/logs/{uuid4()}").status_code == 404
    assert client.get("/api/v1/logs/not-an-id").status_code == 422


def test_http_logs_accept_raw_syslog_and_json(client):
    response = client.post("/logs", content="<132>1 - router firewall - - - HTTP log",
                           headers={"Content-Type": "text/plain; charset=utf-8"})
    assert response.status_code == 201
    row = response.json()
    assert row["message"] == "HTTP log"
    assert row["level"] == "WARNING"
    assert row["attributes"]["transport"] == "HTTP"
    assert row["attributes"]["syslog_host"] == "router"
    assert client.get(f"/api/v1/logs/{row['id']}").json() == row
    assert client.post("/logs", json=event()).status_code == 201
    assert client.post("/logs", content=b"\xff").status_code == 422
    assert client.post("/logs", content=b"x" * (2 * 1024 * 1024 + 1)).status_code == 413
    assert client.get("/logs").status_code == 405


def test_http_logs_accept_agent_json_payloads(client):
    payload = {
        "hostname": "windows-server", "collected_at": "2026-11-19T10:17:16+03:30",
        "severity": "WARN", "logs": [{"channel": "Application", "event_id": 1001}],
        "metrics": {"cpu_percent": 18.5},
    }
    response = client.post("/logs", json=payload)
    assert response.status_code == 201
    row = response.json()
    assert row["source"] == "windows-server"
    assert row["timestamp"] == "2026-11-19T06:47:16Z"
    assert row["level"] == "WARNING"
    assert row["message"] == "Agent payload with 1 log(s)"
    assert row["attributes"]["agent_payload"] == payload
    assert row["attributes"]["transport"] == "HTTP"

    batch = [{"message": "first"}, {"message": "second"}]
    row = client.post("/logs", json=batch).json()
    assert row["message"] == "Agent JSON batch with 2 item(s)"
    assert row["attributes"]["agent_payload"] == batch

    unusual = client.post("/logs", json={"message": "event", "severity": "notice",
                                         "timestamp": "local time"}).json()
    assert unusual["level"] == "INFO"
    assert unusual["attributes"]["agent_level"] == "notice"
    assert unusual["attributes"]["agent_timestamp"] == "local time"


def test_agent_payload_creates_system_metrics_events_and_change_history(client):
    payload = {
        "agent_id": "DESKTOP-88EQ9K3", "timestamp": "2026-11-19T11:52:23.190071",
        "metrics": {"cpu_percent": 4.18, "memory_percent": 66.3, "memory_used_mb": 10777.1,
                    "disk_read_bytes_per_sec": 62400.39, "disk_write_bytes_per_sec": 179017.51,
                    "net_sent_bytes_per_sec": 1391.98, "net_recv_bytes_per_sec": 2512.19},
        "logs": [{"log": "System", "record_number": 28766,
                  "time": "2026-11-19T08:21:18.434923+00:00", "source": "Service Control Manager",
                  "event_id": 7045, "type": 2, "message": "A service changed"}],
        "system_info": {"hostname": "DESKTOP-88EQ9K3", "os_name": "Windows", "os_release": "10",
                        "os_version": "10.0.19045", "architecture": "AMD64",
                        "processor": "Intel CPU", "cpu_cores_physical": 4, "cpu_cores_logical": 8,
                        "total_ram_gb": 15.89, "total_disk_c_gb": 159.88,
                        "mac_address": "78:24:AF:CB:1B:FD"},
    }
    assert client.post("/logs", json=payload).status_code == 201
    database = client.app.state.database
    stored = database.agent_payloads.find_one({"agent_id": payload["agent_id"]})
    assert stored["cpu_percent"] == 4.18
    assert stored["memory_percent"] == 66.3
    assert stored["hostname"] == "DESKTOP-88EQ9K3"
    assert stored["mac"] == "78:24:af:cb:1b:fd"
    assert stored["logs"][0]["event_id"] == 7045
    assert stored["system_info"]["mac_address"] == "78:24:AF:CB:1B:FD"

    mac = "78:24:af:cb:1b:fd"
    system = database.systems.find_one(mac)
    assert system["hostname"] == payload["agent_id"]
    assert system["cpu_percent"] == 4.18
    event_row = database.log_events.find_one({"attributes.agent_id": payload["agent_id"],
                                               "attributes.event_id": 7045})
    assert event_row["source"] == payload["agent_id"]
    assert event_row["level"] == "WARNING"
    assert event_row["timestamp"].isoformat() == "2026-11-19T08:21:18.434000+00:00"

    changed = {**payload, "logs": [], "metrics": {**payload["metrics"], "cpu_percent": 21.5},
               "system_info": {**payload["system_info"], "processor": "New CPU"}}
    assert client.post("/logs", json=changed).status_code == 201
    assert database.systems.find_one(mac)["processor"] == "New CPU"
    history = database.system_changes.find_one({"system_id": mac})
    assert history["changes"]["processor"] == {"before": "Intel CPU", "after": "New CPU"}

    metrics_only = {"agent_id": payload["agent_id"], "metrics": {"cpu_percent": 9.25}, "logs": []}
    assert client.post("/logs", json=metrics_only).status_code == 201
    assert database.systems.find_one(mac)["cpu_percent"] == 9.25
    assert database.agent_payloads.index_information()["received_at_1"]["expireAfterSeconds"] == 604800


def test_existing_agent_wrapper_bootstraps_system(client):
    from datetime import datetime, timezone
    from app.services.agent_ingestion import bootstrap_systems

    database = client.app.state.database
    payload = {"agent_id": "legacy-agent", "metrics": {"cpu_percent": 12.5}, "logs": [],
               "system_info": {"hostname": "legacy-agent", "mac_address": "00-11-22-33-44-55"}}
    database.log_events.insert_one({
        "_id": "legacy-wrapper", "received_at": datetime.now(timezone.utc),
        "attributes": {"agent_payload": payload, "source_ip": "192.0.2.40", "source_port": 8080},
    })
    bootstrap_systems(database)
    system = database.systems.find_one("00:11:22:33:44:55")
    assert system["agent_id"] == "legacy-agent" and system["cpu_percent"] == 12.5
    bootstrap_systems(database)
    assert database.systems.count_documents({"agent_id": "legacy-agent"}) == 1


def test_http_log_token_is_limited_to_ingestion(client, monkeypatch):
    from pydantic import SecretStr

    settings = client.app.state.settings
    monkeypatch.setattr(settings, "auth_required", True)
    monkeypatch.setattr(settings, "http_log_token", SecretStr("test-ingestion-token"))
    assert client.post("/logs", content="no token").status_code == 401
    assert client.post("/logs", content="invalid", headers={"Authorization": "Bearer invalid"}).status_code == 401
    headers = {"Authorization": "Bearer test-ingestion-token"}
    assert client.post("/logs", content="valid", headers=headers).status_code == 201
    assert client.get("/api/v1/logs", headers=headers).status_code == 401


def test_batch_filter_and_pagination(client):
    response = client.post("/api/v1/logs/batch", json={"events": [event(), event(source="router", level="INFO")]})
    assert response.status_code == 201
    result = client.get("/api/v1/logs", params={"source": "firewall-01", "level": "WARNING",
                        "start": "2026-11-16T10:00:00Z", "end": "2026-11-16T10:00:00Z"}).json()
    assert result["total"] == len(result["items"]) == 1
    assert result["items"][0]["source"] == "firewall-01"
    page = client.get("/api/v1/logs?limit=1&offset=1").json()
    assert page["total"] == 2 and len(page["items"]) == 1
    assert client.get("/api/v1/logs?source=missing").json()["total"] == 0
    assert client.get("/api/v1/logs?limit=0").status_code == 422
    assert client.get("/api/v1/logs?start=2026-11-17T00:00:00Z&end=2026-11-16T00:00:00Z").status_code == 422


@pytest.mark.parametrize("changes", [{"source": " "}, {"message": ""}, {"level": "INVALID"},
                                    {"timestamp": "2026-11-16T10:00:00"}, {"unknown": True}])
def test_invalid_event_not_stored(client, changes):
    assert client.post("/api/v1/logs", json=event(**changes)).status_code == 422
    assert client.get("/api/v1/logs").json()["total"] == 0


def test_invalid_batch_not_stored(client):
    for events in [[], [event(), event(source="")], [event()] * 501]:
        assert client.post("/api/v1/logs/batch", json={"events": events}).status_code == 422
    assert client.get("/api/v1/logs").json()["total"] == 0


def test_docs_and_health(client):
    assert client.get("/docs").status_code == 200
    schema = client.get("/openapi.json").json()
    assert "/api/v1/logs/batch" in schema["paths"]
    assert client.get("/api/v1/health").json() == {"status": "ok", "database": "mongodb"}


def test_timestamp_precision_and_invalid_bson(client):
    r = client.post("/api/v1/logs", json=event(timestamp="2026-11-16T10:00:00.123456Z"))
    assert r.status_code == 201
    assert client.get('/api/v1/logs/' + r.json()['id']).json() == r.json()
    for attributes in [{"number": 2 ** 100}, {"bad\u0000key": "x"}]:
        assert client.post("/api/v1/logs", json=event(attributes=attributes)).status_code == 422


def test_database_failure_returns_503(client):
    from pymongo.errors import ServerSelectionTimeoutError
    from app.db.session import get_database

    def unavailable():
        raise ServerSelectionTimeoutError("internal connection details")

    client.app.dependency_overrides[get_database] = unavailable
    response = client.get("/api/v1/logs")
    assert response.status_code == 503
    assert "internal connection details" not in response.text
