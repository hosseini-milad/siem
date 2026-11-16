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
