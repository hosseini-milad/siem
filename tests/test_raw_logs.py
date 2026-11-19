import socket
from time import monotonic, sleep
from uuid import uuid4

from fastapi.testclient import TestClient
from pymongo import MongoClient

from app.core.config import Settings
from app.main import create_app


def test_udp_log_reaches_explorer(monkeypatch):
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as reservation:
        reservation.bind(("127.0.0.1", 0))
        port = reservation.getsockname()[1]

    monkeypatch.setenv("SIEM_RAW_LOG_PORT", str(port))
    settings = Settings(raw_log_host="127.0.0.1", mongodb_database=f"siem_test_{uuid4().hex}")
    message = "پیام خام UDP\nsecond line <log>"
    with MongoClient(settings.mongodb_uri, serverSelectionTimeoutMS=3000) as mongo:
        try:
            with TestClient(create_app(settings)) as client:
                with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sender:
                    sender.bind(("127.0.0.1", 0))
                    address = ("127.0.0.1", port)
                    sender.sendto(b" \n", address)
                    sender.sendto(message.encode(), address)
                    source_port = sender.getsockname()[1]

                deadline = monotonic() + 5
                while True:
                    response = client.get("/api/v1/explorer/records", params={"kind": "logs"})
                    assert response.status_code == 200
                    items = response.json()["items"]
                    if items or monotonic() >= deadline:
                        break
                    sleep(0.05)

                assert len(items) == 1
                row = items[0]
                assert row["message"] == message
                assert row["source_ip"] == "127.0.0.1"
                assert row["source_port"] == source_port
                assert row["protocol"] == "UDP"
                stored = client.get("/api/v1/logs/" + row["id"]).json()
                assert stored["message"] == message
                assert stored["level"] == "INFO"

            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as probe:
                probe.bind(("127.0.0.1", port))
        finally:
            mongo.drop_database(settings.mongodb_database)
