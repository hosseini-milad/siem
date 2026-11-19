import socket
from time import monotonic, sleep
from uuid import uuid4

import pytest
from fastapi.testclient import TestClient
from pymongo import MongoClient

from app.core.config import Settings
from app.main import create_app


@pytest.mark.parametrize(("datagram", "message", "level", "parsed"), [
    ("پیام خام UDP\nsecond line <log>", "پیام خام UDP\nsecond line <log>", "INFO", {}),
    ("<34>1 2026-11-18T20:00:00+03:30 router firewall 42 ID47 [meta zone=\"edge\"] Access denied",
     "Access denied", "CRITICAL", {
         "syslog_format": "rfc5424", "syslog_facility": 4, "syslog_severity": 2,
         "syslog_host": "router", "syslog_app": "firewall", "syslog_pid": "42",
         "syslog_msgid": "ID47", "syslog_structured_data": '[meta zone="edge"]',
     }),
    ("<132>Nov  9 12:34:56 router agent[12]: Legacy warning", "Legacy warning", "WARNING", {
        "syslog_format": "rfc3164", "syslog_timestamp": "Nov  9 12:34:56",
        "syslog_host": "router", "syslog_app": "agent", "syslog_pid": "12",
    }),
    ("<192>1 - host app - - - invalid priority", "<192>1 - host app - - - invalid priority", "INFO", {}),
    ("<13>1 2026-11-19T04:00:00 host app - - - missing timezone",
     "<13>1 2026-11-19T04:00:00 host app - - - missing timezone", "INFO", {}),
])
def test_udp_log_reaches_explorer(monkeypatch, datagram, message, level, parsed):
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as reservation:
        reservation.bind(("127.0.0.1", 0))
        port = reservation.getsockname()[1]

    monkeypatch.setenv("SIEM_RAW_LOG_PORT", str(port))
    settings = Settings(raw_log_host="127.0.0.1", mongodb_database=f"siem_test_{uuid4().hex}")
    with MongoClient(settings.mongodb_uri, serverSelectionTimeoutMS=3000) as mongo:
        try:
            with TestClient(create_app(settings)) as client:
                with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sender:
                    sender.bind(("127.0.0.1", 0))
                    address = ("127.0.0.1", port)
                    sender.sendto(b" \n", address)
                    sender.sendto(datagram.encode(), address)
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
                assert stored["level"] == level
                attributes = stored["attributes"]
                if parsed:
                    assert attributes["raw_message"] == datagram
                    assert {key: attributes[key] for key in parsed} == parsed
                else:
                    assert "syslog_format" not in attributes
                if parsed.get("syslog_format") == "rfc5424":
                    assert stored["timestamp"] == "2026-11-18T16:30:00Z"
                index = mongo[settings.mongodb_database].log_events.index_information()["received_at_1"]
                assert index["key"] == [("received_at", 1)]
                assert index["expireAfterSeconds"] == 604800

            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as probe:
                probe.bind(("127.0.0.1", port))
        finally:
            mongo.drop_database(settings.mongodb_database)
