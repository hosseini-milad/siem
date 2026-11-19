import gzip
import json
from uuid import uuid4

import pytest
from fastapi.testclient import TestClient
from pymongo import MongoClient

from app.core.config import Settings
from app.main import create_app


@pytest.fixture
def setup(tmp_path):
    folder = tmp_path / "Labelled LMD-2023"
    folder.mkdir()
    config = Settings(system_log_datasets_root=str(tmp_path), mongodb_database="siem_test_" + uuid4().hex)
    mongo = MongoClient(config.mongodb_uri)
    try:
        with TestClient(create_app(config)) as client:
            yield client, folder, mongo[config.mongodb_database]
    finally:
        mongo.drop_database(config.mongodb_database)
        mongo.close()


def import_status(client, path):
    response = client.post("/api/v1/system-log-datasets/imports", json={"path": path})
    assert response.status_code == 202, response.text
    return client.get("/api/v1/system-log-datasets/imports/" + response.json()["id"]).json()


def test_imports_supported_formats_and_preserves_root_fields(setup):
    client, folder, database = setup
    (folder / "events.csv").write_text("event_id,message\n1,first\n2,دوم\n", encoding="utf-8")
    (folder / "array.json").write_text(json.dumps([
        {"event_id": 3, "nested": {"host.name": "pc-1"}},
        {"event_id": 4, "tags": ["system", "sample"]},
    ]), encoding="utf-8")
    (folder / "events.jsonl").write_text('{"event_id":5,"severity":"low"}\n', encoding="utf-8")
    (folder / "agent.log").write_text("line one\nline two\n", encoding="utf-8")
    (folder / "extra.ndjson.gz").write_bytes(gzip.compress(b'{"event_id":6,"compressed":true}\n'))

    status = import_status(client, str(folder))
    assert status["status"] == "completed", status
    assert status["file_count"] == 5
    assert status["completed_files"] == 5
    assert status["processed"] == 8
    assert status["inserted"] == 8

    rows = client.get("/api/v1/system-log-datasets/records", params={"limit": 100}).json()
    assert rows["total"] == 8
    assert database.system_log_dataset_records.count_documents({}) == 8
    csv_row = database.system_log_dataset_records.find_one({"event_id": "2"})
    assert csv_row["message"] == "دوم"
    assert csv_row["_import"]["format"] == "csv"
    json_row = database.system_log_dataset_records.find_one({"event_id": 3})
    assert json_row["nested"]["host_name"] == "pc-1"
    assert database.system_log_dataset_records.count_documents({"raw_message": {"$exists": True}}) == 2

    repeated = import_status(client, "Labelled LMD-2023")
    assert repeated["status"] == "completed"
    assert repeated["inserted"] == 0
    assert repeated["processed"] == 8
    assert database.system_log_dataset_records.count_documents({}) == 8


def test_streams_json_across_read_boundaries(setup):
    client, folder, database = setup
    long_message = "x" * 70000
    (folder / "large.json").write_text(json.dumps([
        {"event_id": 10, "message": long_message}, {"event_id": 11, "message": "after boundary"},
    ]), encoding="utf-8")
    status = import_status(client, str(folder / "large.json"))
    assert status["status"] == "completed", status
    assert status["processed"] == 2
    assert database.system_log_dataset_records.find_one({"event_id": 10})["message"] == long_message


def test_csv_empty_and_duplicate_headers_are_root_fields(setup):
    client, folder, database = setup
    (folder / "headers.csv").write_text(
        ",event_id,event_id,   \nrow-index,100,duplicate-value,trailing-value\n", encoding="utf-8")

    status = import_status(client, str(folder / "headers.csv"))
    assert status["status"] == "completed", status
    row = database.system_log_dataset_records.find_one()
    assert row["unnamed_column_1"] == "row-index"
    assert row["event_id"] == "100"
    assert row["event_id_2"] == "duplicate-value"
    assert row["unnamed_column_4"] == "trailing-value"
    assert "record" not in row
    assert row["_import"]["format"] == "csv"


def test_rejects_outside_missing_and_invalid_paths(setup, tmp_path):
    client, folder, database = setup
    (folder / "valid.jsonl").write_text('{"ok":true}\n', encoding="utf-8")
    outside = tmp_path.parent / ("outside_" + uuid4().hex + ".jsonl")
    outside.write_text('{"outside":true}\n', encoding="utf-8")
    try:
        for path in ("../" + outside.name, str(outside), "missing"):
            response = client.post("/api/v1/system-log-datasets/imports", json={"path": path})
            assert response.status_code == 422
    finally:
        outside.unlink()
    assert database.system_log_dataset_records.count_documents({}) == 0


def test_invalid_json_fails_job_and_busy_or_missing_root_are_reported(setup):
    client, folder, database = setup
    (folder / "bad.json").write_text('[{"event_id":1}', encoding="utf-8")
    status = import_status(client, str(folder))
    assert status["status"] == "failed"
    assert "closing bracket" in status["error"]
    assert database.system_log_dataset_records.count_documents({}) == 0

    client.app.state.import_lock.acquire()
    try:
        assert client.post("/api/v1/system-log-datasets/imports", json={"path": str(folder)}).status_code == 409
    finally:
        client.app.state.import_lock.release()
    client.app.state.settings.system_log_datasets_root = str(folder / "absent")
    assert client.post("/api/v1/system-log-datasets/imports", json={"path": str(folder)}).status_code == 503


def test_mongo_reserved_keys_are_safe_and_collisions_fail(setup):
    client, folder, database = setup
    (folder / "safe.jsonl").write_text(
        '{"_id":"source","_import":"source metadata","$kind":"event","a.b":1}\n', encoding="utf-8")
    status = import_status(client, str(folder))
    assert status["status"] == "completed", status
    row = database.system_log_dataset_records.find_one()
    assert row["source_id"] == "source"
    assert row["source__import"] == "source metadata"
    assert row["_kind"] == "event"
    assert row["a_b"] == 1

    (folder / "collision.jsonl").write_text('{"a.b":1,"a_b":2}\n', encoding="utf-8")
    status = import_status(client, str(folder / "collision.jsonl"))
    assert status["status"] == "failed"
    assert "collide" in status["error"]
