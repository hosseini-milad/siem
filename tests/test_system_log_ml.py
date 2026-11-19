from uuid import uuid4

from fastapi.testclient import TestClient
from pymongo import MongoClient
import pytest

from app.core.config import Settings
from app.main import create_app
from app.services.system_log_ml import (FEATURES, NORMALIZATION_VERSION, SystemLogModelManager,
                                        category_text, normalize_row)


@pytest.fixture
def setup(tmp_path):
    config = Settings(mongodb_database="siem_test_" + uuid4().hex,
                      ml_model_dir=str(tmp_path / "models"), ml_threads=2)
    mongo = MongoClient(config.mongodb_uri)
    try:
        with TestClient(create_app(config)) as client:
            yield client, mongo[config.mongodb_database]
    finally:
        mongo.drop_database(config.mongodb_database)
        mongo.close()


def source_rows(per_class=60):
    rows = []
    values = {
        "0": (1, "C:\\Windows\\System32\\svchost.exe", "tcp"),
        "1": (3, "C:\\Users\\Public\\malware.exe", "udp"),
        "2": (13, "C:\\Windows\\System32\\services.exe", "registry"),
    }
    for label, (event_id, image, protocol) in values.items():
        for index in range(per_class):
            rows.append({
                "_id": f"{label}-{index:04}", "Label": label,
                "SystemTime": f"2023-12-{index % 28 + 1:02} 02:19:07",
                "EventID": str(event_id), "Level": "4", "Channel": "Microsoft-Windows-Sysmon/Operational",
                "Name": "Microsoft-Windows-Sysmon", "Computer": f"host-{index % 4}",
                "ProcessId": str(1000 + index), "Image": image, "Protocol": protocol,
                "DestinationPort": "443" if label == "0" else ("53" if label == "1" else "0"),
                "RuleName": "-" if label == "0" else f"rule-{label}",
                "_import": {"file": "sample.csv", "record_number": index + 1},
                "unnamed_column_1": str(index),
            })
    rows.append({"_id": "missing-label", "EventID": "1"})
    return rows


def run_status(client, start_path, status_path, body=None):
    response = client.post(start_path, json=body) if body is not None else client.post(start_path)
    assert response.status_code == 202, response.text
    result = client.get(status_path + response.json()["id"])
    assert result.status_code == 200
    return result.json()


def test_system_log_normalization_is_incremental_and_agent_compatible(setup):
    client, database = setup
    database.system_log_dataset_records.insert_many(source_rows())
    status = run_status(client, "/api/v1/system-log-ml/normalization/runs",
                        "/api/v1/system-log-ml/normalization/runs/")
    assert status["status"] == "completed", status
    assert status["processed"] == 180 and status["failed"] == 1 and status["skipped"] == 0
    assert database.system_log_dataset_normal.count_documents({}) == 180
    row = database.system_log_dataset_normal.find_one({"original_id": "2-0000"})
    assert row["Label"] == "2" and row["normalization_version"] == NORMALIZATION_VERSION
    assert 0 < row["num_event_id"] <= 1 and 0 <= row["num_process_id"] <= 1
    assert "Image" not in row and "_import" not in row and "unnamed_column_1" not in row
    assert all(0 <= value <= 1 for key, value in row.items() if key in FEATURES)

    repeated = run_status(client, "/api/v1/system-log-ml/normalization/runs",
                          "/api/v1/system-log-ml/normalization/runs/")
    assert repeated["processed"] == 0 and repeated["skipped"] == 180 and repeated["failed"] == 1
    labels = client.get("/api/v1/system-log-ml/labels").json()["counts"]
    assert labels == {"0": 60, "1": 60, "2": 60}

    dataset = normalize_row({"_id": "dataset", "Label": "0", "EventID": "3",
                             "Channel": "Microsoft-Windows-Sysmon/Operational",
                             "Name": "Microsoft-Windows-Sysmon", "Computer": "host",
                             "SystemTime": "2023-12-08T02:19:07", "Image": "test.exe"})
    agent = normalize_row({"_id": "agent", "event_id": 3,
                           "log": "Microsoft-Windows-Sysmon/Operational",
                           "source": "Microsoft-Windows-Sysmon", "computer": "host",
                           "timestamp": "2023-12-08T02:19:07", "Image": "test.exe"}, require_label=False)
    assert [dataset.get(name, 0) for name in FEATURES] == [agent.get(name, 0) for name in FEATURES]
    assert category_text("MicrosoftÃÂ® Windows") == "Microsoft® Windows"


def test_training_stores_feature_weights_evaluation_and_model_artifact(setup):
    client, database = setup
    database.system_log_dataset_records.insert_many(source_rows(per_class=50)[:-1])
    normalized = run_status(client, "/api/v1/system-log-ml/normalization/runs",
                            "/api/v1/system-log-ml/normalization/runs/")
    assert normalized["status"] == "completed", normalized

    trained = run_status(client, "/api/v1/system-log-ml/training/runs",
                         "/api/v1/system-log-ml/training/runs/",
                         {"max_records": 150, "rounds": 20, "random_seed": 7})
    assert trained["status"] == "completed", trained
    assert trained["acceptance"]["accepted"] is True
    assert trained["evaluation"]["ensemble"]["accuracy"] > 0.9
    assert len(trained["evaluation"]["ensemble"]["confusion_matrix"]) == 3
    assert len(trained["feature_weights"]) == len(FEATURES)
    assert trained["feature_weights"][0]["weight"] > 0

    model = client.get("/api/v1/system-log-ml/models/current")
    assert model.status_code == 200, model.text
    metadata = model.json()
    assert metadata["labels"] == ["0", "1", "2"]
    assert metadata["active"] is True and metadata["artifact_bytes"] > 0
    assert isinstance(metadata["artifact_file_id"], str)
    assert database.system_log_models.count_documents({"active": True}) == 1
    assert database.system_log_model_files.files.count_documents({}) == 1
    assert database.system_log_model_files.chunks.count_documents({}) >= 1

    raw = {"_id": "manual", "event_id": 13, "log": "Microsoft-Windows-Sysmon/Operational",
           "source": "Microsoft-Windows-Sysmon", "computer": "host-1",
           "timestamp": "2026-11-19T12:00:00+00:00", "Image": "C:\\Windows\\System32\\services.exe",
           "Protocol": "registry", "RuleName": "rule-2"}
    prediction = client.post("/api/v1/system-log-ml/predict", json={"records": [raw]})
    assert prediction.status_code == 200, prediction.text
    assert prediction.json()["items"][0]["predicted_label"] == "2"

    reloaded = SystemLogModelManager()
    assert reloaded.load(database) is True
    assert reloaded.require().predict([raw])[0]["predicted_label"] == "2"

    payload = {
        "agent_id": "host-1", "logs": [{
            "log": "Microsoft-Windows-Sysmon/Operational", "record_number": 500,
            "time": "2026-11-19T12:00:00+00:00", "source": "Microsoft-Windows-Sysmon",
            "event_id": 13, "type": 4, "computer": "host-1", "message": "Registry value set",
            "event_data": {"Image": "C:\\Windows\\System32\\services.exe",
                           "Protocol": "registry", "RuleName": "rule-2"},
        }],
    }
    receipt = client.post("/logs", json=payload)
    assert receipt.status_code == 201, receipt.text
    scored = database.agent_logs.find_one({"record_number": 500})
    assert scored["predicted_label"] == "2" and scored["model_id"] == metadata["_id"]
    assert 0 <= scored["prediction_confidence"] <= 1
    assert len(scored["label_probabilities"]) == 3
