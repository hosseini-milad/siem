"""Streaming Sysmon normalization and evaluated LightGBM/CatBoost training."""
from collections import defaultdict
from datetime import datetime, timezone
from hashlib import sha256
from io import BytesIO
import json
import logging
import math
import os
import random
from tempfile import TemporaryDirectory
from time import monotonic
from zipfile import ZIP_DEFLATED, ZipFile
from threading import Lock

from catboost import CatBoostClassifier
from gridfs import GridFSBucket
import lightgbm as lgb
import numpy as np
from pymongo import ReplaceOne, UpdateOne
from sklearn.metrics import (accuracy_score, confusion_matrix, f1_score, log_loss,
                             precision_recall_fscore_support, precision_score,
                             recall_score, roc_auc_score)
from sklearn.model_selection import train_test_split

SOURCE = "system_log_dataset_records"
NORMAL = "system_log_dataset_normal"
NORMAL_RUNS = "system_log_normalization_runs"
TRAINING_RUNS = "system_log_training_runs"
MODELS = "system_log_models"
MODEL_FILES = "system_log_model_files"
AGENT_LOG_LABELS = "agent_logs_label"
NORMALIZATION_VERSION = 2
NORMAL_PARAMETERS = "system_log_normalization_parameters"
SCALER_ID = f"minmax-v{NORMALIZATION_VERSION}"
HASH_BUCKETS = 128
BATCH_SIZE = 500

LOGGER = logging.getLogger("uvicorn.error.siem.system_log_ml")
MISSING = {"", "-", "0", "0.0", "nan", "none", "null", "unknown"}

# output: (source aliases, transformation, scale)
NUMERIC = {
    "num_event_id": (("EventID", "event_id"), "linear", 255),
    "num_version": (("Version", "version"), "linear", 20),
    "num_level": (("Level", "level", "type"), "linear", 255),
    "num_task": (("Task", "task"), "linear", 255),
    "num_opcode": (("Opcode", "opcode"), "linear", 255),
    "num_event_record_id": (("EventRecordID", "record_number"), "log", 20),
    "num_execution_process_id": (("Execution_ProcessID",), "log", 20),
    "num_system_process_id": (("ProcessID",), "log", 20),
    "num_thread_id": (("ThreadID", "thread_id"), "log", 20),
    "num_process_id": (("ProcessId",), "log", 20),
    "num_parent_process_id": (("ParentProcessId",), "log", 20),
    "num_terminal_session_id": (("TerminalSessionId",), "log", 8),
    "num_source_port": (("SourcePort",), "linear", 65535),
    "num_destination_port": (("DestinationPort",), "linear", 65535),
    "num_source_process_id": (("SourceProcessId",), "log", 20),
    "num_source_thread_id": (("SourceThreadId",), "log", 20),
    "num_target_process_id": (("TargetProcessId",), "log", 20),
    "num_new_thread_id": (("NewThreadId",), "log", 20),
    "num_query_status": (("QueryStatus",), "log", 20),
    "num_schema_version": (("SchemaVersion",), "linear", 20),
}

BOOLEAN = {
    "flag_initiated": ("Initiated",),
    "flag_source_ipv6": ("SourceIsIpv6",),
    "flag_destination_ipv6": ("DestinationIsIpv6",),
    "flag_signed": ("Signed",),
    "flag_executable": ("IsExecutable",),
    "flag_archived": ("Archived",),
}

CATEGORICAL = {
    "provider": ("Name", "source"), "channel": ("Channel", "log", "channel"),
    "computer": ("Computer", "computer"), "user_id": ("UserID",), "rule": ("RuleName",),
    "guid": ("Guid",), "process_guid": ("ProcessGuid",), "image": ("Image",),
    "file_version": ("FileVersion",), "description": ("Description",), "product": ("Product",),
    "company": ("Company",), "original_file": ("OriginalFileName",),
    "command_line": ("CommandLine",), "current_directory": ("CurrentDirectory",),
    "user": ("User",), "logon_guid": ("LogonGuid",), "logon_id": ("LogonId",),
    "integrity": ("IntegrityLevel",), "hashes": ("Hashes",),
    "parent_process_guid": ("ParentProcessGuid",), "parent_image": ("ParentImage",),
    "parent_command_line": ("ParentCommandLine",), "parent_user": ("ParentUser",),
    "protocol": ("Protocol",), "source_ip": ("SourceIp",),
    "source_hostname": ("SourceHostname",), "source_port_name": ("SourcePortName",),
    "destination_ip": ("DestinationIp",), "destination_hostname": ("DestinationHostname",),
    "destination_port_name": ("DestinationPortName",), "state": ("State",),
    "configuration": ("Configuration",), "image_loaded": ("ImageLoaded",),
    "signature": ("Signature",), "signature_status": ("SignatureStatus",),
    "source_image": ("SourceImage",), "target_image": ("TargetImage",),
    "granted_access": ("GrantedAccess",), "call_trace": ("CallTrace",),
    "source_user": ("SourceUser",), "target_user": ("TargetUser",),
    "target_filename": ("TargetFilename",), "event_type": ("EventType",),
    "target_object": ("TargetObject",), "details": ("Details",), "pipe_name": ("PipeName",),
    "query_name": ("QueryName",), "query_results": ("QueryResults",),
    "start_address": ("StartAddress",), "start_module": ("StartModule",),
    "start_function": ("StartFunction",), "hash": ("Hash",), "contents": ("Contents",),
}

FEATURES = [*NUMERIC, *BOOLEAN, "time_hour_sin", "time_hour_cos",
            *(f"hash_{index:03}" for index in range(HASH_BUCKETS))]


def first(row, aliases):
    for name in aliases:
        if name in row and row[name] is not None:
            return row[name]
    return None


def text(value):
    if isinstance(value, (dict, list)):
        return ""
    return "" if value is None else str(value).strip()


def category_text(value):
    value = text(value)
    markers = ("Ã", "Â", "\x82", "\x83")
    for _ in range(6):
        if not any(marker in value for marker in markers):
            break
        try:
            repaired = value.encode("latin-1").decode("utf-8")
        except (UnicodeEncodeError, UnicodeDecodeError):
            break
        if repaired == value:
            break
        value = repaired
    return value


def finite_number(value):
    try:
        number = float(text(value))
    except (TypeError, ValueError, OverflowError):
        return None
    return number if math.isfinite(number) else None


def numeric(value, kind, scale):
    number = finite_number(value)
    if number is None or number <= 0:
        return 0.0
    if kind == "linear":
        return min(number / scale, 1.0)
    return min(math.log1p(number) / scale, 1.0)


def boolean(value):
    return float(text(value).casefold() in {"1", "true", "yes"})


def hour_features(value):
    value = text(value).replace("Z", "+00:00")
    try:
        parsed = datetime.fromisoformat(value)
    except ValueError:
        return 0.0, 0.0
    hour = parsed.hour + parsed.minute / 60 + parsed.second / 3600
    angle = 2 * math.pi * hour / 24
    return (math.sin(angle) + 1) / 2, (math.cos(angle) + 1) / 2


def minmax(value, bounds):
    number = finite_number(value)
    if number is None or bounds is None:
        return 0.0
    lower, upper = bounds
    if lower == upper or number <= lower:
        return 0.0
    if number >= upper:
        return 1.0
    if math.isinf(upper - lower):
        return (number / 2 - lower / 2) / (upper / 2 - lower / 2)
    return (number - lower) / (upper - lower)


def normalization_bounds(database, job_id):
    parameters = database[NORMAL_PARAMETERS]
    existing = parameters.find_one({"_id": SCALER_ID})
    if existing is not None:
        return existing["numeric_bounds"]

    projection = {alias: 1 for aliases, _, _ in NUMERIC.values() for alias in aliases}
    bounds = {}
    database[NORMAL_RUNS].update_one({"_id": job_id}, {"$set": {"phase": "fit_minmax"}})
    with database[SOURCE].find({}, projection).batch_size(BATCH_SIZE) as cursor:
        for scanned, row in enumerate(cursor, 1):
            for name, (aliases, _, _) in NUMERIC.items():
                value = finite_number(first(row, aliases))
                if value is not None:
                    lower, upper = bounds.get(name, (value, value))
                    bounds[name] = [min(lower, value), max(upper, value)]
            if scanned % 10000 == 0:
                database[NORMAL_RUNS].update_one({"_id": job_id}, {"$set": {
                    "fit_scanned": scanned, "heartbeat_at": datetime.now(timezone.utc),
                }})
    if not bounds:
        raise ValueError("The source collection has no usable numeric features")
    parameters.update_one({"_id": SCALER_ID}, {"$setOnInsert": {
        "version": NORMALIZATION_VERSION, "features": FEATURES, "numeric_bounds": bounds,
        "hash_buckets": HASH_BUCKETS, "updated_at": datetime.now(timezone.utc),
    }}, upsert=True)
    return parameters.find_one({"_id": SCALER_ID})["numeric_bounds"]


def normalize_row(row, require_label=True, bounds=None):
    label = text(row.get("Label"))
    missing_label = not label or label.casefold() in {"nan", "none", "null", "unknown", "unlabeled"}
    if require_label and missing_label:
        raise ValueError("Every source row requires a usable Label")
    identifier = row.get("_id")
    result = {"_id": identifier, "original_id": identifier,
              "normalization_version": 1 if bounds is None else NORMALIZATION_VERSION}
    if not missing_label:
        result["Label"] = label
    for output, (aliases, kind, scale) in NUMERIC.items():
        value = first(row, aliases)
        result[output] = (numeric(value, kind, scale) if bounds is None
                          else minmax(value, bounds.get(output)))
    for output, aliases in BOOLEAN.items():
        result[output] = boolean(first(row, aliases))
    result["time_hour_sin"], result["time_hour_cos"] = hour_features(
        first(row, ("SystemTime", "timestamp", "time")))
    buckets = defaultdict(int)
    for field, aliases in CATEGORICAL.items():
        value = category_text(first(row, aliases))
        if value.casefold() in MISSING:
            continue
        digest = sha256(f"{field}\0{value.casefold()}".encode("utf-8")).digest()
        buckets[int.from_bytes(digest[:4], "big") % HASH_BUCKETS] += 1
    for index, count in buckets.items():
        result[f"hash_{index:03}"] = min(count / 4, 1.0)
    return result


def normalize_dataset(database, job_id):
    processed = skipped = failed = 0
    try:
        total = database[SOURCE].estimated_document_count()
        database[NORMAL].create_index("original_id", unique=True)
        database[NORMAL].create_index([("normalization_version", 1), ("Label", 1)])
        database[NORMAL_RUNS].update_one({"_id": job_id}, {"$set": {
            "phase": "starting", "normalization_version": NORMALIZATION_VERSION, "total_estimate": total, "started_at": datetime.now(timezone.utc),
            "heartbeat_at": datetime.now(timezone.utc), "worker_pid": os.getpid(),
        }})
        bounds = normalization_bounds(database, job_id)
        database[NORMAL_RUNS].update_one({"_id": job_id}, {"$set": {"phase": "transform"}})
        batch = []
        reported = monotonic()

        def consume(rows):
            nonlocal processed, skipped, failed, reported
            identifiers = [row["_id"] for row in rows]
            existing = {row["_id"] for row in database[NORMAL].find({
                "_id": {"$in": identifiers}, "normalization_version": NORMALIZATION_VERSION}, {"_id": 1})}
            operations = []
            for row in rows:
                if row["_id"] in existing:
                    skipped += 1
                    continue
                try:
                    normalized = normalize_row(row, bounds=bounds)
                except ValueError:
                    failed += 1
                    continue
                operations.append(ReplaceOne({"_id": row["_id"]}, normalized, upsert=True))
            if operations:
                database[NORMAL].bulk_write(operations, ordered=False)
                processed += len(operations)
            now = datetime.now(timezone.utc)
            database[NORMAL_RUNS].update_one({"_id": job_id}, {"$set": {
                "processed": processed, "skipped": skipped, "failed": failed,
                "scanned": processed + skipped + failed, "heartbeat_at": now,
            }})
            if monotonic() - reported >= 5:
                LOGGER.info("System-log normalization %s scanned=%s/%s", job_id,
                            processed + skipped + failed, total)
                reported = monotonic()

        with database[SOURCE].find().batch_size(BATCH_SIZE) as cursor:
            for row in cursor:
                batch.append(row)
                if len(batch) == BATCH_SIZE:
                    consume(batch)
                    batch = []
        if batch:
            consume(batch)
        database[NORMAL_RUNS].update_one({"_id": job_id}, {"$set": {
            "status": "completed", "phase": "done", "processed": processed, "skipped": skipped,
            "failed": failed, "finished_at": datetime.now(timezone.utc),
        }})
    except Exception as exc:
        LOGGER.exception("System-log normalization %s failed", job_id)
        message = str(exc) if isinstance(exc, ValueError) else "System-log normalization failed; see server logs"
        database[NORMAL_RUNS].update_one({"_id": job_id}, {"$set": {
            "status": "failed", "error": message[:500], "processed": processed,
            "skipped": skipped, "failed": failed, "finished_at": datetime.now(timezone.utc),
        }})


def label_sort(value):
    try:
        return 0, float(value)
    except ValueError:
        return 1, value


def dataset_statistics(database, top_event_pairs):
    pipeline = [
        {"$project": {
            "label": {"$trim": {"input": {"$convert": {
                "input": "$Label", "to": "string", "onError": "", "onNull": "",
            }}}},
            "event_id": {"$convert": {
                "input": "$EventID", "to": "string", "onError": None, "onNull": None,
            }},
        }},
        {"$group": {"_id": {"label": "$label", "event_id": "$event_id"}, "count": {"$sum": 1}}},
        {"$facet": {
            "label_counts": [
                {"$group": {"_id": "$_id.label", "count": {"$sum": "$count"}}},
                {"$sort": {"count": -1, "_id": 1}},
                {"$project": {"_id": 0, "label": "$_id", "count": 1}},
            ],
            "top_label_events": [
                {"$sort": {"count": -1, "_id.label": 1, "_id.event_id": 1}},
                {"$limit": top_event_pairs},
                {"$project": {"_id": 0, "label": "$_id.label", "event_id": "$_id.event_id", "count": 1}},
            ],
        }},
    ]
    with database[SOURCE].aggregate(pipeline, allowDiskUse=True) as cursor:
        result = next(cursor)
    return {"total": sum(row["count"] for row in result["label_counts"]), **result}


def class_counts(database):
    rows = database[NORMAL].aggregate([
        {"$match": {"normalization_version": NORMALIZATION_VERSION}},
        {"$group": {"_id": "$Label", "count": {"$sum": 1}}},
        {"$sort": {"_id": 1}},
    ], allowDiskUse=True)
    return {str(row["_id"]): row["count"] for row in rows}


def sample_training_rows(database, max_records, random_seed, progress=None):
    counts = class_counts(database)
    if len(counts) < 2:
        raise ValueError("At least two distinct labels are required")
    labels = sorted(counts, key=label_sort)
    per_class = min(min(counts.values()), max_records // len(labels))
    if per_class < 20:
        raise ValueError("At least 20 normalized records per label are required")
    projection = {name: 1 for name in FEATURES} | {"Label": 1, "original_id": 1}
    values = np.empty((per_class * len(labels), len(FEATURES)), dtype=np.float32)
    targets = np.repeat(np.arange(len(labels), dtype=np.int32), per_class)
    scanned = 0
    for class_index, label in enumerate(labels):
        seed = random_seed + int.from_bytes(sha256(label.encode()).digest()[:4], "big")
        rng = random.Random(seed)
        start = class_index * per_class
        seen = 0
        with database[NORMAL].find({
            "normalization_version": NORMALIZATION_VERSION, "Label": label}, projection).batch_size(1000) as cursor:
            for index, row in enumerate(cursor):
                slot = index if index < per_class else rng.randrange(index + 1)
                if slot < per_class:
                    values[start + slot] = [row.get(name, 0.0) for name in FEATURES]
                seen += 1
                scanned += 1
                if progress and scanned % 10000 == 0:
                    progress(scanned, counts, per_class)
        if seen < per_class:
            raise ValueError("Normalized records changed during training sampling")
    if progress:
        progress(scanned, counts, per_class)
    validate_matrix(values)
    return values, targets, labels, counts, per_class


def validate_matrix(result):
    if result.ndim != 2 or result.shape[1] != len(FEATURES) or not np.isfinite(result).all():
        raise ValueError("Normalized features must be a finite numeric matrix")
    if (result < 0).any() or (result > 1).any():
        raise ValueError("Normalized features must remain between zero and one")


def matrix(rows):
    result = np.asarray([[row.get(name, 0.0) for name in FEATURES] for row in rows], dtype=np.float32)
    validate_matrix(result)
    return result


def probabilities(model, values, classes):
    method = getattr(model, "predict_proba", None)
    predicted = np.asarray(method(values) if method else model.predict(values), dtype=np.float64)
    if predicted.ndim == 1:
        predicted = np.column_stack([1 - predicted, predicted])
    if predicted.shape[1] != classes:
        raise ValueError("Model probability columns do not match labels")
    return np.clip(predicted, 1e-12, 1 - 1e-12)


def evaluation(labels, predicted_probabilities, class_names):
    predicted = predicted_probabilities.argmax(axis=1)
    precision, recall, f1, support = precision_recall_fscore_support(
        labels, predicted, labels=list(range(len(class_names))), zero_division=0)
    report = {
        "accuracy": float(accuracy_score(labels, predicted)),
        "precision_macro": float(precision_score(labels, predicted, average="macro", zero_division=0)),
        "recall_macro": float(recall_score(labels, predicted, average="macro", zero_division=0)),
        "f1_macro": float(f1_score(labels, predicted, average="macro", zero_division=0)),
        "log_loss": float(log_loss(labels, predicted_probabilities, labels=list(range(len(class_names))))),
        "confusion_matrix": confusion_matrix(labels, predicted, labels=list(range(len(class_names)))).tolist(),
        "per_class": [{"label": name, "precision": float(precision[index]),
                       "recall": float(recall[index]), "f1": float(f1[index]),
                       "support": int(support[index])} for index, name in enumerate(class_names)],
    }
    try:
        if len(class_names) == 2:
            report["roc_auc"] = float(roc_auc_score(labels, predicted_probabilities[:, 1]))
        else:
            report["roc_auc_ovr_macro"] = float(roc_auc_score(
                labels, predicted_probabilities, multi_class="ovr", average="macro"))
    except ValueError:
        pass
    return report


def normalized_importance(values):
    values = np.asarray(values, dtype=np.float64)
    total = values.sum()
    return values / total if total > 0 else np.zeros_like(values)


def model_package(light, cat, manifest):
    output = BytesIO()
    with TemporaryDirectory() as directory:
        cat_path = os.path.join(directory, "catboost.cbm")
        cat.save_model(cat_path)
        with ZipFile(output, "w", compression=ZIP_DEFLATED) as archive:
            archive.writestr("lightgbm.txt", light.model_to_string())
            archive.write(cat_path, "catboost.cbm")
            archive.writestr("manifest.json", json.dumps(manifest, ensure_ascii=False, allow_nan=False))
    return output.getvalue()


class SystemLogPredictor:
    def __init__(self, model_id, manifest, light, cat):
        self.model_id = model_id
        self.manifest = manifest
        self.light = light
        self.cat = cat

    def standardize(self, records):
        bounds = self.manifest.get("numeric_bounds")
        return matrix([normalize_row(row, require_label=False, bounds=bounds) for row in records])

    def predict(self, records):
        if not records:
            return []
        return self.predict_features(records, self.standardize(records))

    def predict_features(self, records, values):
        classes = len(self.manifest["labels"])
        light_values = probabilities(self.light, values, classes)
        cat_values = probabilities(self.cat, values, classes)
        weight = self.manifest["ensemble"]["lightgbm_weight"]
        combined = weight * light_values + (1 - weight) * cat_values
        labels = self.manifest["labels"]
        return [{
            "original_id": row.get("_id"), "predicted_label": labels[int(values.argmax())],
            "prediction_confidence": float(values.max()),
            "label_probabilities": [{"label": label, "probability": float(values[index])}
                                    for index, label in enumerate(labels)],
            "model_id": self.model_id,
        } for row, values in zip(records, combined)]


def predictor_from_package(model_id, package):
    with ZipFile(BytesIO(package)) as archive:
        manifest = json.loads(archive.read("manifest.json"))
        light = lgb.Booster(model_str=archive.read("lightgbm.txt").decode("utf-8"))
        cat_bytes = archive.read("catboost.cbm")
    with TemporaryDirectory() as directory:
        path = os.path.join(directory, "catboost.cbm")
        with open(path, "wb") as stream:
            stream.write(cat_bytes)
        cat = CatBoostClassifier()
        cat.load_model(path)
    return SystemLogPredictor(model_id, manifest, light, cat)


class SystemLogModelManager:
    def __init__(self):
        self.active = None
        self.lock = Lock()

    def require(self):
        with self.lock:
            predictor = self.active
        if predictor is None:
            raise LookupError("No accepted system-log model is active")
        return predictor

    def publish(self, predictor):
        with self.lock:
            self.active = predictor

    def load(self, database):
        model = database[MODELS].find_one({"active": True}, sort=[("created_at", -1)])
        if model is None:
            return False
        output = BytesIO()
        GridFSBucket(database, bucket_name=MODEL_FILES).download_to_stream(model["artifact_file_id"], output)
        self.publish(predictor_from_package(model["_id"], output.getvalue()))
        return True


def predict_and_store(database, manager, records):
    try:
        predictor = manager.require()
    except LookupError:
        return []
    predictions = []
    for start in range(0, len(records), BATCH_SIZE):
        batch = records[start:start + BATCH_SIZE]
        features = predictor.standardize(batch)
        items = predictor.predict_features(batch, features)
        predicted_at = datetime.now(timezone.utc)
        labeled_writes = []
        raw_writes = []
        for record, values, item in zip(batch, features, items):
            identifier = record["_id"]
            prediction = {
                key: item[key] for key in (
                    "predicted_label", "prediction_confidence", "label_probabilities", "model_id")
            }
            prediction["predicted_at"] = predicted_at
            labeled = {
                "_id": identifier, "original_id": identifier, "agent_id": record["agent_id"],
                "timestamp": record["timestamp"], "received_at": record["received_at"],
                "normalization_version": predictor.manifest["normalization_version"],
                "features": dict(zip(FEATURES, values.tolist())),
                **prediction,
            }
            labeled_writes.append(ReplaceOne({"_id": identifier}, labeled, upsert=True))
            raw_writes.append(UpdateOne({"_id": identifier}, {"$set": prediction}))
        database[AGENT_LOG_LABELS].bulk_write(labeled_writes, ordered=False)
        database.agent_logs.bulk_write(raw_writes, ordered=False)
        predictions.extend(items)
    return predictions


def train_models(database, job_id, max_records, rounds, random_seed, threads=2, manager=None):
    artifact_file_id = None
    try:
        database[TRAINING_RUNS].update_one({"_id": job_id}, {"$set": {
            "phase": "sampling", "started_at": datetime.now(timezone.utc), "worker_pid": os.getpid(),
        }})

        def progress(scanned, counts, per_class):
            database[TRAINING_RUNS].update_one({"_id": job_id}, {"$set": {
                "scanned": scanned, "class_counts": counts, "sample_per_class": per_class,
                "heartbeat_at": datetime.now(timezone.utc),
            }})

        parameters = database[NORMAL_PARAMETERS].find_one({"_id": SCALER_ID})
        completed = database[NORMAL_RUNS].find_one({
            "status": "completed", "normalization_version": NORMALIZATION_VERSION,
        }, {"_id": 1})
        if parameters is None or completed is None:
            raise ValueError("Run Sysmon normalization before training")
        values, targets, class_names, counts, per_class = sample_training_rows(
            database, max_records, random_seed, progress)
        x_train_valid, x_test, y_train_valid, y_test = train_test_split(
            values, targets, test_size=0.2, random_state=random_seed, stratify=targets)
        x_train, x_validation, y_train, y_validation = train_test_split(
            x_train_valid, y_train_valid, test_size=0.2, random_state=random_seed, stratify=y_train_valid)
        classes = len(class_names)
        database[TRAINING_RUNS].update_one({"_id": job_id}, {"$set": {
            "phase": "training", "sampled": len(targets), "labels": class_names,
            "split": {"train": len(y_train), "validation": len(y_validation), "test": len(y_test)},
        }})
        objective = "binary" if classes == 2 else "multiclass"
        params = {
            "objective": objective, "metric": "binary_logloss" if classes == 2 else "multi_logloss",
            "learning_rate": 0.05, "num_leaves": 63, "feature_fraction": 0.85,
            "bagging_fraction": 0.85, "bagging_freq": 1, "verbosity": -1,
            "seed": random_seed, "num_threads": threads,
        }
        if classes > 2:
            params["num_class"] = classes
        light = lgb.train(params, lgb.Dataset(x_train, label=y_train), num_boost_round=rounds,
                          valid_sets=[lgb.Dataset(x_validation, label=y_validation)],
                          callbacks=[lgb.early_stopping(max(5, min(30, rounds // 5)), verbose=False)])
        cat = CatBoostClassifier(
            iterations=rounds, depth=8, learning_rate=0.05,
            loss_function="Logloss" if classes == 2 else "MultiClass",
            random_seed=random_seed, thread_count=threads, verbose=False, allow_writing_files=False,
        )
        cat.fit(x_train, y_train, eval_set=(x_validation, y_validation),
                early_stopping_rounds=max(5, min(30, rounds // 5)), verbose=False)
        light_validation = probabilities(light, x_validation, classes)
        cat_validation = probabilities(cat, x_validation, classes)
        candidates = []
        for weight in np.linspace(0, 1, 11):
            combined = weight * light_validation + (1 - weight) * cat_validation
            candidates.append((float(log_loss(y_validation, combined,
                                               labels=list(range(classes)))), float(weight)))
        validation_loss, light_weight = min(candidates, key=lambda item: (item[0], abs(item[1] - 0.5)))
        light_test = probabilities(light, x_test, classes)
        cat_test = probabilities(cat, x_test, classes)
        ensemble_test = light_weight * light_test + (1 - light_weight) * cat_test
        reports = {
            "lightgbm": evaluation(y_test, light_test, class_names),
            "catboost": evaluation(y_test, cat_test, class_names),
            "ensemble": evaluation(y_test, ensemble_test, class_names),
        }
        light_importance = normalized_importance(light.feature_importance("gain"))
        cat_importance = normalized_importance(cat.get_feature_importance())
        combined_importance = light_weight * light_importance + (1 - light_weight) * cat_importance
        weights = [{"feature": feature, "weight": float(combined_importance[index]),
                    "lightgbm": float(light_importance[index]), "catboost": float(cat_importance[index])}
                   for index, feature in enumerate(FEATURES)]
        weights.sort(key=lambda item: item["weight"], reverse=True)
        baseline = 1 / classes
        accepted = reports["ensemble"]["accuracy"] > baseline and reports["ensemble"]["f1_macro"] > baseline
        manifest = {
            "version": 1, "normalization_version": NORMALIZATION_VERSION,
            "features": FEATURES, "labels": class_names,
            "numeric_bounds": parameters["numeric_bounds"],
            "ensemble": {"lightgbm_weight": light_weight, "catboost_weight": 1 - light_weight},
        }
        package = model_package(light, cat, manifest)
        bucket = GridFSBucket(database, bucket_name=MODEL_FILES)
        artifact_file_id = bucket.upload_from_stream(
            f"{job_id}.zip", BytesIO(package), metadata={"model_id": job_id, "kind": "system-log"})
        model = {
            "_id": job_id, "active": False, "algorithm": "LightGBM + CatBoost",
            "normalization_version": NORMALIZATION_VERSION, "features": FEATURES, "labels": class_names,
            "feature_weights": weights, "evaluation": reports,
            "ensemble": {"lightgbm_weight": light_weight, "catboost_weight": 1 - light_weight,
                         "validation_log_loss": validation_loss},
            "source": {"collection": NORMAL, "scaler_id": SCALER_ID, "class_counts": counts,
                       "sample_per_class": per_class, "sampled": len(targets)},
            "split": {"train": len(y_train), "validation": len(y_validation), "test": len(y_test)},
            "acceptance": {"accepted": accepted, "baseline_accuracy": baseline,
                           "policy": "ensemble accuracy and macro-F1 must exceed balanced random baseline"},
            "artifact_file_id": artifact_file_id, "artifact_bytes": len(package),
            "created_at": datetime.now(timezone.utc), "random_seed": random_seed, "rounds": rounds,
        }
        database[MODELS].insert_one(model)
        if accepted:
            database[MODELS].update_many({"_id": {"$ne": job_id}, "active": True},
                                         {"$set": {"active": False}})
            database[MODELS].update_one({"_id": job_id}, {"$set": {"active": True}})
            if manager is not None:
                manager.publish(SystemLogPredictor(job_id, manifest, light, cat))
        status = "completed" if accepted else "rejected"
        database[TRAINING_RUNS].update_one({"_id": job_id}, {"$set": {
            "status": status, "phase": "done" if accepted else "quality_gate",
            "model_id": job_id, "evaluation": reports, "feature_weights": weights,
            "ensemble": model["ensemble"], "acceptance": model["acceptance"],
            "finished_at": datetime.now(timezone.utc),
        }})
    except Exception as exc:
        LOGGER.exception("System-log training %s failed", job_id)
        if artifact_file_id is not None:
            try:
                GridFSBucket(database, bucket_name=MODEL_FILES).delete(artifact_file_id)
            except Exception:
                LOGGER.exception("Could not remove failed system-log model artifact %s", artifact_file_id)
        message = str(exc) if isinstance(exc, ValueError) else "System-log training failed; see server logs"
        database[TRAINING_RUNS].update_one({"_id": job_id}, {"$set": {
            "status": "failed", "error": message[:500], "finished_at": datetime.now(timezone.utc),
        }})
