from datetime import datetime, timezone
from hashlib import sha256
from ipaddress import ip_address
import json
import re
from uuid import uuid4

from pymongo import ReplaceOne
from pymongo.errors import DuplicateKeyError

from app.schemas.log import LogCreate, LogLevel

PAYLOADS = "agent_payloads"
AGENT_LOGS = "agent_logs"
SYSTEM_METRICS = "system_metrics"
SYSTEMS = "systems"
SYSTEM_CHANGES = "system_changes"
SYSTEM_INFO_FIELDS = (
    "hostname", "os_name", "os_release", "os_version", "architecture", "processor",
    "cpu_cores_physical", "cpu_cores_logical", "total_ram_gb", "total_disk_c_gb",
)
METRIC_FIELDS = (
    "cpu_percent", "memory_percent", "memory_used_mb", "disk_percent",
    "disk_read_bytes_per_sec", "disk_write_bytes_per_sec", "net_sent_bytes_per_sec",
    "net_recv_bytes_per_sec",
)
WINDOWS_LEVELS = {
    1: LogLevel.ERROR, 2: LogLevel.WARNING, 4: LogLevel.INFO,
    8: LogLevel.INFO, 16: LogLevel.WARNING,
}


def normalize_mac(value):
    if not isinstance(value, str):
        return None
    digits = re.sub(r"[:-]", "", value).lower()
    if not re.fullmatch(r"[0-9a-f]{12}", digits):
        return None
    return ":".join(digits[index:index + 2] for index in range(0, 12, 2))


def aware_timestamp(value, fallback):
    if not isinstance(value, str):
        return fallback
    try:
        parsed = datetime.fromisoformat(value)
    except (ValueError, OverflowError):
        return fallback
    return parsed.astimezone(timezone.utc) if parsed.utcoffset() is not None else fallback


def payload_document(payload, source_ip, source_port, received_at):
    agent_id = str(payload.get("agent_id") or payload.get("hostname") or source_ip)[:255]
    metrics = payload.get("metrics") if isinstance(payload.get("metrics"), dict) else {}
    system_info = payload.get("system_info") if isinstance(payload.get("system_info"), dict) else {}
    logs = payload.get("logs") if isinstance(payload.get("logs"), list) else []
    agent_timestamp = next((payload.get(key) for key in
                            ("timestamp", "collected_at", "created_at", "time")
                            if payload.get(key) is not None), None)
    document = {
        "_id": uuid4().hex, "agent_id": agent_id,
        "timestamp": aware_timestamp(agent_timestamp, received_at),
        "agent_timestamp": agent_timestamp, "received_at": received_at,
        "source_ip": source_ip, "source_port": source_port, "logs": logs,
        "system_info": system_info,
    }
    document.update({key: metrics[key] for key in METRIC_FIELDS if key in metrics})
    document.update({key: system_info[key] for key in SYSTEM_INFO_FIELDS if key in system_info})
    mac = normalize_mac(system_info.get("mac_address"))
    if mac:
        document["mac"] = mac
    return document


def reported_ip(info):
    for key in ("ip_address", "local_ip", "ip"):
        value = info.get(key)
        if isinstance(value, str) and "%" not in value:
            try:
                return str(ip_address(value.strip()))
            except ValueError:
                continue
    return None


def update_system(database, document):
    info = document["system_info"]
    mac = document.get("mac")
    systems = database[SYSTEMS]
    if not mac:
        matches = list(systems.find({"agent_id": document["agent_id"]}, {"mac": 1}).limit(2))
        if len(matches) != 1:
            return None
        mac = matches[0]["mac"]

    received_at = document["received_at"]
    profile = {key: info[key] for key in SYSTEM_INFO_FIELDS if info.get(key) not in (None, "")}
    profile["source_ip"] = document["source_ip"]
    if address := reported_ip(info):
        profile["ip"] = address
    update = {"mac": mac, "agent_id": document["agent_id"], "last_seen": received_at, **profile}
    initial = {"_id": mac, "first_seen": received_at, "type": "desktop", "threshold": 70}
    change = {"$set": update, "$unset": {key: "" for key in METRIC_FIELDS}, "$setOnInsert": initial}
    query = {"mac": mac, "$or": [{"last_seen": {"$lte": received_at}}, {"last_seen": None}]}
    try:
        previous = systems.find_one_and_update(query, change, upsert=True)
    except DuplicateKeyError:
        # A later payload or concurrent upsert already established this MAC.
        previous = systems.find_one_and_update(query, change)
        if previous is None:
            return systems.find_one({"mac": mac})
    if previous is None:
        return {**initial, **update}

    changes = {key: {"before": previous.get(key), "after": value}
               for key, value in profile.items() if previous.get(key) != value}
    if changes:
        database[SYSTEM_CHANGES].insert_one({
            "_id": uuid4().hex, "system_id": previous["_id"], "mac": mac,
            "agent_id": document["agent_id"], "changed_at": received_at, "changes": changes,
        })
    return {**previous, **update}


def mongo_key(value):
    key = str(value).replace("\x00", "�").replace(".", "_")
    if key == "_id":
        return "source_id"
    return "_" + key[1:] if key.startswith("$") else key


def mongo_value(value):
    if isinstance(value, dict):
        result = {}
        for key, item in value.items():
            normalized = mongo_key(key)
            suffix = 2
            unique = normalized
            while unique in result:
                unique = f"{normalized}_{suffix}"
                suffix += 1
            result[unique] = mongo_value(item)
        return result
    if isinstance(value, list):
        return [mongo_value(item) for item in value]
    return value


def root_agent_log(document, row):
    channel = row.get("log") or row.get("channel") or "Windows"
    record_number = row.get("record_number")
    if record_number is None:
        identity = document["agent_id"] + "\0" + json.dumps(
            row, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    else:
        identity = f"{document['agent_id']}\0{channel}\0{record_number}"
    result = {
        "_id": sha256(identity.encode("utf-8")).hexdigest(),
        "agent_id": document["agent_id"], "received_at": document["received_at"],
        "timestamp": aware_timestamp(row.get("time"), document["timestamp"]),
        "source_ip": document["source_ip"], "source_port": document["source_port"],
    }
    if document.get("mac"):
        result["system_id"] = result["mac"] = document["mac"]

    def add_fields(fields, collision_prefix):
        for key, value in fields.items():
            normalized = mongo_key(key)
            if normalized in result:
                normalized = f"{collision_prefix}_{normalized}"
            suffix = 2
            unique = normalized
            while unique in result:
                unique = f"{normalized}_{suffix}"
                suffix += 1
            result[unique] = mongo_value(value)

    add_fields({key: value for key, value in row.items() if key != "event_data"}, "log")
    event_data = row.get("event_data")
    if isinstance(event_data, dict):
        add_fields(event_data, "event_data")
    return result


def store_agent_logs(database, document):
    unique = {}
    for row in document["logs"]:
        if not isinstance(row, dict):
            continue
        raw = root_agent_log(document, row)
        unique[raw["_id"]] = (raw, row)
    if not unique:
        return [], []
    identifiers = list(unique)
    existing = {row["_id"] for row in database[AGENT_LOGS].find(
        {"_id": {"$in": identifiers}}, {"_id": 1})}
    database[AGENT_LOGS].bulk_write([
        ReplaceOne({"_id": raw["_id"]}, raw, upsert=True) for raw, _ in unique.values()
    ])
    inserted_rows = [row for identifier, (_, row) in unique.items() if identifier not in existing]
    return [raw for raw, _ in unique.values()], inserted_rows


def store_metrics(database, document, system):
    metrics = {key: document[key] for key in METRIC_FIELDS if key in document}
    if not metrics:
        return False
    identity_time = document.get("metrics_timestamp") or document.get("agent_timestamp")
    identity = f"{document['agent_id']}\0{identity_time or document['received_at'].isoformat()}"
    row = {
        "_id": sha256(identity.encode("utf-8")).hexdigest(), "agent_id": document["agent_id"],
        "timestamp": aware_timestamp(identity_time, document["received_at"]),
        "agent_timestamp": identity_time, "received_at": document["received_at"],
        "source_ip": document["source_ip"], "source_port": document["source_port"], **metrics,
    }
    if system:
        row["system_id"] = system["_id"]
        row["mac"] = system["mac"]
    database[SYSTEM_METRICS].replace_one({"_id": row["_id"]}, row, upsert=True)
    return True


def windows_events(document, rows):
    events = []
    for row in rows:
        if not isinstance(row, dict):
            continue
        message = str(row.get("message") or "Windows event").strip()
        if not message:
            message = "Windows event"
        event_type = row.get("type")
        attributes = {
            "agent_id": document["agent_id"], "source_ip": document["source_ip"],
            "transport": "HTTP", "protocol": "TCP",
            **{key: row[key] for key in ("log", "record_number", "event_id", "type", "computer") if key in row},
        }
        if isinstance(row.get("event_data"), dict):
            attributes["event_data"] = mongo_value(row["event_data"])
        events.append(LogCreate(
            timestamp=aware_timestamp(row.get("time"), document["timestamp"]),
            source=document["agent_id"], level=WINDOWS_LEVELS.get(event_type, LogLevel.INFO),
            message=message, attributes=attributes,
        ))
    return events


def ingest_agent_payload(database, payload, source_ip, source_port, received_at):
    document = payload_document(payload, source_ip, source_port, received_at)
    metrics = payload.get("metrics") if isinstance(payload.get("metrics"), dict) else {}
    document["metrics_timestamp"] = metrics.get("timestamp")
    system = update_system(database, document)
    if system:
        document["mac"] = system["mac"]
        document["system_id"] = system["_id"]
    has_metrics = store_metrics(database, document, system)
    stored, inserted_rows = store_agent_logs(database, document)
    return {
        "events": windows_events(document, inserted_rows), "logs": len(stored),
        "inserted": len(inserted_rows), "metrics": has_metrics, "records": stored,
    }


def bootstrap_systems(database):
    seen = set()
    cursor = database.log_events.find(
        {"attributes.agent_payload.system_info.mac_address": {"$type": "string"}},
        {"attributes.agent_payload": 1, "attributes.source_ip": 1, "attributes.source_port": 1,
         "received_at": 1},
    ).sort("received_at", -1)
    for row in cursor:
        payload = row["attributes"]["agent_payload"]
        agent_id = payload.get("agent_id")
        if not agent_id or agent_id in seen:
            continue
        seen.add(agent_id)
        mac = normalize_mac(payload.get("system_info", {}).get("mac_address"))
        if not mac or database[SYSTEMS].find_one({"mac": mac}, {"_id": 1}):
            continue
        document = payload_document(
            payload, row["attributes"].get("source_ip", "unknown"),
            row["attributes"].get("source_port"), row["received_at"],
        )
        metrics = payload.get("metrics") if isinstance(payload.get("metrics"), dict) else {}
        document["metrics_timestamp"] = metrics.get("timestamp")
        store_metrics(database, document, update_system(database, document))
        latest = database.log_events.find_one(
            {"attributes.agent_payload.agent_id": agent_id},
            {"attributes.agent_payload": 1, "attributes.source_ip": 1,
             "attributes.source_port": 1, "received_at": 1}, sort=[("received_at", -1)],
        )
        if latest and latest["_id"] != row["_id"]:
            latest_payload = latest["attributes"]["agent_payload"]
            latest_document = payload_document(
                latest_payload, latest["attributes"].get("source_ip", "unknown"),
                latest["attributes"].get("source_port"), latest["received_at"],
            )
            latest_metrics = latest_payload.get("metrics") if isinstance(latest_payload.get("metrics"), dict) else {}
            latest_document["metrics_timestamp"] = latest_metrics.get("timestamp")
            store_metrics(database, latest_document, update_system(database, latest_document))
