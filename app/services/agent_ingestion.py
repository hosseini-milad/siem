from datetime import datetime, timezone
import re
from uuid import uuid4

from pymongo import ReturnDocument

from app.schemas.log import LogCreate, LogLevel

PAYLOADS = "agent_payloads"
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
    document = {
        "_id": uuid4().hex, "agent_id": agent_id,
        "timestamp": aware_timestamp(payload.get("timestamp"), received_at),
        "agent_timestamp": payload.get("timestamp"), "received_at": received_at,
        "source_ip": source_ip, "source_port": source_port, "logs": logs,
        "system_info": system_info,
    }
    document.update({key: metrics[key] for key in METRIC_FIELDS if key in metrics})
    document.update({key: system_info[key] for key in SYSTEM_INFO_FIELDS if key in system_info})
    mac = normalize_mac(system_info.get("mac_address"))
    if mac:
        document["mac"] = mac
    return document


def update_system(database, document):
    info = document["system_info"]
    mac = normalize_mac(info.get("mac_address"))
    query = {"mac": mac} if mac else {"agent_id": document["agent_id"]}
    existing = database[SYSTEMS].find_one(query, sort=[("last_seen", -1)])
    if not mac and not existing:
        return None
    mac = mac or existing["mac"]
    profile = {key: info[key] for key in SYSTEM_INFO_FIELDS if key in info}
    metrics = {key: document[key] for key in METRIC_FIELDS if key in document}
    changes = {
        key: {"before": existing.get(key), "after": value}
        for key, value in profile.items() if existing and existing.get(key) != value
    }
    update = {
        "mac": mac, "agent_id": document["agent_id"], "last_seen": document["received_at"],
        "source_ip": document["source_ip"], **profile, **metrics,
    }
    system = database[SYSTEMS].find_one_and_update(
        {"mac": mac}, {"$set": update, "$setOnInsert": {
            "_id": mac, "first_seen": document["received_at"], "type": "desktop", "threshold": 70,
        }}, upsert=True, return_document=ReturnDocument.AFTER,
    )
    if changes:
        database[SYSTEM_CHANGES].insert_one({
            "_id": uuid4().hex, "system_id": mac, "mac": mac,
            "agent_id": document["agent_id"], "changed_at": document["received_at"],
            "changes": changes,
        })
    return system


def windows_events(document):
    events = []
    for row in document["logs"]:
        if not isinstance(row, dict):
            continue
        message = str(row.get("message") or "Windows event").strip()
        if not message:
            message = "Windows event"
        event_type = row.get("type")
        attributes = {
            "agent_id": document["agent_id"], "source_ip": document["source_ip"],
            "transport": "HTTP", "protocol": "TCP",
            **{key: row[key] for key in ("log", "record_number", "event_id", "type") if key in row},
        }
        events.append(LogCreate(
            timestamp=aware_timestamp(row.get("time"), document["timestamp"]),
            source=document["agent_id"], level=WINDOWS_LEVELS.get(event_type, LogLevel.INFO),
            message=message, attributes=attributes,
        ))
    return events


def ingest_agent_payload(database, payload, source_ip, source_port, received_at):
    document = payload_document(payload, source_ip, source_port, received_at)
    database[PAYLOADS].insert_one(document)
    update_system(database, document)
    return windows_events(document)


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
        update_system(database, document)
        latest = database.log_events.find_one(
            {"attributes.agent_payload.agent_id": agent_id},
            {"attributes.agent_payload": 1, "attributes.source_ip": 1,
             "attributes.source_port": 1, "received_at": 1}, sort=[("received_at", -1)],
        )
        if latest and latest["_id"] != row["_id"]:
            update_system(database, payload_document(
                latest["attributes"]["agent_payload"], latest["attributes"].get("source_ip", "unknown"),
                latest["attributes"].get("source_port"), latest["received_at"],
            ))
