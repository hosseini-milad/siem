"""Streaming import for sample operating-system log datasets."""
import csv
import gzip
import json
import logging
from datetime import datetime, timezone
from hashlib import sha256
from pathlib import Path

from pymongo import ReplaceOne

COLLECTION = "system_log_dataset_records"
JOBS = "system_log_dataset_imports"
SUPPORTED = (".csv", ".json", ".jsonl", ".ndjson", ".log", ".txt")
LOGGER = logging.getLogger("uvicorn.error.siem.system_log_datasets")


def import_path(root: Path, supplied: str) -> Path:
    root = root.resolve()
    candidate = Path(supplied)
    candidate = candidate.resolve() if candidate.is_absolute() else (root / candidate).resolve()
    try:
        candidate.relative_to(root)
    except ValueError as exc:
        raise ValueError("Dataset path must be inside SIEM_SYSTEM_LOG_DATASETS_ROOT") from exc
    if not candidate.exists() or candidate.is_symlink() or not (candidate.is_file() or candidate.is_dir()):
        raise ValueError("Dataset path does not exist or is unsupported")
    return candidate


def file_format(path: Path):
    name = path.name.lower()
    if name.endswith(".gz"):
        name = name[:-3]
    return next((suffix[1:] for suffix in SUPPORTED if name.endswith(suffix)), None)


def dataset_files(path: Path):
    candidates = [path] if path.is_file() else sorted(item for item in path.rglob("*") if item.is_file())
    files = []
    for item in candidates:
        if item.is_symlink():
            raise ValueError("Symlink files are not supported")
        if file_format(item):
            files.append(item)
    if not files:
        raise ValueError("No supported CSV, JSON, JSONL, NDJSON, LOG or TXT file found")
    return files


def open_text(path: Path, newline=None):
    opener = gzip.open if path.name.lower().endswith(".gz") else open
    return opener(path, "rt", encoding="utf-8-sig", errors="strict", newline=newline)


def json_values(stream):
    decoder = json.JSONDecoder()
    buffer = ""
    in_array = False
    started = False
    need_separator = False
    eof = False
    while True:
        if not eof and len(buffer) < 65536:
            chunk = stream.read(65536)
            if chunk:
                buffer += chunk
            else:
                eof = True
        buffer = buffer.lstrip()
        if not started:
            started = True
            if buffer.startswith("["):
                in_array = True
                buffer = buffer[1:].lstrip()
        if in_array and need_separator:
            if buffer.startswith(","):
                buffer = buffer[1:].lstrip()
                need_separator = False
            elif buffer.startswith("]"):
                return
            else:
                raise ValueError("JSON array requires a comma or closing bracket after each record")
        if in_array and not need_separator and buffer.startswith("]"):
            return
        if not buffer:
            if eof:
                if in_array:
                    raise ValueError("JSON array is missing its closing bracket")
                return
            continue
        try:
            value, end = decoder.raw_decode(buffer)
        except json.JSONDecodeError:
            if eof:
                raise
            chunk = stream.read(65536)
            if chunk:
                buffer += chunk
                continue
            eof = True
            continue
        yield value
        buffer = buffer[end:].lstrip()
        if in_array:
            need_separator = True


def records(path: Path):
    kind = file_format(path)
    if kind == "csv":
        with open_text(path, newline="") as stream:
            reader = csv.DictReader(stream, strict=True)
            if not reader.fieldnames or any(not key or not key.strip() for key in reader.fieldnames):
                raise ValueError("CSV requires nonempty column names")
            if len(set(reader.fieldnames)) != len(reader.fieldnames):
                raise ValueError("CSV requires unique column names")
            yield from reader
    elif kind in {"json", "jsonl", "ndjson"}:
        with open_text(path) as stream:
            yield from json_values(stream)
    else:
        with open_text(path) as stream:
            for line in stream:
                value = line.rstrip("\r\n")
                if value:
                    yield {"raw_message": value}


def mongo_key(value):
    key = str(value).replace("\x00", "�")
    if key == "_id":
        return "source_id"
    if key == "_import":
        return "source__import"
    if key.startswith("$"):
        key = "_" + key[1:]
    return key.replace(".", "_")


def mongo_value(value, location="record"):
    if isinstance(value, dict):
        result = {}
        for key, item in value.items():
            normalized = mongo_key(key)
            if normalized in result:
                raise ValueError(f"Fields collide after MongoDB key normalization at {location}: {normalized}")
            result[normalized] = mongo_value(item, f"{location}.{normalized}")
        return result
    if isinstance(value, list):
        return [mongo_value(item, f"{location}[]") for item in value]
    return value


def document(value, identity, relative, number, kind, job_id, imported_at):
    fields = mongo_value(value) if isinstance(value, dict) else {"value": mongo_value(value)}
    return {
        "_id": sha256(f"{identity}:{number}".encode()).hexdigest(), **fields,
        "_import": {"job_id": job_id, "file": relative, "record_number": number,
                    "format": kind, "imported_at": imported_at},
    }


def import_dataset(database, root: Path, supplied: str, job_id: str):
    jobs = database[JOBS]
    processed = inserted = updated = completed_files = 0
    try:
        selected = import_path(root, supplied)
        files = dataset_files(selected)
        root = root.resolve()
        for path in files:
            relative = path.resolve().relative_to(root).as_posix()
            identity = sha256(relative.encode()).hexdigest()
            batch = []
            for number, value in enumerate(records(path), 1):
                imported_at = datetime.now(timezone.utc)
                row = document(value, identity, relative, number, file_format(path), job_id, imported_at)
                batch.append(ReplaceOne({"_id": row["_id"]}, row, upsert=True))
                if len(batch) == 500:
                    result = database[COLLECTION].bulk_write(batch)
                    processed += len(batch)
                    inserted += result.upserted_count
                    updated += result.modified_count
                    batch = []
                    jobs.update_one({"_id": job_id}, {"$set": {
                        "processed": processed, "inserted": inserted, "updated": updated,
                        "completed_files": completed_files,
                    }})
            if batch:
                result = database[COLLECTION].bulk_write(batch)
                processed += len(batch)
                inserted += result.upserted_count
                updated += result.modified_count
            completed_files += 1
            jobs.update_one({"_id": job_id}, {"$set": {
                "processed": processed, "inserted": inserted, "updated": updated,
                "completed_files": completed_files,
            }})
        jobs.update_one({"_id": job_id}, {"$set": {
            "status": "completed", "processed": processed, "inserted": inserted,
            "updated": updated, "completed_files": completed_files,
            "finished_at": datetime.now(timezone.utc),
        }})
    except Exception as exc:
        LOGGER.exception("System-log dataset import %s failed", job_id)
        expected = (ValueError, csv.Error, UnicodeError, json.JSONDecodeError, EOFError, gzip.BadGzipFile)
        message = str(exc) if isinstance(exc, expected) else "Import failed; check server logs and database availability"
        jobs.update_one({"_id": job_id}, {"$set": {
            "status": "failed", "error": message[:500], "processed": processed,
            "inserted": inserted, "updated": updated, "completed_files": completed_files,
            "finished_at": datetime.now(timezone.utc),
        }})
