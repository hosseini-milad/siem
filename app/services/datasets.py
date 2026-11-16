"""Streaming CSV/gzip ingestion, including byte-split gzip volumes."""
import csv
import gzip
import hashlib
import io
import re
from datetime import datetime, timezone
from pathlib import Path

from pymongo import UpdateOne


def folder_path(root: Path, name: str) -> Path:
    if not name or name in (".", "..") or '/' in name or '\\' in name:
        raise ValueError("Select an immediate dataset folder")
    path = (root / name).resolve()
    if path.parent != root.resolve() or not path.is_dir():
        raise ValueError("Dataset folder not found or outside configured root")
    return path


def archives(folder: Path):
    files = sorted(folder.iterdir())
    groups = []
    for path in files:
        if path.is_symlink():
            raise ValueError("Symlink files are not supported")
        if path.name.endswith(('.csv', '.csv.gz')):
            groups.append([path])
        elif path.name.endswith('.csv.gz.001'):
            prefix = path.name[:-3]
            parts = sorted(p for p in files if re.fullmatch(re.escape(prefix) + r'\d{3}', p.name))
            if [int(p.name[-3:]) for p in parts] != list(range(1, len(parts) + 1)):
                raise ValueError("Missing split gzip part")
            groups.append(parts)
    used = {p for group in groups for p in group}
    if any(re.search(r'\.csv\.gz\.\d{3}$', p.name) and p not in used for p in files):
        raise ValueError("Split gzip sequence must start at .001")
    if not groups:
        raise ValueError("No .csv, .csv.gz or .csv.gz.001 dataset found")
    return groups


class PartsReader(io.RawIOBase):
    def __init__(self, paths):
        super().__init__()
        self.paths = iter(paths)
        self.current = None

    def readable(self):
        return True

    def readinto(self, buffer):
        while True:
            if self.current is None:
                path = next(self.paths, None)
                if path is None:
                    return 0
                self.current = path.open('rb')
            count = self.current.readinto(buffer)
            if count:
                return count
            self.current.close()
            self.current = None

    def close(self):
        if self.current:
            self.current.close()
        super().close()


def import_folder(db, root: Path, folder: str, job_id: str):
    jobs = db.dataset_imports
    processed = inserted = 0
    try:
        for parts in archives(folder_path(root, folder)):
            digest = hashlib.sha256()
            for part in parts:
                with part.open('rb') as source:
                    for block in iter(lambda: source.read(1024 * 1024), b''):
                        digest.update(block)
            identity = hashlib.sha256((folder + ':' + parts[0].name + ':' + digest.hexdigest()).encode()).hexdigest()
            with PartsReader(parts) as raw, io.BufferedReader(raw) as buffered:
                stream = gzip.GzipFile(fileobj=buffered) if '.csv.gz' in parts[0].name else buffered
                with io.TextIOWrapper(stream, encoding='utf-8-sig', newline='') as text:
                    reader = csv.reader(text, strict=True)
                    header = next(reader, None)
                    if not header or any(not key.strip() for key in header) or len(set(header)) != len(header):
                        raise ValueError("CSV requires unique, nonempty column names")
                    batch = []
                    for number, values in enumerate(reader, 1):
                        if len(values) != len(header):
                            raise ValueError(f"CSV row {number} has an unexpected column count")
                        document = {'folder': folder, 'archive': parts[0].name, 'row_number': number,
                                    'data': dict(zip(header, values)), 'import_id': job_id,
                                    'received_at': datetime.now(timezone.utc)}
                        key = f'{identity}:{number}'
                        batch.append(UpdateOne({'_id': key}, {'$setOnInsert': document}, upsert=True))
                        if len(batch) == 500:
                            result = db.dataset_records.bulk_write(batch)
                            processed += len(batch)
                            inserted += result.upserted_count
                            batch = []
                            jobs.update_one({'_id': job_id}, {'$set': {'processed': processed, 'inserted': inserted}})
                    if batch:
                        result = db.dataset_records.bulk_write(batch)
                        processed += len(batch)
                        inserted += result.upserted_count
        jobs.update_one({'_id': job_id}, {'$set': {'status': 'completed', 'processed': processed,
                        'inserted': inserted, 'finished_at': datetime.now(timezone.utc)}})
    except Exception as exc:
        # Completed batches remain queryable; an import is deliberately not a huge transaction.
        message = str(exc) if isinstance(exc, (ValueError, csv.Error, UnicodeError, EOFError, gzip.BadGzipFile)) else 'Import failed; check server logs and database availability'
        jobs.update_one({'_id': job_id}, {'$set': {'status': 'failed', 'error': message[:500],
                        'processed': processed, 'inserted': inserted, 'finished_at': datetime.now(timezone.utc)}})
