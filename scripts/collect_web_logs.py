#!/usr/bin/env python3
"""Ship one-minute JSONL request summaries with a durable SQLite outbox."""
import argparse
from bisect import bisect_left
from collections import Counter
from datetime import datetime, timedelta, timezone
import hmac
import ipaddress
import json
import math
import os
from pathlib import Path
import re
import sqlite3
import sys
import time
from urllib.error import HTTPError, URLError
from urllib.parse import urlsplit
from urllib.request import build_opener, HTTPRedirectHandler, ProxyHandler, Request
from uuid import uuid4

BOUNDS = (5, 10, 25, 50, 100, 250, 500, 1000, 2500, 5000)
METHODS = {'GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'HEAD', 'OPTIONS', 'CONNECT', 'TRACE', 'OTHER'}
SECURITY_EVENTS = {'login_success', 'login_failure', 'access_denied', 'permission_changed'}
MEDIA_TYPES = {'application/json', 'application/problem+json', 'application/x-www-form-urlencoded',
               'application/octet-stream', 'multipart/form-data', 'text/plain', 'text/html', 'text/css'}
BODY_FIELDS = {'id', 'batch_id', 'events', 'items', 'count', 'status', 'code', 'error', 'detail', 'limit', 'offset'}
SOURCE_PATTERN = r'[a-zA-Z0-9][a-zA-Z0-9_.-]{0,63}'
MAX_LINE = 16 * 1024
MAX_OUTBOX = 64 * 1024 * 1024


class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def sanitize(line):
    row = json.loads(line)
    if not isinstance(row, dict):
        raise ValueError('request log must be an object')
    timestamp = datetime.fromisoformat(row['timestamp'])
    request_id, method, route = (row[key] for key in ('request_id', 'method', 'route'))
    status, duration = row['status'], row['duration_ms']
    sizes = {key: row[key] for key in ('request_bytes', 'response_bytes')}
    if (timestamp.utcoffset() is None or not re.fullmatch(r'[a-zA-Z0-9_.:-]{1,80}', request_id)
            or method not in METHODS or not re.fullmatch(r'(?:/[^?#\r\n]{0,199}|<unmatched>)', route)
            or type(status) is not int or not 100 <= status <= 599
            or type(duration) not in (float, int) or not math.isfinite(duration) or duration < 0
            or any(type(value) is not int or not 0 <= value <= 1000000000 for value in sizes.values())):
        raise ValueError('invalid request metadata')
    event = {
        'timestamp': timestamp.astimezone(timezone.utc).isoformat(), 'request_id': request_id,
        'method': method, 'route': route, 'status': status, 'duration_ms': duration, **sizes,
    }
    if isinstance(row.get('source_ip'), str):
        try:
            event['source_ip'] = str(ipaddress.ip_address(row['source_ip']))
        except ValueError:
            pass
    if isinstance(row.get('security_event'), str) and row['security_event'] in SECURITY_EVENTS:
        event['security_event'] = row['security_event']
    if row.get('url_scheme') in ('http', 'https'):
        event['url_scheme'] = row['url_scheme']
    if isinstance(row.get('url_host'), str) and re.fullmatch(r'[A-Za-z0-9.:\[\]-]{1,253}', row['url_host']):
        event['url_host'] = row['url_host']
    for key in ('request_headers', 'response_headers'):
        if isinstance(headers := row.get(key), dict):
            selected = {}
            if isinstance(media := headers.get('content_type'), str) and media in MEDIA_TYPES:
                selected['content_type'] = media
            if type(length := headers.get('content_length')) is int and 0 <= length <= 1000000000:
                selected['content_length'] = length
            if selected:
                event[key] = selected
    for key in ('request_body_fields', 'response_body_fields'):
        if isinstance(names := row.get(key), list):
            event[key] = sorted({name for name in names if isinstance(name, str) and name in BODY_FIELDS})
    return event


def open_current(db, path):
    row = db.execute('SELECT device, inode, offset FROM cursor WHERE id=1').fetchone()
    with path.open('rb') as current:
        stat = os.fstat(current.fileno())
        identity = (stat.st_dev, stat.st_ino)
        if row is not None and tuple(row[:2]) != identity:
            previous_path = path.with_name(path.name + '.1')
            try:
                previous = previous_path.open('rb')
            except FileNotFoundError:
                previous = None
            if previous is not None:
                with previous:
                    stat = os.fstat(previous.fileno())
                    if (stat.st_dev, stat.st_ino) == tuple(row[:2]):
                        yield previous, tuple(row[:2]), row[2]
            row = None
        offset = row[2] if row is not None and row[2] <= os.fstat(current.fileno()).st_size else 0
        yield current, identity, offset


def aggregate(db, path, service, end, slow_ms):
    if db.execute('SELECT coalesce(sum(length(payload)), 0) FROM pending').fetchone()[0] >= MAX_OUTBOX:
        print('outbox is full; waiting before reading more input', file=sys.stderr)
        return
    classes, codes = Counter(), Counter()
    buckets = [0] * (len(BOUNDS) + 1)
    critical, regular = [], []
    invalid = 0
    checkpoint = None
    for stream, identity, offset in open_current(db, path):
        stream.seek(offset)
        end_offset = os.fstat(stream.fileno()).st_size
        while stream.tell() < end_offset:
            start = stream.tell()
            line = stream.readline(min(MAX_LINE + 1, end_offset - start))
            if not line:
                break
            oversized = len(line) > MAX_LINE
            while oversized and not line.endswith(b'\n') and stream.tell() < end_offset:
                line = stream.readline(min(MAX_LINE, end_offset - stream.tell()))
            if not line.endswith(b'\n'):
                stream.seek(start)
                break
            try:
                if oversized:
                    raise ValueError('line too long')
                event = sanitize(line)
            except (ValueError, TypeError, KeyError, OverflowError, RecursionError):
                invalid += 1
                continue
            status, duration = event['status'], event['duration_ms']
            classes[f'{status // 100}xx'] += 1
            codes[str(status)] += 1
            buckets[bisect_left(BOUNDS, duration)] += 1
            if (status >= 500 or 'security_event' in event) and len(critical) < 300:
                critical.append(event)
            elif (status >= 400 or duration >= slow_ms) and len(regular) < 50:
                regular.append(event)
        checkpoint = (*identity, stream.tell())

    with db:
        if checkpoint:
            db.execute('INSERT OR REPLACE INTO cursor VALUES (1, ?, ?, ?)', checkpoint)
        if not codes and not invalid:
            return
        events = (critical + regular)[:300]
        identifier = str(uuid4())
        payload = json.dumps({
            'batch_id': identifier, 'service': service,
            'interval_start': (end - timedelta(minutes=1)).isoformat(), 'interval_end': end.isoformat(),
            'status_classes': classes, 'status_codes': codes, 'latency_buckets': buckets,
            'omitted_details': sum(codes.values()) - len(events), 'invalid_lines': invalid,
            'events': events,
        }, ensure_ascii=False, separators=(',', ':')).encode('utf-8')
        db.execute('INSERT INTO pending VALUES (?, ?, ?)', (identifier, end.timestamp(), payload))


def flush(db, opener, target, service, secret):
    for identifier, end, payload in db.execute('SELECT * FROM pending ORDER BY interval_end, id').fetchall():
        if end < time.time() - 7 * 86400:
            print(f'expired unsent batch {identifier}', file=sys.stderr)
        else:
            request = Request(target, data=payload, headers={
                'Content-Type': 'application/json', 'X-SIEM-Service': service,
                'X-SIEM-Signature': hmac.digest(secret, payload, 'sha256').hex(),
            })
            try:
                with opener.open(request, timeout=10) as response:
                    receipt = json.loads(response.read(4096))
                    if response.status != 202 or not isinstance(receipt, dict) or receipt.get('batch_id') != identifier:
                        raise ValueError('unexpected batch acknowledgment')
            except (HTTPError, URLError, OSError, ValueError) as error:
                print(f'batch {identifier} kept for retry: {error}', file=sys.stderr)
                return
        with db:
            db.execute('DELETE FROM pending WHERE id=?', (identifier,))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source', type=Path, required=True)
    parser.add_argument('--state', type=Path, required=True)
    parser.add_argument('--service', required=True)
    parser.add_argument('--endpoint', required=True, help='Full HTTP URL ending in /api/v1/web-services/batches')
    parser.add_argument('--slow-ms', type=int, default=1000)
    parser.add_argument('--once', action='store_true', help='Collect and send once for setup validation')
    args = parser.parse_args()
    url = urlsplit(args.endpoint)
    if (url.scheme not in ('http', 'https') or not url.hostname or url.username or url.password
            or url.query or url.fragment or url.path != '/api/v1/web-services/batches'):
        parser.error('invalid SIEM endpoint')
    secret = os.environ.get('SIEM_WEB_COLLECTOR_KEY', '').encode()
    if len(secret) < 32 or not re.fullmatch(SOURCE_PATTERN, args.service) or args.slow_ms < 1:
        parser.error('a collector key of at least 32 bytes, valid service ID and positive slow threshold are required')
    os.umask(0o077)
    opener = build_opener(ProxyHandler({}), NoRedirect())
    with sqlite3.connect(args.state) as db:
        db.executescript('''
          CREATE TABLE IF NOT EXISTS source (id INTEGER PRIMARY KEY, path TEXT, service TEXT);
          CREATE TABLE IF NOT EXISTS cursor (id INTEGER PRIMARY KEY, device INTEGER, inode INTEGER, offset INTEGER);
          CREATE TABLE IF NOT EXISTS pending (id TEXT PRIMARY KEY, interval_end INTEGER, payload BLOB);
        ''')
        binding = (str(args.source.resolve()), args.service)
        with db:
            db.execute('INSERT OR IGNORE INTO source VALUES (1, ?, ?)', binding)
        if db.execute('SELECT path, service FROM source WHERE id=1').fetchone() != binding:
            parser.error('use a different state file for each source and service')
        while True:
            if not args.once:
                time.sleep(60 - time.time() % 60)
            end = datetime.now(timezone.utc).replace(second=0, microsecond=0)
            read_failed = False
            try:
                aggregate(db, args.source, args.service, end, args.slow_ms)
            except OSError as error:
                read_failed = True
                print(f'could not read input: {error}', file=sys.stderr)
            flush(db, opener, args.endpoint, args.service, secret)
            if args.once:
                return int(read_failed or db.execute('SELECT 1 FROM pending LIMIT 1').fetchone() is not None)


if __name__ == '__main__':
    sys.exit(main())
