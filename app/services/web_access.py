"""Export request metadata as JSON lines for an external collector."""
import json
import logging
import re
from datetime import datetime, timezone
from logging.handlers import WatchedFileHandler
from time import perf_counter
from uuid import uuid4

INGEST_PATH = '/api/v1/web-services/batches'
RECORDS = 'web-records'
METHODS = {'GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'HEAD', 'OPTIONS', 'CONNECT', 'TRACE'}


MEDIA_TYPES = {'application/json', 'application/problem+json', 'application/x-www-form-urlencoded',
               'application/octet-stream', 'multipart/form-data', 'text/plain', 'text/html', 'text/css'}
BODY_FIELDS = {'id', 'batch_id', 'events', 'items', 'count', 'status', 'code', 'error', 'detail', 'limit', 'offset'}
BODY_LIMIT = 8192
HOST_PATTERN = r'[A-Za-z0-9.:\[\]-]{1,253}'


def selected_headers(pairs):
    headers = dict(pairs)
    media = headers.get(b'content-type', b'').split(b';', 1)[0].strip().decode('ascii', 'ignore').lower()
    result = {'content_type': media} if media in MEDIA_TYPES else {}
    length = headers.get(b'content-length', b'')
    if 0 < len(length) <= 9 and length.isdigit():
        result['content_length'] = int(length)
    return result


class BodyFieldNames:
    def __init__(self, content_type):
        self.data = bytearray() if content_type in {'application/json', 'application/problem+json'} else None

    def consume(self, chunk):
        if self.data is not None:
            if len(self.data) + len(chunk) > BODY_LIMIT:
                self.data = None
            else:
                self.data.extend(chunk)

    def names(self):
        if self.data:
            try:
                value = json.loads(self.data)
            except (ValueError, RecursionError):
                return []
            if isinstance(value, dict):
                return sorted(BODY_FIELDS.intersection(value))
        return []


class WebAccessLog:
    def __init__(self, app, handler):
        self.app = app
        self.handler = handler

    async def __call__(self, scope, receive, send):
        if scope['type'] != 'http' or scope['path'].rstrip('/') == INGEST_PATH:
            await self.app(scope, receive, send)
            return

        identifier = uuid4().hex
        started = perf_counter()
        status = 500
        request_bytes = response_bytes = 0
        request_headers = selected_headers(scope.get('headers', []))
        response_headers = {}
        request_fields = BodyFieldNames(request_headers.get('content_type'))
        response_fields = BodyFieldNames(None)

        async def counted_receive():
            nonlocal request_bytes
            message = await receive()
            if message['type'] == 'http.request':
                chunk = message.get('body', b'')
                request_bytes += len(chunk)
                request_fields.consume(chunk)
            return message

        async def counted_send(message):
            nonlocal status, response_bytes, response_headers, response_fields
            if message['type'] == 'http.response.start':
                status = message['status']
                response_headers = selected_headers(message.get('headers', []))
                response_fields = BodyFieldNames(response_headers.get('content_type'))
                headers = [pair for pair in message.get('headers', []) if pair[0].lower() != b'x-request-id']
                message = {**message, 'headers': [*headers, (b'x-request-id', identifier.encode('ascii'))]}
            elif message['type'] == 'http.response.body':
                chunk = message.get('body', b'')
                response_bytes += len(chunk)
                response_fields.consume(chunk)
            await send(message)

        try:
            await self.app(scope, counted_receive, counted_send)
        finally:
            route = getattr(scope.get('route'), 'path', '<unmatched>')
            method = scope['method']
            row = {
                'timestamp': datetime.now(timezone.utc).isoformat(),
                'request_id': identifier,
                'method': method if method in METHODS else 'OTHER',
                'route': route,
                'status': status,
                'duration_ms': round((perf_counter() - started) * 1000, 3),
                'request_bytes': request_bytes,
                'response_bytes': response_bytes,
            }
            if request_headers:
                row['request_headers'] = request_headers
            if response_headers:
                row['response_headers'] = response_headers
            for key, body in (('request_body_fields', request_fields), ('response_body_fields', response_fields)):
                if names := body.names():
                    row[key] = names
            if scope['scheme'] in ('http', 'https'):
                row['url_scheme'] = scope['scheme']
            server = scope.get('server')
            if server and server[0] and re.fullmatch(HOST_PATTERN, server[0]):
                host = server[0]
                if ':' in host and not host.startswith('['):
                    host = f'[{host}]'
                row['url_host'] = f'{host}:{server[1]}' if server[1] is not None else host
            security_event = scope.get('state', {}).get('web_security_event')
            if route == '/api/v1/auth/login' and status in (200, 401, 429):
                security_event = 'login_success' if status == 200 else 'login_failure'
            elif status == 403:
                security_event = 'access_denied'
            if security_event:
                row['security_event'] = security_event
            if scope.get('client'):
                row['source_ip'] = scope['client'][0]
            try:
                self.handler.handle(logging.LogRecord(
                    'siem.web_access', logging.INFO, '', 0, json.dumps(row), (), None))
            except OSError:
                logging.getLogger('uvicorn.error').exception('Could not write web access log')


def access_log_handler(path):
    return WatchedFileHandler(path, encoding='utf-8', delay=False)
