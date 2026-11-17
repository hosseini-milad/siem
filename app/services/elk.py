"""HTTP integrations with real ELK services; MongoDB remains the source of truth."""
from datetime import datetime, timezone
import json

import httpx


class IntegrationUnavailable(Exception):
    pass


class Elk:
    def __init__(self, settings, client):
        self.settings = settings
        self.client = client

    def request(self, service, method, path, *, decode=True, **kwargs):
        base = str(getattr(self.settings, service + '_url')).rstrip('/')
        try:
            response = self.client.request(method, base + path, **kwargs)
            if response.status_code >= 400:
                raise IntegrationUnavailable(f'{service} returned HTTP {response.status_code}; check service configuration')
            return response.json() if decode else response
        except (httpx.HTTPError, ValueError) as exc:
            raise IntegrationUnavailable(f'{service} is unavailable or returned an invalid response') from exc

    def status(self, service):
        path = {'elasticsearch': '/_cluster/health', 'logstash': '/_node/stats/pipelines', 'kibana': '/api/status'}[service]
        try:
            data = self.request(service, 'GET', path)
            if service == 'elasticsearch':
                details = {key: data.get(key) for key in ('status', 'number_of_nodes', 'active_shards')}
            elif service == 'logstash':
                details = {'pipelines': list(data.get('pipelines', {})), 'status': data.get('status')}
            else:
                details = {'status': data.get('status', {}).get('overall', {}).get('level'),
                           'version': data.get('version', {}).get('number')}
            return {'service': service, 'available': True, **details}
        except IntegrationUnavailable as exc:
            return {'service': service, 'available': False, 'error': str(exc)}

    def ensure_index(self):
        name = self.settings.elasticsearch_index
        existing = self.request('elasticsearch', 'GET', '/_cat/indices/' + name + '?format=json&ignore_unavailable=true')
        if existing:
            mapping = self.request('elasticsearch', 'GET', '/' + name + '/_mapping')
            properties = mapping[name]['mappings'].get('properties', {})
            if properties.get('@timestamp', {}).get('type') != 'date':
                raise IntegrationUnavailable('Existing index has an incompatible mapping; configure a new SIEM index')
            return {'index': name, 'created': False}
        self.request('elasticsearch', 'PUT', '/' + name, json={
            'settings': {'number_of_shards': 1, 'number_of_replicas': 0},
            'mappings': {'dynamic': 'strict', 'properties': {
                '@timestamp': {'type': 'date'}, 'message': {'type': 'text'},
                'event': {'properties': {'id': {'type': 'keyword'}, 'kind': {'type': 'keyword'}}},
                'log': {'properties': {'level': {'type': 'keyword'}}},
                'siem': {'properties': {'source': {'type': 'keyword'}, 'attributes': {'type': 'flattened'}}}}}})
        return {'index': name, 'created': True}

    def sync(self, db, limit):
        initialized = self.ensure_index()
        if initialized['created']:
            db.log_events.update_many({}, {'$unset': {'_search_index': ''}})
        query = {'_search_index': {'$ne': self.settings.elasticsearch_index}}
        processed = 0
        while processed < limit:
            rows = list(db.log_events.find(query).sort([('received_at', 1), ('_id', 1)]).limit(min(500, limit - processed)))
            if not rows:
                break
            lines = []
            for row in rows:
                lines.append(json.dumps({'index': {'_index': self.settings.elasticsearch_index, '_id': row['_id']}}))
                lines.append(json.dumps({'@timestamp': row['timestamp'].isoformat(), 'message': row['message'],
                    'event': {'id': row['_id'], 'kind': 'event'}, 'log': {'level': row['level']},
                    'siem': {'source': row['source'], 'attributes': row.get('attributes', {})}}))
            result = self.request('elasticsearch', 'POST', '/_bulk?refresh=wait_for',
                                  content='\n'.join(lines) + '\n', headers={'Content-Type': 'application/x-ndjson'})
            if result.get('errors') or len(result.get('items', [])) != len(rows):
                raise IntegrationUnavailable('Bulk indexing failed; checkpoint is unchanged for this batch. Retry safely.')
            last = rows[-1]
            db.elastic_sync_state.update_one({'_id': 'log_events'}, {'$set': {
                'received_at': last['received_at'], 'event_id': last['_id'],
                'index': self.settings.elasticsearch_index, 'updated_at': datetime.now(timezone.utc)}}, upsert=True)
            db.log_events.update_many({'_id': {'$in': [row['_id'] for row in rows]}},
                                      {'$set': {'_search_index': self.settings.elasticsearch_index}})
            processed += len(rows)
        return {'indexed': processed, 'limit': limit, 'checkpoint': db.elastic_sync_state.find_one({'_id': 'log_events'})}

    def search(self, *, query, source, level, start, end, limit, offset):
        filters = [{'range': {'@timestamp': {'gte': start.isoformat(), 'lte': end.isoformat()}}}]
        if source:
            filters.append({'term': {'siem.source': source}})
        if level:
            filters.append({'term': {'log.level': level}})
        must = [{'simple_query_string': {'query': query, 'fields': ['message', 'siem.source'], 'default_operator': 'and'}}] if query else []
        result = self.request('elasticsearch', 'POST', '/' + self.settings.elasticsearch_index + '/_search', json={
            'query': {'bool': {'filter': filters, 'must': must}}, 'track_total_hits': True,
            'size': limit, 'from': offset, 'sort': [{'@timestamp': 'desc'}, {'event.id': 'desc'}]})
        return {'items': [{'id': item['_id'], **item['_source']} for item in result['hits']['hits']],
                'total': result['hits']['total']['value'], 'limit': limit, 'offset': offset, 'engine': 'elasticsearch'}

    def bootstrap_kibana(self):
        index = self.settings.elasticsearch_index
        view_id = 'siem-events'
        headers = {'kbn-xsrf': 'siem'}
        self.request('kibana', 'POST', '/api/data_views/data_view', headers=headers, json={
            'data_view': {'id': view_id, 'name': 'SIEM Events', 'title': index, 'timeFieldName': '@timestamp'}, 'override': True})
        objects = []
        for identity, title, kind, field in [('siem-volume', 'Event volume', 'histogram', '@timestamp'),
                                              ('siem-levels', 'Log levels', 'pie', 'log.level'),
                                              ('siem-sources', 'Top sources', 'histogram', 'siem.source')]:
            bucket = {'id': '2', 'enabled': True, 'type': 'date_histogram' if field == '@timestamp' else 'terms',
                      'schema': 'segment', 'params': {'field': field, **({'interval': 'auto', 'min_doc_count': 1}
                                                      if field == '@timestamp' else {'size': 10, 'order': 'desc', 'orderBy': '1'})}}
            objects.append({'type': 'visualization', 'id': identity,
                'attributes': {'title': title, 'visState': json.dumps({'title': title, 'type': kind,
                    'params': {'addLegend': True}, 'aggs': [{'id': '1', 'enabled': True, 'type': 'count', 'schema': 'metric', 'params': {}}, bucket]}),
                    'uiStateJSON': '{}', 'kibanaSavedObjectMeta': {'searchSourceJSON': json.dumps({
                        'query': {'language': 'kuery', 'query': ''}, 'filter': [],
                        'indexRefName': 'kibanaSavedObjectMeta.searchSourceJSON.index'})}},
                'references': [{'name': 'kibanaSavedObjectMeta.searchSourceJSON.index', 'type': 'index-pattern', 'id': view_id}]})
        panels = [{'type': 'visualization', 'panelRefName': f'panel_{i}', 'embeddableConfig': {},
                   'gridData': {'x': (i % 2) * 24, 'y': (i // 2) * 15, 'w': 24, 'h': 15, 'i': str(i + 1)},
                   'panelIndex': str(i + 1)} for i in range(3)]
        objects.append({'type': 'dashboard', 'id': 'siem-overview', 'attributes': {
            'title': 'SIEM Overview', 'description': 'SIEM events indexed from MongoDB', 'panelsJSON': json.dumps(panels),
            'optionsJSON': '{"useMargins":true,"hidePanelTitles":false}', 'timeRestore': True,
            'timeFrom': 'now-24h', 'timeTo': 'now',
            'kibanaSavedObjectMeta': {'searchSourceJSON': '{"query":{"language":"kuery","query":""},"filter":[]}'}},
            'references': [{'name': f'panel_{i}', 'type': 'visualization', 'id': item['id']} for i, item in enumerate(objects)]})
        data = '\n'.join(json.dumps(item) for item in objects) + '\n'
        result = self.request('kibana', 'POST', '/api/saved_objects/_import?overwrite=true', headers=headers,
                              files={'file': ('siem.ndjson', data.encode(), 'application/ndjson')})
        if not result.get('success'):
            raise IntegrationUnavailable('Kibana saved object import failed; check compatible Kibana version')
        return {'data_view_id': view_id, 'dashboard_id': 'siem-overview', 'imported': result.get('successCount', 0)}
