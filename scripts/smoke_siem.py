"""Functional ELK smoke test. Creates a small, uniquely named demonstration source and evidence."""
import argparse
from datetime import datetime, timezone
import json
from time import monotonic, sleep
from uuid import uuid4

import httpx


def main():
    parser = argparse.ArgumentParser(description='Exercise real Logstash, MongoDB, Elasticsearch and Kibana through the SIEM API')
    parser.add_argument('--url', default='http://127.0.0.1:8000')
    args = parser.parse_args()
    source = 'siem-smoke-' + uuid4().hex[:12]
    with httpx.Client(base_url=args.url, timeout=90, trust_env=False) as client:
        def call(method, path, **kwargs):
            response = client.request(method, '/api/v1' + path, **kwargs)
            if not response.is_success:
                raise RuntimeError(f'{method} {path}: HTTP {response.status_code}: {response.text[:500]}')
            return response.json()
        deadline = monotonic() + 90
        while True:
            services = call('GET', '/system/status?include_elk=true')
            if all(item['available'] for item in services['elk']):
                break
            if monotonic() >= deadline:
                raise RuntimeError(f'Services did not become ready: {services}')
            sleep(1)
        batch = {'batch_id': str(uuid4()), 'events': [
            {'timestamp': datetime.now(timezone.utc).isoformat(), 'source': source, 'level': 'WARNING',
             'message': 'SIEM integration smoke event', 'attributes': {'sample': i}} for i in range(3)]}
        accepted = call('POST', '/logstash/ingest', json=batch)
        deadline = monotonic() + 90
        while True:
            state = call('GET', '/ingestion/batches/' + batch['batch_id'])
            if state['status'] == 'stored':
                break
            if monotonic() >= deadline:
                raise RuntimeError(f'Logstash did not deliver the batch: {state}')
            sleep(1)
        assert call('GET', '/logs', params={'source': source})['total'] == 3
        # Explicit replay exercises receiver idempotency independently of async queue timing.
        assert call('POST', '/ingestion/logstash', json=batch)['deduplicated'] == 3
        call('POST', '/elasticsearch/setup')
        while True:
            result = call('POST', '/elasticsearch/sync', json={'limit': 5000})
            if result['indexed'] < 5000:
                break
        events = call('GET', '/search/events', params={'source': source, 'q': 'integration'})
        assert events['total'] == 3, events
        assert call('POST', '/elasticsearch/sync', json={'limit': 5000})['indexed'] == 0
        rule = call('POST', '/detections/rules', json={'name': source, 'description': 'Smoke threshold rule',
                    'source': source, 'level': 'WARNING', 'threshold': 3})
        call('POST', '/detections/evaluate')
        alerts = call('GET', '/alerts', params={'limit': 200})['items']
        alert = next(item for item in alerts if item.get('rule_id') == rule['id'])
        incident = call('POST', '/incidents', json={'title': source, 'description': 'Smoke incident', 'alert_ids': [alert['id']]})
        call('POST', '/incidents/' + incident['id'] + '/notes', json={'text': 'Verified end-to-end event delivery'})
        dashboard = call('POST', '/kibana/setup')
        assert any(item['id'] == dashboard['dashboard_id'] for item in call('GET', '/kibana/dashboards')['items'])
        report = {'source': source, 'batch_id': accepted['batch_id'], 'stored_events': 3, 'search_hits': events['total'],
                  'rule_id': rule['id'], 'alert_id': alert['id'], 'incident_id': incident['id'],
                  'kibana': dashboard, 'services': services['elk']}
        print(json.dumps(report, indent=2))


if __name__ == '__main__':
    main()
