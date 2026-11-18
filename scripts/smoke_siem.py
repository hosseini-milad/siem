"""Functional smoke test for native SIEM. Creates a small, uniquely named demonstration source and evidence."""
import argparse
from datetime import datetime, timezone
import json
from uuid import uuid4

import httpx


def main():
    parser = argparse.ArgumentParser(description='Exercise the native SIEM APIs against MongoDB')
    parser.add_argument('--url', default='http://127.0.0.1:8000')
    args = parser.parse_args()
    source = 'siem-smoke-' + uuid4().hex[:12]
    with httpx.Client(base_url=args.url, timeout=90, trust_env=False) as client:
        def call(method, path, **kwargs):
            response = client.request(method, '/api/v1' + path, **kwargs)
            if not response.is_success:
                raise RuntimeError(f'{method} {path}: HTTP {response.status_code}: {response.text[:500]}')
            return response.json()
        services = call('GET', '/system/status')
        assert services['mongodb']['available']
        batch = {'batch_id': str(uuid4()), 'events': [
            {'timestamp': datetime.now(timezone.utc).isoformat(), 'source': source, 'level': 'WARNING',
             'message': 'SIEM integration smoke event', 'attributes': {'sample': i}} for i in range(3)]}
        accepted = call('POST', '/ingestion/batches', json=batch)
        assert accepted['inserted'] == 3
        state = call('GET', '/ingestion/batches/' + batch['batch_id'])
        assert state['status'] == 'stored'
        assert call('POST', '/ingestion/batches', json=batch)['deduplicated'] == 3
        assert call('GET', '/logs', params={'source': source})['total'] == 3
        filters = {'source': source, 'q': 'integration', 'level': 'WARNING'}
        events = call('GET', '/search/events', params=filters)
        assert events['engine'] == 'mongodb' and events['total'] == 3, events
        stats = call('GET', '/dashboard/charts', params=filters)
        assert stats['event_count'] == 3
        assert sum(row['count'] for row in stats['series']) == 3
        assert client.get('/dashboard').is_success
        rule = call('POST', '/detections/rules', json={'name': source, 'description': 'Smoke threshold rule',
                    'source': source, 'level': 'WARNING', 'threshold': 3})
        call('POST', '/detections/evaluate')
        alerts = call('GET', '/alerts', params={'limit': 200})['items']
        alert = next(item for item in alerts if item.get('rule_id') == rule['id'])
        incident = call('POST', '/incidents', json={'title': source, 'description': 'Smoke incident', 'alert_ids': [alert['id']]})
        call('POST', '/incidents/' + incident['id'] + '/notes', json={'text': 'Verified end-to-end event delivery'})
        report = {'source': source, 'batch_id': accepted['batch_id'], 'stored_events': 3, 'search_hits': events['total'],
                  'rule_id': rule['id'], 'alert_id': alert['id'], 'incident_id': incident['id'],
                  'chart_events': stats['event_count'], 'services': services}
        print(json.dumps(report, indent=2))


if __name__ == '__main__':
    main()
