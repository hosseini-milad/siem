from datetime import datetime, timezone
from uuid import uuid4

from fastapi.testclient import TestClient
from pymongo import MongoClient

from app.core.config import Settings
from app.main import create_app
from app.services.explorer import indexed_dataset_window


def test_explorer_joins_and_filters_real_mongodb(tmp_path):
    settings = Settings(mongodb_database='siem_test_' + uuid4().hex, ml_model_dir=str(tmp_path))
    stamp = datetime(2026, 11, 17, 21, tzinfo=timezone.utc)
    day = {'start': '2026-11-18T00:00:00+03:30', 'end': '2026-11-19T00:00:00+03:30'}
    with MongoClient(settings.mongodb_uri) as mongo:
        db = mongo[settings.mongodb_database]
        try:
            raw = {'_id': 'flow:1', 'Timestamp': str(int(stamp.timestamp())), ' Src IP ': '192.0.2.10',
                   'Dst Port': '443', 'Protocol': '6', 'Label': 'Attack', 'columns': 'original'}
            db.dataset_records.insert_many([
                raw,
                {'_id': 'flow:2', 'Timestamp': '2026-11-18T20:30:00Z'},
                {'_id': 'flow:3', 'Timestamp': '10'},
                {'_id': 'flow:4', 'Timestamp': str(int(stamp.timestamp() * 1000)), 'Label': ' 0 '},
                {'_id': 'flow:5', 'Timestamp': '2026-11-18T08:00:00Z', 'Label': '0.65'},
            ])
            db.normal_records.insert_many([
                {'_id': 'norm:1', 'original_id': 'flow:1', 'Label': 0, 'Dst Port': .44},
                {'_id': 'norm:3', 'original_id': 'flow:3', 'Label': 1},
            ])
            db.standard_records.insert_many([
                {'_id': 'standard:1', 'original_id': 'flow:1', 'Label': 1},
                {'_id': 'standard:4', 'original_id': 'flow:4', 'Label': 0},
                {'_id': 'standard:5', 'original_id': 'flow:5', 'Label': .65},
            ])
            db.ml_predictions.insert_one({'_id': 'flow:1', 'original_id': 'flow:1', 'attack_probability': .85})
            with TestClient(create_app(settings)) as client:
                def get(**query):
                    result = client.get('/api/v1/explorer/records', params=query)
                    assert result.status_code == 200, result.text
                    return result.json()

                page = get(**day, source_ip='192.0.2.10', destination_port=443, protocol='TCP',
                           risk='attack', q='attack', limit=1)
                assert page['total'] == 1
                row = page['items'][0]
                assert row['raw'] == raw
                assert row['normalized']['original_id'] == 'flow:1'
                assert row['standardized']['_id'] == 'standard:1'
                assert row['normalized']['Label'] == 0
                assert get(q='flow:3')['items'][0]['risk'] is None
                assert row['risk'] == {'score': 1, 'severity': 'attack'}
                assert get(**day, risk='high')['items'][0]['risk'] == {'score': .65, 'severity': 'high'}
                assert get(**day, risk='benign')['items'][0]['risk'] == {'score': 0, 'severity': 'benign'}
                assert row['timestamp'] == '2026-11-17T21:00:00+00:00'
                assert get(**day, risk='unscored')['total'] == 0
                assert get(**day, limit=1, offset=1)['items'][0]['id'] == 'flow:4'
                assert get(q='flow:3')['items'][0]['timestamp'] is None
                assert get(risk='unscored')['total'] == 2
                assert get(q='.*')['total'] == 0

                event = {'timestamp': stamp.isoformat(), 'source': 'test', 'level': 'INFO',
                         'message': 'Test [literal]', 'attributes': {'source_ip': '192.0.2.10', 'port': 443}}
                assert client.post('/api/v1/logs', json=event).status_code == 201
                logs = get(kind='logs', **day, q='[literal]', destination_port=443, level='INFO')
                assert logs['total'] == 1
                assert logs['items'][0]['raw']['attributes'] == event['attributes']
                assert logs['items'][0]['risk'] is None
                assert logs['items'][0]['normalized'] is None
                assert get(kind='logs', risk='critical')['total'] == 0
                event['attributes']['Label'] = 0.9
                assert client.post('/api/v1/logs', json=event).status_code == 201
                assert get(kind='logs', risk='critical')['total'] == 0
                assert get(kind='logs', risk='unscored')['total'] == 2
                assert client.get('/api/v1/explorer/records', params={'destination_port': 65536}).status_code == 422
                assert client.get('/api/v1/explorer/records', params={'start': day['end'], 'end': day['start']}).status_code == 422
        finally:
            mongo.drop_database(settings.mongodb_database)


def test_explorer_uses_timestamp_index_for_2025_seconds(tmp_path):
    settings = Settings(mongodb_database='siem_test_' + uuid4().hex, ml_model_dir=str(tmp_path))
    start = datetime.fromisoformat('2025-05-17T20:30:00+00:00')
    end = datetime.fromisoformat('2025-05-18T20:30:00+00:00')
    with MongoClient(settings.mongodb_uri) as mongo:
        db = mongo[settings.mongodb_database]
        try:
            first, last = int(start.timestamp()), int(end.timestamp())
            db.dataset_records.insert_many([
                {'_id': str(i), 'Timestamp': str(last + i)} for i in range(1, 5001)
            ] + [
                {'_id': 'lower', 'Timestamp': str(first)},
                {'_id': 'upper', 'Timestamp': str(last)},
                {'_id': 'numeric', 'Timestamp': first + 1},
            ])
            with TestClient(create_app(settings)) as client:
                result = client.get('/api/v1/explorer/records', params={
                    'kind': 'data', 'start': start.isoformat(), 'end': end.isoformat(), 'limit': 15,
                })
                assert result.status_code == 200, result.text
                assert result.json()['total'] == 2
                assert [row['id'] for row in result.json()['items']] == ['numeric', 'lower']

                plan = db.command('explain', {
                    'find': 'dataset_records', 'filter': indexed_dataset_window(start, end)[0]['$match'],
                }, verbosity='executionStats')
                assert plan['executionStats']['totalDocsExamined'] < 20
        finally:
            mongo.drop_database(settings.mongodb_database)


def test_candidate_cap_is_independent_of_page_size(tmp_path):
    settings = Settings(mongodb_database='siem_test_' + uuid4().hex, ml_model_dir=str(tmp_path))
    stamp = datetime(2025, 5, 18, 12, tzinfo=timezone.utc)
    with MongoClient(settings.mongodb_uri) as mongo:
        db = mongo[settings.mongodb_database]
        try:
            for collection, fields in [
                (db.dataset_records, {'Timestamp': str(int(stamp.timestamp()))}),
                (db.log_events, {'timestamp': stamp, 'message': 'Example', 'source': 'test', 'level': 'INFO'}),
            ]:
                collection.insert_many([{'_id': f'example-{index:04}', **fields} for index in range(1010)])
            with TestClient(create_app(settings)) as client:
                for kind in ('data', 'logs'):
                    path = '/api/v1/explorer/records'
                    params = {'kind': kind, 'start': '2025-05-18T00:00:00Z', 'end': '2025-05-19T00:00:00Z'}
                    page = client.get(path, params={**params, 'limit': 15, 'offset': 990})
                    assert page.status_code == 200, page.text
                    assert page.json()['total'] == 1000
                    assert len(page.json()['items']) == 10
                    assert client.get(path, params={**params, 'offset': 1000}).json()['items'] == []
                    excluded = client.get(path, params={**params, 'q': 'example-0000'})
                    assert excluded.json()['total'] == 0
        finally:
            mongo.drop_database(settings.mongodb_database)
