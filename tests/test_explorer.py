from datetime import datetime, timezone
from uuid import uuid4

from fastapi.testclient import TestClient
from pymongo import MongoClient

from app.core.config import Settings
from app.main import create_app


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
                {'_id': 'flow:4', 'Timestamp': str(int(stamp.timestamp() * 1000))},
                {'_id': 'flow:5', 'Timestamp': '2026-11-18T08:00:00Z'},
            ])
            db.normal_records.insert_one({'_id': 'flow:1', 'original_id': 'flow:1', 'Dst Port': .44})
            db.ml_predictions.insert_one({'_id': 'flow:1', 'original_id': 'flow:1', 'attack_probability': .85})
            with TestClient(create_app(settings)) as client:
                def get(**query):
                    result = client.get('/api/v1/explorer/records', params=query)
                    assert result.status_code == 200, result.text
                    return result.json()

                page = get(**day, source_ip='192.0.2.10', destination_port=443, protocol='TCP',
                           risk='critical', q='attack', limit=1)
                assert page['total'] == 1
                row = page['items'][0]
                assert row['raw'] == raw
                assert row['normalized']['original_id'] == 'flow:1'
                assert row['risk']['attack_probability'] == .85
                assert row['timestamp'] == '2026-11-17T21:00:00+00:00'
                assert get(**day, risk='unscored')['total'] == 2
                assert get(**day, limit=1, offset=1)['items'][0]['id'] == 'flow:4'
                assert get(q='flow:3')['items'][0]['timestamp'] is None
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
                assert client.get('/api/v1/explorer/records', params={'destination_port': 65536}).status_code == 422
                assert client.get('/api/v1/explorer/records', params={'start': day['end'], 'end': day['start']}).status_code == 422
        finally:
            mongo.drop_database(settings.mongodb_database)
