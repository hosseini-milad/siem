import pytest
from fastapi.testclient import TestClient
from pydantic import ValidationError

from app.core.config import Settings
from app.main import create_app


@pytest.mark.parametrize('name', [
    'mongodb_socket_timeout_ms', 'mongodb_connect_timeout_ms',
    'mongodb_server_selection_timeout_ms',
])
def test_timeout_environment_and_validation(name, monkeypatch):
    monkeypatch.setenv('SIEM_' + name.upper(), '120000')
    assert getattr(Settings(_env_file=None), name) == 120000
    monkeypatch.setenv('SIEM_' + name.upper(), '0')
    assert getattr(Settings(_env_file=None), name) == 0
    monkeypatch.setenv('SIEM_' + name.upper(), '-1')
    with pytest.raises(ValidationError):
        Settings(_env_file=None)


@pytest.mark.parametrize('socket_ms', [0, 120000])
def test_client_receives_configured_timeouts(socket_ms):
    config = Settings(mongodb_socket_timeout_ms=socket_ms,
                      mongodb_connect_timeout_ms=7000,
                      mongodb_server_selection_timeout_ms=9000)
    with TestClient(create_app(config)) as client:
        options = client.app.state.database.client.options
        assert options.pool_options.socket_timeout == (socket_ms / 1000 or None)
        assert options.pool_options.connect_timeout == 7
        assert options.server_selection_timeout == 9
        assert client.get('/api/v1/health').json()['status'] == 'ok'
