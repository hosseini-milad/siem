import pytest


@pytest.fixture(autouse=True)
def legacy_api_mode(monkeypatch):
    # Existing API suites exercise their endpoints independently of access control.
    monkeypatch.setenv('SIEM_AUTH_REQUIRED', 'false')
