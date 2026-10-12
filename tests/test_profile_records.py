import sqlite3
from unittest.mock import Mock

import pytest

from app import create_app
from services.ip_threat import IPThreatError


class Cursor:
    def __init__(self, db):
        self.cursor = db.cursor()
    def __enter__(self):
        return self
    def __exit__(self, *args):
        self.cursor.close()
    def execute(self, sql, args=()):
        self.cursor.execute(sql.replace('%s', '?'), args)
    def fetchall(self):
        return [dict(row) for row in self.cursor.fetchall()]
    def fetchone(self):
        row = self.cursor.fetchone()
        return dict(row) if row else None


@pytest.fixture
def client(monkeypatch):
    db = sqlite3.connect(':memory:')
    db.row_factory = sqlite3.Row
    db.execute('CREATE TABLE user_threats (id INTEGER PRIMARY KEY, owner_sub TEXT, name TEXT, severity TEXT, category TEXT, description TEXT, mitigation TEXT)')
    adapter = Mock()
    adapter.cursor.side_effect = lambda: Cursor(db)
    adapter.commit.side_effect = db.commit
    adapter.rollback.side_effect = db.rollback
    monkeypatch.setattr('routes.threats.get_db', lambda: adapter)
    monkeypatch.setattr('services.devices.get_db', lambda: adapter)
    app = create_app('development')
    app.config.update(TESTING=True, SECRET_KEY='test-key')
    client = app.test_client()
    with client.session_transaction() as session:
        session['user'] = {'sub': 'owner', 'name': 'Tester', 'email': 'test@example.com'}
        session['records_csrf'] = 'token'
        session['profile_csrf'] = 'token'
    yield client
    db.close()


def test_threat_crud_and_ownership(client):
    payload = dict(csrf_token='token', name='Example threat', severity='High', category='Malware', description='Example description', mitigation='Patch systems')
    assert client.post('/my-threats/new', data=payload).status_code == 302
    assert b'Example threat' in client.get('/my-threats').data
    assert client.get('/my-threats/1/edit').status_code == 200
    payload['name'] = 'Updated threat'
    assert client.post('/my-threats/1/edit', data=payload).status_code == 302
    assert b'Updated threat' in client.get('/my-threats').data
    with client.session_transaction() as session:
        session['user']['sub'] = 'other'
        session.modified = True
    assert b'Updated threat' not in client.get('/my-threats').data
    assert client.post('/my-threats/1/edit', data=payload).status_code == 404
    assert client.post('/my-threats/1/delete', data={'csrf_token': 'token'}).status_code == 404
    with client.session_transaction() as session:
        session['user']['sub'] = 'owner'
        session.modified = True
    assert client.post('/my-threats/1/delete', data={'csrf_token': 'token'}).status_code == 302
    assert b'Updated threat' not in client.get('/my-threats').data


@pytest.mark.parametrize('path', ['/my-threats/new', '/profile/devices', '/profile/devices/1/check', '/profile/devices/1/delete'])
def test_csrf(client, path):
    assert client.post(path).status_code == 400


def test_validation(client):
    assert client.post('/my-threats/new', data={'csrf_token': 'token'}).status_code == 400
    assert b'No threat records' in client.get('/my-threats').data


def test_device_validation_and_create(client, monkeypatch):
    create = Mock()
    monkeypatch.setattr('services.devices.create_device', create)
    payload = {'csrf_token': 'token', 'name': 'Laptop', 'ip_address': '192.168.1.1'}
    client.post('/profile/devices', data=payload)
    create.assert_not_called()
    payload['ip_address'] = '8.8.8.8'
    client.post('/profile/devices', data=payload)
    create.assert_called_once_with('owner', 'Laptop', '8.8.8.8')


def test_device_ownership(client, monkeypatch):
    lookup = Mock(return_value=None)
    monkeypatch.setattr('services.devices.get_device', lookup)
    for action in ['edit', 'delete', 'check']:
        assert client.post(f'/profile/devices/2/{action}', data={'csrf_token': 'token'}).status_code == 404
    lookup.assert_called_with('owner', 2)


def test_status_and_failure(client, monkeypatch):
    monkeypatch.setattr('services.devices.get_device', lambda owner, device_id: {'id': 1, 'ip_address': '8.8.8.8'})
    analyze = Mock(return_value={'score': 0})
    save = Mock()
    monkeypatch.setattr('routes.profile.analyze_ip', analyze)
    monkeypatch.setattr('services.devices.save_result', save)
    assert client.post('/profile/devices/1/check', data={'csrf_token': 'token'}).status_code == 302
    save.assert_called_once_with('owner', 1, '8.8.8.8', {'score': 0})
    save.reset_mock()
    analyze.side_effect = IPThreatError('Unavailable')
    assert client.post('/profile/devices/1/check', data={'csrf_token': 'token'}).status_code == 302
    save.assert_not_called()


def test_profile_and_login_required(client, monkeypatch):
    monkeypatch.setattr('services.devices.list_devices', lambda owner: [])
    assert b'No devices saved' in client.get('/profile').data
    with client.session_transaction() as session:
        session.clear()
    for path in ['/profile', '/my-threats']:
        response = client.get(path)
        assert response.status_code == 302
        assert '/login/google' in response.location
