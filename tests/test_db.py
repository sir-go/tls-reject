import pytest
from reject import update_list


class MockedCursor:
    result_rows = [0]

    @staticmethod
    def __init__(*args, **kwargs):
        pass

    def execute(self, query: str):
        if query.startswith('select time from events'):
            self.result_rows = [999]
        if query == 'select hostname from https_domains':
            self.result_rows = [
                ('hostname0',),
                ('hostname1',),
                ('hostname2',)
            ]

    def fetchall(self):
        return self.result_rows

    def fetchone(self):
        return self.result_rows[0]

    def __enter__(self):
        return self

    @staticmethod
    def __exit__(exc_type, exc_val, exc_tb):
        pass


class MockedConnection:
    @staticmethod
    def __init__(*args, **kwargs):
        pass

    @staticmethod
    def cursor():
        return MockedCursor()

    def __enter__(self):
        return self

    @staticmethod
    def __exit__(exc_type, exc_val, exc_tb):
        pass


@pytest.fixture(autouse=True)
def fake_conn(monkeypatch):
    monkeypatch.setattr('pymysql.connect', MockedConnection)


def test_update_list():
    d_list = {'hostname-a', 'hostname1'}
    new_time = update_list(0, d_list)
    assert ','.join(sorted(
        d_list)) == 'hostname-a,hostname0,hostname1,hostname2'
    assert new_time == 999
