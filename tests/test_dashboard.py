import pytest

pytest.importorskip("flask")

from trailsight.dashboard import create_app


@pytest.fixture
def client():
    app = create_app()
    app.config.update(TESTING=True)
    return app.test_client()


def test_landing_page_shows_upload(client):
    response = client.get("/")
    assert response.status_code == 200
    assert b"CloudTrail" in response.data
    assert b"Load demo data" in response.data
