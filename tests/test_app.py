import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

import app as app_module


def test_health_endpoint_returns_ok():
    client = app_module.app.test_client()

    response = client.get("/health")

    assert response.status_code == 200
    assert response.get_json() == {"status": "ok"}


def test_home_page_loads():
    client = app_module.app.test_client()

    response = client.get("/")

    assert response.status_code == 200
    assert b"DevOps AI Assistant" in response.data
    assert b"Cloud / DevOps / DevSecOps questions only" in response.data


def test_post_without_gemini_key_shows_configuration_error(monkeypatch):
    client = app_module.app.test_client()
    monkeypatch.setattr(app_module, "API_KEY", "")
    monkeypatch.setattr(app_module, "model", None)

    response = client.post("/", data={"question": "What is Docker?"})

    assert response.status_code == 200
    assert b"ERROR: GEMINI_API_KEY is not set on the server." in response.data
