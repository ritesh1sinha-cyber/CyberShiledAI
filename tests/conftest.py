import pytest

from app import observability
from app.config import settings


@pytest.fixture(autouse=True)
def offline_tracing(monkeypatch):
    """Keep the suite hermetic: no test may open a Langfuse client."""
    monkeypatch.setattr(settings, "langfuse_enabled", False)
    monkeypatch.setattr(observability, "_client", None)
    monkeypatch.setattr(observability, "_client_unavailable", False)
    monkeypatch.setattr(observability, "_trace", None)
    yield
