import pytest

import sso_client.client as client_mod


@pytest.fixture(autouse=True)
def _no_backoff(monkeypatch):
    monkeypatch.setattr(client_mod, "BACKOFF", (0, 0))
    monkeypatch.setattr(client_mod.random, "uniform", lambda a, b: 0)
