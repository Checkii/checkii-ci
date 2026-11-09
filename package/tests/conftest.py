"""Fixtures: a running fake control plane and a token in the environment."""

from __future__ import annotations

import pytest
from fake_control_plane import TOKEN, FakeControlPlane


@pytest.fixture
def control_plane():
    fake = FakeControlPlane().start()
    try:
        yield fake
    finally:
        fake.stop()


@pytest.fixture
def token_env(monkeypatch):
    monkeypatch.delenv("AEGIS_API_TOKEN", raising=False)
    monkeypatch.delenv("CHECKII_API_URL", raising=False)
    monkeypatch.delenv("AEGIS_API_URL", raising=False)
    monkeypatch.setenv("CHECKII_API_TOKEN", TOKEN)
    return TOKEN
