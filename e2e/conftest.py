"""Fixtures for the browser tests.

The server is not started here on purpose: these run against a running
instance, local or deployed, chosen with E2E_BASE_URL.
"""
import os
import uuid

import pytest
import requests

BASE_URL = os.getenv("E2E_BASE_URL", "http://127.0.0.1:8000")
PASSWORD = "Str0ngPass!2026"


@pytest.fixture(scope="session")
def base_url() -> str:
    return BASE_URL


@pytest.fixture
def registered_user(base_url):
    """A fresh account, created through the API.

    Registering through the form would work, but it would make every
    sign-in test depend on the registration form as well - and it takes
    about fifty milliseconds here instead of a few seconds in a browser.
    Arrange over the API, act in the browser.
    """
    email = f"e2e-{uuid.uuid4().hex[:10]}@example.com"
    r = requests.post(
        f"{base_url}/auth/register",
        json={"name": "E2E User", "email": email, "password": PASSWORD},
        timeout=10,
    )
    assert r.status_code in (200, 201), f"setup failed: {r.status_code} {r.text}"
    return {"email": email, "password": PASSWORD}
