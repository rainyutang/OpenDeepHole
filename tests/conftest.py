"""Each test owns its application state; services never retain test dictionaries."""

import pytest

from backend.application import BackendRuntime, use_runtime


@pytest.fixture(autouse=True)
def application_runtime():
    with use_runtime(BackendRuntime()) as runtime:
        yield runtime
