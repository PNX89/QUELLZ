import socket

import pytest

from quellz.cli import DEMO_ALLOWED_SENSITIVITY, DEMO_ALLOWED_TOOLS
from quellz.contain import LeastPrivilege, SpotlightWrapper
from quellz.mock import NaiveMockAgent
from quellz.report import Report
from quellz.runner import run_suite
from quellz.types import Agent


@pytest.fixture(scope="session", autouse=True)
def _no_network():
    """Any accidental network call has to fail loudly rather than reach a real host."""

    def blocked(*args: object, **kwargs: object) -> None:
        raise RuntimeError("the QUELLZ test suite does not touch the network")

    with pytest.MonkeyPatch.context() as patch:
        patch.setattr(socket, "socket", blocked)
        yield


def contained_agent() -> Agent:
    """The demo containment configuration, built from the policy the CLI ships."""
    return LeastPrivilege(
        SpotlightWrapper(NaiveMockAgent()),
        allowed_tools=DEMO_ALLOWED_TOOLS,
        allowed_sensitivity=DEMO_ALLOWED_SENSITIVITY,
    )


@pytest.fixture(scope="session")
def baseline() -> Report:
    return run_suite(NaiveMockAgent, label="baseline")


@pytest.fixture(scope="session")
def contained() -> Report:
    return run_suite(contained_agent, label="contained")
