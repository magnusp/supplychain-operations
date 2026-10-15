import pytest


def pytest_addoption(parser: pytest.Parser) -> None:
    parser.addoption(
        "--live-repo",
        default="magnusp/openbao-seal-spire",
        help="repository that the live smoke test runs against",
    )


@pytest.fixture
def live_repo(request: pytest.FixtureRequest) -> str:
    return request.config.getoption("--live-repo")
