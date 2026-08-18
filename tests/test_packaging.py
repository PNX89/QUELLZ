import tomllib
from pathlib import Path

import quellz

PYPROJECT = Path(__file__).resolve().parents[1] / "pyproject.toml"


def test_the_core_install_has_no_runtime_dependencies():
    project = tomllib.loads(PYPROJECT.read_text(encoding="utf-8"))["project"]
    assert project["dependencies"] == []
    assert project["version"] == quellz.__version__
