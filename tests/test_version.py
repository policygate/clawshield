"""Verify version consistency between __init__.py and pyproject.toml."""
from pathlib import Path

import clawshield


def test_version_matches_pyproject():
    pyproject = Path(__file__).parent.parent / "pyproject.toml"
    for line in pyproject.read_text().splitlines():
        if line.strip().startswith("version"):
            # Extract version string from: version = "0.3.0"
            pyproject_version = line.split("=", 1)[1].strip().strip('"')
            break
    else:
        raise AssertionError("No version found in pyproject.toml")

    assert clawshield.__version__ == pyproject_version, (
        f"Version mismatch: clawshield/__init__.py has {clawshield.__version__!r}, "
        f"pyproject.toml has {pyproject_version!r}"
    )
