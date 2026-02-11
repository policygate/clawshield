"""File permissions scanner: detects world-readable/writable config and .env files.

Only meaningful on POSIX systems. On Windows, all permission facts emit False.
"""
from __future__ import annotations

import os
import stat
from pathlib import Path

from ...core.models import Fact

_IS_POSIX = os.name != "nt"


class FilePermissionsScanner:
    """Checks file permissions on OpenClaw config and .env files."""

    name = "file_permissions"

    def scan(self, config_paths: list[Path]) -> list[Fact]:
        facts: list[Fact] = []

        checked_dirs: set[Path] = set()
        for config_path in config_paths:
            config_dir = config_path.parent

            # Config file: only check world-writable
            mode = _get_mode(config_path)
            facts.append(Fact(
                key="files.config_world_writable",
                value=_is_world_writable(mode),
                source=f"file_permissions:{config_path}",
            ))

            # .env: check once per directory
            if config_dir not in checked_dirs:
                checked_dirs.add(config_dir)
                env_path = config_dir / ".env"
                if env_path.is_file():
                    env_mode = _get_mode(env_path)
                    facts.append(Fact(
                        key="files.env_world_readable",
                        value=_is_world_readable(env_mode),
                        source=f"file_permissions:{env_path}",
                    ))
                    facts.append(Fact(
                        key="files.env_world_writable",
                        value=_is_world_writable(env_mode),
                        source=f"file_permissions:{env_path}",
                    ))
                else:
                    facts.append(Fact(
                        key="files.env_world_readable",
                        value=False,
                        source=f"file_permissions:{env_path}",
                    ))
                    facts.append(Fact(
                        key="files.env_world_writable",
                        value=False,
                        source=f"file_permissions:{env_path}",
                    ))

        return facts


def _get_mode(path: Path) -> int | None:
    """Return file mode bits, or None if not available."""
    if not _IS_POSIX:
        return None
    try:
        return path.stat().st_mode
    except OSError:
        return None


def _is_world_readable(mode: int | None) -> bool:
    if mode is None:
        return False
    return bool(mode & stat.S_IROTH)


def _is_world_writable(mode: int | None) -> bool:
    if mode is None:
        return False
    return bool(mode & stat.S_IWOTH)
