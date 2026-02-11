"""Tests for FilePermissionsScanner.

Uses mocked stat results for cross-platform compatibility (Unix permission
bits are not meaningful on Windows).
"""
import stat
from pathlib import Path
from unittest.mock import patch

from clawshield.scanners.openclaw.permissions import FilePermissionsScanner


def _write_config(tmp_path: Path, content: str = "server:\n  port: 8080\n") -> Path:
    config = tmp_path / "config.yaml"
    config.write_text(content)
    return config


def _write_env(tmp_path: Path, content: str = "FOO=bar\n") -> Path:
    env = tmp_path / ".env"
    env.write_text(content)
    return env


class _FakeStat:
    def __init__(self, mode: int):
        self.st_mode = mode


def _mock_posix_scan(config_paths, mode_map):
    """Run scanner with mocked POSIX stat results.

    mode_map: dict mapping Path -> int (mode bits)
    """
    def fake_get_mode(path):
        if path in mode_map:
            return mode_map[path]
        return None

    with patch("clawshield.scanners.openclaw.permissions._IS_POSIX", True), \
         patch("clawshield.scanners.openclaw.permissions._get_mode", side_effect=fake_get_mode):
        return FilePermissionsScanner().scan(config_paths)


# --- Config world-writable ---

def test_config_world_writable(tmp_path):
    config = _write_config(tmp_path)
    mode = stat.S_IRUSR | stat.S_IWUSR | stat.S_IRGRP | stat.S_IWOTH  # 0o642
    facts = _mock_posix_scan([config], {config: mode})
    fact_map = {f.key: f.value for f in facts}
    assert fact_map["files.config_world_writable"] is True


def test_config_not_world_writable(tmp_path):
    config = _write_config(tmp_path)
    mode = stat.S_IRUSR | stat.S_IWUSR | stat.S_IRGRP  # 0o640
    facts = _mock_posix_scan([config], {config: mode})
    fact_map = {f.key: f.value for f in facts}
    assert fact_map["files.config_world_writable"] is False


def test_config_safe_600(tmp_path):
    config = _write_config(tmp_path)
    mode = stat.S_IRUSR | stat.S_IWUSR  # 0o600
    facts = _mock_posix_scan([config], {config: mode})
    fact_map = {f.key: f.value for f in facts}
    assert fact_map["files.config_world_writable"] is False


# --- .env world-readable ---

def test_env_world_readable(tmp_path):
    config = _write_config(tmp_path)
    env = _write_env(tmp_path)
    mode_env = stat.S_IRUSR | stat.S_IWUSR | stat.S_IROTH  # 0o604
    mode_config = stat.S_IRUSR | stat.S_IWUSR  # 0o600
    facts = _mock_posix_scan([config], {config: mode_config, env: mode_env})
    fact_map = {f.key: f.value for f in facts}
    assert fact_map["files.env_world_readable"] is True
    assert fact_map["files.env_world_writable"] is False


def test_env_world_writable(tmp_path):
    config = _write_config(tmp_path)
    env = _write_env(tmp_path)
    mode_env = stat.S_IRUSR | stat.S_IWUSR | stat.S_IWOTH  # 0o602
    mode_config = stat.S_IRUSR | stat.S_IWUSR
    facts = _mock_posix_scan([config], {config: mode_config, env: mode_env})
    fact_map = {f.key: f.value for f in facts}
    assert fact_map["files.env_world_writable"] is True


def test_env_777(tmp_path):
    """chmod 777 triggers both world-readable and world-writable."""
    config = _write_config(tmp_path)
    env = _write_env(tmp_path)
    mode_777 = 0o777
    mode_config = stat.S_IRUSR | stat.S_IWUSR
    facts = _mock_posix_scan([config], {config: mode_config, env: mode_777})
    fact_map = {f.key: f.value for f in facts}
    assert fact_map["files.env_world_readable"] is True
    assert fact_map["files.env_world_writable"] is True


def test_env_safe_600(tmp_path):
    config = _write_config(tmp_path)
    env = _write_env(tmp_path)
    mode_safe = stat.S_IRUSR | stat.S_IWUSR  # 0o600
    facts = _mock_posix_scan([config], {config: mode_safe, env: mode_safe})
    fact_map = {f.key: f.value for f in facts}
    assert fact_map["files.env_world_readable"] is False
    assert fact_map["files.env_world_writable"] is False


# --- .env absent ---

def test_env_absent_emits_false(tmp_path):
    config = _write_config(tmp_path)
    mode_config = stat.S_IRUSR | stat.S_IWUSR
    facts = _mock_posix_scan([config], {config: mode_config})
    fact_map = {f.key: f.value for f in facts}
    assert fact_map["files.env_world_readable"] is False
    assert fact_map["files.env_world_writable"] is False


# --- Windows (non-POSIX) ---

def test_windows_emits_all_false(tmp_path):
    config = _write_config(tmp_path)
    _write_env(tmp_path)
    with patch("clawshield.scanners.openclaw.permissions._IS_POSIX", False):
        facts = FilePermissionsScanner().scan([config])
    fact_map = {f.key: f.value for f in facts}
    assert fact_map["files.config_world_writable"] is False
    assert fact_map["files.env_world_readable"] is False
    assert fact_map["files.env_world_writable"] is False


# --- Source attribution ---

def test_source_includes_path(tmp_path):
    config = _write_config(tmp_path)
    env = _write_env(tmp_path)
    mode = stat.S_IRUSR | stat.S_IWUSR
    facts = _mock_posix_scan([config], {config: mode, env: mode})
    for f in facts:
        assert f.source.startswith("file_permissions:")


# --- Dedup ---

def test_env_checked_once_per_directory(tmp_path):
    config_a = _write_config(tmp_path)
    config_b = tmp_path / "config2.yaml"
    config_b.write_text("b: 2\n")
    _write_env(tmp_path)
    mode = stat.S_IRUSR | stat.S_IWUSR
    facts = _mock_posix_scan([config_a, config_b], {config_a: mode, config_b: mode, tmp_path / ".env": mode})
    env_readable_facts = [f for f in facts if f.key == "files.env_world_readable"]
    assert len(env_readable_facts) == 1
