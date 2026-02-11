"""Tests for SecretsLiteScanner."""
from pathlib import Path

from clawshield.scanners.openclaw.secrets import SecretsLiteScanner


def _write_config(tmp_path: Path, content: str) -> Path:
    config = tmp_path / "config.yaml"
    config.write_text(content)
    return config


def _write_env(tmp_path: Path, content: str) -> Path:
    env = tmp_path / ".env"
    env.write_text(content)
    return env


# --- .env detection ---

def test_env_file_present(tmp_path):
    config = _write_config(tmp_path, "server:\n  port: 8080\n")
    _write_env(tmp_path, "FOO=bar\n")
    facts = SecretsLiteScanner().scan([config])
    fact_map = {f.key: f.value for f in facts}
    assert fact_map["secrets.env_file_present"] is True


def test_env_file_absent(tmp_path):
    config = _write_config(tmp_path, "server:\n  port: 8080\n")
    facts = SecretsLiteScanner().scan([config])
    fact_map = {f.key: f.value for f in facts}
    assert fact_map["secrets.env_file_present"] is False
    # Always emitted, False when .env doesn't exist
    assert fact_map["secrets.api_key_in_env_file"] is False


# --- .env with API keys ---

def test_env_with_openai_key(tmp_path):
    config = _write_config(tmp_path, "server:\n  port: 8080\n")
    _write_env(tmp_path, "OPENAI_API_KEY=sk-abc123\n")
    facts = SecretsLiteScanner().scan([config])
    fact_map = {f.key: f.value for f in facts}
    assert fact_map["secrets.api_key_in_env_file"] is True


def test_env_with_anthropic_key(tmp_path):
    config = _write_config(tmp_path, "server:\n  port: 8080\n")
    _write_env(tmp_path, "ANTHROPIC_API_KEY=sk-ant-xyz\n")
    facts = SecretsLiteScanner().scan([config])
    fact_map = {f.key: f.value for f in facts}
    assert fact_map["secrets.api_key_in_env_file"] is True


def test_env_with_no_known_keys(tmp_path):
    config = _write_config(tmp_path, "server:\n  port: 8080\n")
    _write_env(tmp_path, "DATABASE_URL=postgres://localhost/db\nDEBUG=true\n")
    facts = SecretsLiteScanner().scan([config])
    fact_map = {f.key: f.value for f in facts}
    assert fact_map["secrets.api_key_in_env_file"] is False


def test_env_comments_and_blanks_ignored(tmp_path):
    config = _write_config(tmp_path, "server:\n  port: 8080\n")
    _write_env(tmp_path, "# OPENAI_API_KEY=sk-old\n\n  \nDEBUG=true\n")
    facts = SecretsLiteScanner().scan([config])
    fact_map = {f.key: f.value for f in facts}
    assert fact_map["secrets.api_key_in_env_file"] is False


# --- Config file with API key names ---

def test_config_with_api_key_reference(tmp_path):
    config = _write_config(tmp_path, "llm:\n  api_key_env: OPENAI_API_KEY\n")
    facts = SecretsLiteScanner().scan([config])
    fact_map = {f.key: f.value for f in facts}
    assert fact_map["secrets.api_key_in_config"] is True


def test_config_without_api_key_reference(tmp_path):
    config = _write_config(tmp_path, "server:\n  port: 8080\n")
    facts = SecretsLiteScanner().scan([config])
    fact_map = {f.key: f.value for f in facts}
    assert fact_map["secrets.api_key_in_config"] is False


def test_config_case_insensitive_match(tmp_path):
    config = _write_config(tmp_path, "key: openai_api_key\n")
    facts = SecretsLiteScanner().scan([config])
    fact_map = {f.key: f.value for f in facts}
    assert fact_map["secrets.api_key_in_config"] is True


# --- Multiple config paths ---

def test_multiple_configs_different_dirs(tmp_path):
    dir_a = tmp_path / "a"
    dir_b = tmp_path / "b"
    dir_a.mkdir()
    dir_b.mkdir()

    config_a = dir_a / "config.yaml"
    config_a.write_text("server:\n  port: 8080\n")
    (dir_a / ".env").write_text("OPENAI_API_KEY=sk-abc\n")

    config_b = dir_b / "config.yaml"
    config_b.write_text("server:\n  port: 9090\n")
    # No .env in dir_b

    facts = SecretsLiteScanner().scan([config_a, config_b])
    env_key_facts = [f for f in facts if f.key == "secrets.api_key_in_env_file"]
    # Both dirs emit the fact; dir_a has key, dir_b doesn't
    assert len(env_key_facts) == 2
    assert any(f.value is True for f in env_key_facts)


def test_env_checked_once_per_directory(tmp_path):
    """Two configs in the same dir should only produce one env_file_present fact."""
    config_a = _write_config(tmp_path, "a: 1\n")
    config_b = tmp_path / "config2.yaml"
    config_b.write_text("b: 2\n")
    _write_env(tmp_path, "FOO=bar\n")

    facts = SecretsLiteScanner().scan([config_a, config_b])
    env_present_facts = [f for f in facts if f.key == "secrets.env_file_present"]
    assert len(env_present_facts) == 1


# --- Source attribution ---

def test_source_includes_file_path(tmp_path):
    config = _write_config(tmp_path, "server:\n  port: 8080\n")
    _write_env(tmp_path, "OPENAI_API_KEY=sk-abc\n")
    facts = SecretsLiteScanner().scan([config])
    for f in facts:
        assert f.source.startswith("secrets_lite:")
