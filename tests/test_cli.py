"""Integration tests for CLI behavior and JSON schema stability."""
import json
from pathlib import Path
from unittest.mock import patch

from clawshield import __version__
from clawshield.__main__ import main

FIXTURES = Path(__file__).parent / "fixtures"

_DOCKER_ROOT_PRIVILEGED = [{
    "Id": "abc123def456",
    "Name": "/openclaw",
    "Config": {"User": "", "Image": "openclaw:latest"},
    "HostConfig": {"Privileged": True},
}]


def _run_main(*args: str, docker_available: bool = False) -> int:
    """Run main() with given CLI args.

    By default, Docker is mocked as unavailable. Set docker_available=True
    to simulate a running root+privileged container.
    """
    if docker_available:
        docker_patches = (
            patch("clawshield.scanners.docker._get_running_container_ids", return_value=(["abc123"], None)),
            patch("clawshield.scanners.docker._inspect_containers", return_value=_DOCKER_ROOT_PRIVILEGED),
        )
    else:
        docker_patches = (
            patch("clawshield.scanners.docker._get_running_container_ids", return_value=(None, "docker binary not found")),
        )

    with patch("sys.argv", ["clawshield", *args]):
        # Apply all Docker patches
        ctx_stack = []
        for p in docker_patches:
            ctx_stack.append(p.__enter__())
        try:
            return main()
        finally:
            for p in reversed(docker_patches):
                p.__exit__(None, None, None)


# --- --fail-on behavior ---

def test_fail_on_critical_exits_1_for_critical(capsys):
    code = _run_main("--fail-on", "critical", str(FIXTURES / "openclaw_vulnerable.yaml"))
    assert code == 1


def test_fail_on_critical_exits_0_for_safe(capsys):
    code = _run_main("--fail-on", "critical", str(FIXTURES / "openclaw_safe.yaml"))
    assert code == 0


def test_fail_on_high_exits_1_for_critical(capsys):
    """Critical >= high threshold, so should still exit 1."""
    code = _run_main("--fail-on", "high", str(FIXTURES / "openclaw_vulnerable.yaml"))
    assert code == 1


def test_fail_on_high_exits_1_for_doc001(capsys):
    """DOC-001 is high severity; --fail-on high should exit 1."""
    code = _run_main(
        "--fail-on", "high",
        str(FIXTURES / "openclaw_safe.yaml"),
        docker_available=True,
    )
    assert code == 1


def test_fail_on_critical_exits_0_for_doc001_only(capsys):
    """DOC-001 is high (not critical); --fail-on critical should exit 0."""
    code = _run_main(
        "--fail-on", "critical",
        str(FIXTURES / "openclaw_safe.yaml"),
        docker_available=True,
    )
    assert code == 0


# --- Golden JSON schema tests ---

def test_golden_json_net001_only(capsys):
    """Lock the JSON schema for a NET-001 finding (no Docker)."""
    _run_main("--json", str(FIXTURES / "openclaw_vulnerable.yaml"))
    output = json.loads(capsys.readouterr().out)

    # Top-level keys
    assert set(output.keys()) == {"meta", "facts", "findings"}

    # meta
    assert output["meta"]["schema_version"] == "0.1"
    assert output["meta"]["tool_version"] == __version__
    assert "vps_public.yaml" in output["meta"]["policy_path"]
    assert isinstance(output["meta"].get("warnings"), list)

    # facts: 2 config + 3 secrets + 3 file permissions
    assert len(output["facts"]) == 8
    for fact in output["facts"]:
        assert set(fact.keys()) == {"key", "value", "source"}
        assert isinstance(fact["key"], str)
        assert isinstance(fact["source"], str)

    fact_keys = {f["key"] for f in output["facts"]}
    assert fact_keys == {
        "network.bind_address", "runtime.auth_enabled",
        "secrets.env_file_present", "secrets.api_key_in_env_file", "secrets.api_key_in_config",
        "files.config_world_writable", "files.env_world_readable", "files.env_world_writable",
    }

    # findings
    assert len(output["findings"]) == 1
    f = output["findings"][0]
    assert set(f.keys()) == {
        "rule_id", "title", "severity", "confidence",
        "evidence", "recommended_actions", "autofix_available",
    }
    assert f["rule_id"] == "NET-001"
    assert f["severity"] == "critical"
    assert f["confidence"] == "high"
    assert isinstance(f["evidence"], list)
    assert isinstance(f["recommended_actions"], list)
    assert isinstance(f["autofix_available"], bool)
    assert len(f["evidence"]) == 2


def test_golden_json_both_rules(capsys):
    """Lock the JSON schema when both NET-001 and DOC-001 fire."""
    _run_main(
        "--json",
        str(FIXTURES / "openclaw_vulnerable.yaml"),
        docker_available=True,
    )
    output = json.loads(capsys.readouterr().out)

    # meta: no warnings when Docker is available
    assert "warnings" not in output["meta"]
    assert output["meta"]["tool_version"] == __version__

    # facts: 2 config + 3 secrets + 3 file permissions + 2 Docker
    assert len(output["facts"]) == 10
    fact_keys = {f["key"] for f in output["facts"]}
    assert fact_keys == {
        "network.bind_address", "runtime.auth_enabled",
        "secrets.env_file_present", "secrets.api_key_in_env_file", "secrets.api_key_in_config",
        "files.config_world_writable", "files.env_world_readable", "files.env_world_writable",
        "docker.user", "docker.privileged",
    }

    # findings: both rules
    assert len(output["findings"]) == 2
    rule_ids = {f["rule_id"] for f in output["findings"]}
    assert rule_ids == {"NET-001", "DOC-001"}

    # Each finding has the full schema
    for f in output["findings"]:
        assert set(f.keys()) == {
            "rule_id", "title", "severity", "confidence",
            "evidence", "recommended_actions", "autofix_available",
        }


def test_golden_json_clean(capsys):
    """Lock the JSON schema when no findings exist."""
    _run_main("--json", str(FIXTURES / "openclaw_safe.yaml"))
    output = json.loads(capsys.readouterr().out)

    assert output["meta"]["schema_version"] == "0.1"
    assert output["meta"]["tool_version"] == __version__
    assert "vps_public.yaml" in output["meta"]["policy_path"]
    assert len(output["findings"]) == 0
    assert len(output["facts"]) == 8  # 2 config + 3 secrets + 3 file permissions


def test_golden_json_empty_config(capsys, tmp_path):
    """Lock the JSON schema for an empty config (no network/auth facts, only secrets facts)."""
    empty_config = tmp_path / "empty.yaml"
    empty_config.write_text("{}")

    _run_main("--json", str(empty_config))
    output = json.loads(capsys.readouterr().out)

    assert output["meta"]["schema_version"] == "0.1"
    assert output["meta"]["tool_version"] == __version__
    assert "policy_path" in output["meta"]
    assert output["findings"] == []
    # Secrets + file permissions scanners produce facts even for empty config
    assert len(output["facts"]) == 6
    fact_keys = {f["key"] for f in output["facts"]}
    assert fact_keys == {
        "secrets.env_file_present", "secrets.api_key_in_env_file", "secrets.api_key_in_config",
        "files.config_world_writable", "files.env_world_readable", "files.env_world_writable",
    }


# --- Human output ---

def test_clean_message_includes_qualifier(capsys):
    _run_main(str(FIXTURES / "openclaw_safe.yaml"))
    stdout = capsys.readouterr().out
    assert "for the checks performed" in stdout


def test_doc001_title_indicates_host_scope(capsys):
    """DOC-001 title should make host-wide scope explicit."""
    _run_main(
        "--json",
        str(FIXTURES / "openclaw_safe.yaml"),
        docker_available=True,
    )
    output = json.loads(capsys.readouterr().out)
    doc001 = [f for f in output["findings"] if f["rule_id"] == "DOC-001"]
    assert len(doc001) == 1
    assert "Host has" in doc001[0]["title"]


# --- Packaging self-check ---

def test_bundled_policy_exists():
    """The default policy YAML must be present in the installed package."""
    policy = Path(__file__).resolve().parent.parent / "clawshield" / "policies" / "vps_public.yaml"
    assert policy.is_file(), f"bundled policy missing: {policy}"


def test_missing_policy_exits_with_message(capsys):
    """A missing policy file should produce a clear error, not a traceback."""
    code = _run_main("--policy", "/nonexistent/policy.yaml", str(FIXTURES / "openclaw_safe.yaml"))
    assert code == 1
    stderr = capsys.readouterr().err
    assert "policy file not found" in stderr
