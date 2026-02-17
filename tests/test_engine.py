from pathlib import Path

import pytest
import yaml

from clawshield.core.engine import PolicyEngine, PolicyLoadError
from clawshield.core.models import Fact

POLICY_PATH = Path(__file__).parent.parent / "clawshield" / "policies" / "vps_public.yaml"


# --- evaluation ---

def test_net001_finding_on_vulnerable_config():
    engine = PolicyEngine(POLICY_PATH)
    facts = [
        Fact(key="network.bind_address", value="0.0.0.0", source="test"),
        Fact(key="runtime.auth_enabled", value=False, source="test"),
    ]
    result = engine.evaluate(facts)

    assert len(result.findings) == 1
    f = result.findings[0]
    assert f.rule_id == "NET-001"
    assert f.severity == "critical"
    assert f.autofix_available is True
    assert "ACT-ENABLE-AUTH" in f.recommended_actions
    assert len(f.evidence) == 2
    assert result.warnings == []


def test_no_finding_on_safe_config():
    engine = PolicyEngine(POLICY_PATH)
    facts = [
        Fact(key="network.bind_address", value="127.0.0.1", source="test"),
        Fact(key="runtime.auth_enabled", value=True, source="test"),
    ]
    result = engine.evaluate(facts)
    assert len(result.findings) == 0


def test_no_finding_when_auth_enabled():
    engine = PolicyEngine(POLICY_PATH)
    facts = [
        Fact(key="network.bind_address", value="0.0.0.0", source="test"),
        Fact(key="runtime.auth_enabled", value=True, source="test"),
    ]
    result = engine.evaluate(facts)
    assert len(result.findings) == 0


def test_doc001_finding_on_root_container():
    engine = PolicyEngine(POLICY_PATH)
    facts = [
        Fact(key="network.bind_address", value="127.0.0.1", source="test"),
        Fact(key="runtime.auth_enabled", value=True, source="test"),
        Fact(key="docker.user", value="root", source="docker_inspect:openclaw"),
        Fact(key="docker.privileged", value=False, source="docker_inspect:openclaw"),
    ]
    result = engine.evaluate(facts)
    assert len(result.findings) == 1
    f = result.findings[0]
    assert f.rule_id == "DOC-001"
    assert f.severity == "high"


def test_doc001_finding_on_privileged_container():
    engine = PolicyEngine(POLICY_PATH)
    facts = [
        Fact(key="network.bind_address", value="127.0.0.1", source="test"),
        Fact(key="runtime.auth_enabled", value=True, source="test"),
        Fact(key="docker.user", value="non-root", source="docker_inspect:openclaw"),
        Fact(key="docker.privileged", value=True, source="docker_inspect:openclaw"),
    ]
    result = engine.evaluate(facts)
    assert len(result.findings) == 1
    assert result.findings[0].rule_id == "DOC-001"


def test_no_doc001_on_safe_container():
    engine = PolicyEngine(POLICY_PATH)
    facts = [
        Fact(key="network.bind_address", value="127.0.0.1", source="test"),
        Fact(key="runtime.auth_enabled", value=True, source="test"),
        Fact(key="docker.user", value="non-root", source="docker_inspect:openclaw"),
        Fact(key="docker.privileged", value=False, source="docker_inspect:openclaw"),
    ]
    result = engine.evaluate(facts)
    assert len(result.findings) == 0


def test_both_rules_fire_together():
    engine = PolicyEngine(POLICY_PATH)
    facts = [
        Fact(key="network.bind_address", value="0.0.0.0", source="test"),
        Fact(key="runtime.auth_enabled", value=False, source="test"),
        Fact(key="docker.user", value="root", source="docker_inspect:openclaw"),
        Fact(key="docker.privileged", value=True, source="docker_inspect:openclaw"),
    ]
    result = engine.evaluate(facts)
    rule_ids = {f.rule_id for f in result.findings}
    assert rule_ids == {"NET-001", "DOC-001"}


def test_file001_finding_on_world_writable_config():
    engine = PolicyEngine(POLICY_PATH)
    facts = [
        Fact(key="network.bind_address", value="127.0.0.1", source="test"),
        Fact(key="runtime.auth_enabled", value=True, source="test"),
        Fact(key="files.config_world_writable", value=True, source="file_permissions:test"),
        Fact(key="files.env_world_readable", value=False, source="file_permissions:test"),
        Fact(key="files.env_world_writable", value=False, source="file_permissions:test"),
    ]
    result = engine.evaluate(facts)
    file_findings = [f for f in result.findings if f.rule_id == "FILE-001"]
    assert len(file_findings) == 1
    assert file_findings[0].severity == "high"


def test_file001_finding_on_env_world_readable():
    engine = PolicyEngine(POLICY_PATH)
    facts = [
        Fact(key="network.bind_address", value="127.0.0.1", source="test"),
        Fact(key="runtime.auth_enabled", value=True, source="test"),
        Fact(key="files.config_world_writable", value=False, source="file_permissions:test"),
        Fact(key="files.env_world_readable", value=True, source="file_permissions:test"),
        Fact(key="files.env_world_writable", value=False, source="file_permissions:test"),
    ]
    result = engine.evaluate(facts)
    file_findings = [f for f in result.findings if f.rule_id == "FILE-001"]
    assert len(file_findings) == 1


def test_no_file001_on_safe_permissions():
    engine = PolicyEngine(POLICY_PATH)
    facts = [
        Fact(key="network.bind_address", value="127.0.0.1", source="test"),
        Fact(key="runtime.auth_enabled", value=True, source="test"),
        Fact(key="files.config_world_writable", value=False, source="file_permissions:test"),
        Fact(key="files.env_world_readable", value=False, source="file_permissions:test"),
        Fact(key="files.env_world_writable", value=False, source="file_permissions:test"),
    ]
    result = engine.evaluate(facts)
    file_findings = [f for f in result.findings if f.rule_id == "FILE-001"]
    assert len(file_findings) == 0


# --- NET-002 ---

def test_net002_fires_on_public_bind_with_password_auth():
    engine = PolicyEngine(POLICY_PATH)
    facts = [
        Fact(key="network.bind_address", value="0.0.0.0", source="test"),
        Fact(key="runtime.auth_enabled", value=True, source="test"),
        Fact(key="runtime.auth_mode", value="password", source="test"),
    ]
    result = engine.evaluate(facts)
    net002 = [f for f in result.findings if f.rule_id == "NET-002"]
    assert len(net002) == 1
    assert net002[0].severity == "high"


def test_net002_does_not_fire_with_token_auth():
    engine = PolicyEngine(POLICY_PATH)
    facts = [
        Fact(key="network.bind_address", value="0.0.0.0", source="test"),
        Fact(key="runtime.auth_enabled", value=True, source="test"),
        Fact(key="runtime.auth_mode", value="token", source="test"),
    ]
    result = engine.evaluate(facts)
    net002 = [f for f in result.findings if f.rule_id == "NET-002"]
    assert len(net002) == 0


def test_net002_does_not_fire_on_localhost():
    engine = PolicyEngine(POLICY_PATH)
    facts = [
        Fact(key="network.bind_address", value="127.0.0.1", source="test"),
        Fact(key="runtime.auth_mode", value="password", source="test"),
    ]
    result = engine.evaluate(facts)
    net002 = [f for f in result.findings if f.rule_id == "NET-002"]
    assert len(net002) == 0


# --- AUTH-001 ---

def test_auth001_fires_on_weak_token():
    engine = PolicyEngine(POLICY_PATH)
    facts = [
        Fact(key="network.bind_address", value="127.0.0.1", source="test"),
        Fact(key="runtime.auth_enabled", value=True, source="test"),
        Fact(key="runtime.auth_token_weak", value=True, source="test"),
    ]
    result = engine.evaluate(facts)
    auth001 = [f for f in result.findings if f.rule_id == "AUTH-001"]
    assert len(auth001) == 1
    assert auth001[0].severity == "medium"


def test_auth001_does_not_fire_on_strong_token():
    engine = PolicyEngine(POLICY_PATH)
    facts = [
        Fact(key="network.bind_address", value="127.0.0.1", source="test"),
        Fact(key="runtime.auth_enabled", value=True, source="test"),
        Fact(key="runtime.auth_token_weak", value=False, source="test"),
    ]
    result = engine.evaluate(facts)
    auth001 = [f for f in result.findings if f.rule_id == "AUTH-001"]
    assert len(auth001) == 0


# --- SANDBOX-001 ---

def test_sandbox001_fires_when_disabled_with_shell():
    engine = PolicyEngine(POLICY_PATH)
    facts = [
        Fact(key="network.bind_address", value="127.0.0.1", source="test"),
        Fact(key="runtime.auth_enabled", value=True, source="test"),
        Fact(key="sandbox.enabled", value=False, source="test"),
        Fact(key="tools.shell_enabled", value=True, source="test"),
        Fact(key="browser.enabled", value=False, source="test"),
    ]
    result = engine.evaluate(facts)
    sandbox = [f for f in result.findings if f.rule_id == "SANDBOX-001"]
    assert len(sandbox) == 1
    assert sandbox[0].severity == "high"


def test_sandbox001_fires_when_disabled_with_browser():
    engine = PolicyEngine(POLICY_PATH)
    facts = [
        Fact(key="network.bind_address", value="127.0.0.1", source="test"),
        Fact(key="runtime.auth_enabled", value=True, source="test"),
        Fact(key="sandbox.enabled", value=False, source="test"),
        Fact(key="tools.shell_enabled", value=False, source="test"),
        Fact(key="browser.enabled", value=True, source="test"),
    ]
    result = engine.evaluate(facts)
    sandbox = [f for f in result.findings if f.rule_id == "SANDBOX-001"]
    assert len(sandbox) == 1


def test_sandbox001_does_not_fire_when_sandbox_enabled():
    engine = PolicyEngine(POLICY_PATH)
    facts = [
        Fact(key="network.bind_address", value="127.0.0.1", source="test"),
        Fact(key="runtime.auth_enabled", value=True, source="test"),
        Fact(key="sandbox.enabled", value=True, source="test"),
        Fact(key="tools.shell_enabled", value=True, source="test"),
        Fact(key="browser.enabled", value=True, source="test"),
    ]
    result = engine.evaluate(facts)
    sandbox = [f for f in result.findings if f.rule_id == "SANDBOX-001"]
    assert len(sandbox) == 0


def test_sandbox001_does_not_fire_when_no_risky_tools():
    engine = PolicyEngine(POLICY_PATH)
    facts = [
        Fact(key="network.bind_address", value="127.0.0.1", source="test"),
        Fact(key="runtime.auth_enabled", value=True, source="test"),
        Fact(key="sandbox.enabled", value=False, source="test"),
        Fact(key="tools.shell_enabled", value=False, source="test"),
        Fact(key="browser.enabled", value=False, source="test"),
    ]
    result = engine.evaluate(facts)
    sandbox = [f for f in result.findings if f.rule_id == "SANDBOX-001"]
    assert len(sandbox) == 0


# --- TOOL-001 ---

def test_tool001_fires_when_shell_enabled():
    engine = PolicyEngine(POLICY_PATH)
    facts = [
        Fact(key="network.bind_address", value="127.0.0.1", source="test"),
        Fact(key="runtime.auth_enabled", value=True, source="test"),
        Fact(key="tools.shell_enabled", value=True, source="test"),
    ]
    result = engine.evaluate(facts)
    tool001 = [f for f in result.findings if f.rule_id == "TOOL-001"]
    assert len(tool001) == 1
    assert tool001[0].severity == "medium"


def test_tool001_does_not_fire_when_shell_disabled():
    engine = PolicyEngine(POLICY_PATH)
    facts = [
        Fact(key="network.bind_address", value="127.0.0.1", source="test"),
        Fact(key="runtime.auth_enabled", value=True, source="test"),
        Fact(key="tools.shell_enabled", value=False, source="test"),
    ]
    result = engine.evaluate(facts)
    tool001 = [f for f in result.findings if f.rule_id == "TOOL-001"]
    assert len(tool001) == 0


# --- TOOL-002 ---

def test_tool002_fires_when_browser_enabled():
    engine = PolicyEngine(POLICY_PATH)
    facts = [
        Fact(key="network.bind_address", value="127.0.0.1", source="test"),
        Fact(key="runtime.auth_enabled", value=True, source="test"),
        Fact(key="browser.enabled", value=True, source="test"),
    ]
    result = engine.evaluate(facts)
    tool002 = [f for f in result.findings if f.rule_id == "TOOL-002"]
    assert len(tool002) == 1
    assert tool002[0].severity == "medium"


def test_tool002_does_not_fire_when_browser_disabled():
    engine = PolicyEngine(POLICY_PATH)
    facts = [
        Fact(key="network.bind_address", value="127.0.0.1", source="test"),
        Fact(key="runtime.auth_enabled", value=True, source="test"),
        Fact(key="browser.enabled", value=False, source="test"),
    ]
    result = engine.evaluate(facts)
    tool002 = [f for f in result.findings if f.rule_id == "TOOL-002"]
    assert len(tool002) == 0


# --- LOG-001 ---

def test_log001_fires_when_redaction_disabled():
    engine = PolicyEngine(POLICY_PATH)
    facts = [
        Fact(key="network.bind_address", value="127.0.0.1", source="test"),
        Fact(key="runtime.auth_enabled", value=True, source="test"),
        Fact(key="logging.redaction_enabled", value=False, source="test"),
    ]
    result = engine.evaluate(facts)
    log001 = [f for f in result.findings if f.rule_id == "LOG-001"]
    assert len(log001) == 1
    assert log001[0].severity == "medium"


def test_log001_does_not_fire_when_redaction_enabled():
    engine = PolicyEngine(POLICY_PATH)
    facts = [
        Fact(key="network.bind_address", value="127.0.0.1", source="test"),
        Fact(key="runtime.auth_enabled", value=True, source="test"),
        Fact(key="logging.redaction_enabled", value=True, source="test"),
    ]
    result = engine.evaluate(facts)
    log001 = [f for f in result.findings if f.rule_id == "LOG-001"]
    assert len(log001) == 0


# --- LOG-002 ---

def test_log002_fires_when_console_redacted_but_files_not():
    engine = PolicyEngine(POLICY_PATH)
    facts = [
        Fact(key="network.bind_address", value="127.0.0.1", source="test"),
        Fact(key="runtime.auth_enabled", value=True, source="test"),
        Fact(key="logging.redaction_enabled", value=True, source="test"),
        Fact(key="logging.file_logs_redacted", value=False, source="test"),
    ]
    result = engine.evaluate(facts)
    log002 = [f for f in result.findings if f.rule_id == "LOG-002"]
    assert len(log002) == 1
    assert log002[0].severity == "low"


def test_log002_does_not_fire_when_redaction_fully_off():
    """LOG-002 only fires when console redaction is on but file logs aren't."""
    engine = PolicyEngine(POLICY_PATH)
    facts = [
        Fact(key="network.bind_address", value="127.0.0.1", source="test"),
        Fact(key="runtime.auth_enabled", value=True, source="test"),
        Fact(key="logging.redaction_enabled", value=False, source="test"),
        Fact(key="logging.file_logs_redacted", value=False, source="test"),
    ]
    result = engine.evaluate(facts)
    log002 = [f for f in result.findings if f.rule_id == "LOG-002"]
    assert len(log002) == 0


def test_duplicate_fact_warns_with_sources():
    engine = PolicyEngine(POLICY_PATH)
    facts = [
        Fact(key="network.bind_address", value="127.0.0.1", source="config-a.yaml"),
        Fact(key="network.bind_address", value="0.0.0.0", source="config-b.yaml"),
        Fact(key="runtime.auth_enabled", value=False, source="config-b.yaml"),
    ]
    result = engine.evaluate(facts)

    assert len(result.warnings) == 1
    assert "config-a.yaml" in result.warnings[0]
    assert "config-b.yaml" in result.warnings[0]
    assert "2 times" in result.warnings[0]


# --- validation ---

def test_rejects_policy_missing_rule_keys(tmp_path):
    policy = tmp_path / "bad.yaml"
    policy.write_text(yaml.dump({"rules": [{"id": "X"}]}))
    with pytest.raises(PolicyLoadError, match="missing keys"):
        PolicyEngine(policy)


def test_rejects_policy_with_bad_condition(tmp_path):
    policy = tmp_path / "bad.yaml"
    policy.write_text(yaml.dump({
        "rules": [{
            "id": "X", "title": "x", "severity": "low", "confidence": "low",
            "condition": {"fact": "x", "op": "nope", "value": 1},
        }]
    }))
    with pytest.raises(PolicyLoadError, match="unknown operator"):
        PolicyEngine(policy)


def test_rejects_non_dict_policy(tmp_path):
    policy = tmp_path / "bad.yaml"
    policy.write_text("just a string")
    with pytest.raises(PolicyLoadError, match="expected a YAML mapping"):
        PolicyEngine(policy)
