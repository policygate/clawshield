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
