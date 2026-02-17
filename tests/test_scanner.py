from pathlib import Path

from clawshield.scanners.openclaw.config import OpenClawConfigScanner

FIXTURES = Path(__file__).parent / "fixtures"


def test_scan_vulnerable_config():
    scanner = OpenClawConfigScanner()
    facts = scanner.scan([FIXTURES / "openclaw_vulnerable.yaml"])

    fact_map = {f.key: f.value for f in facts}
    assert fact_map["network.bind_address"] == "0.0.0.0"
    assert fact_map["runtime.auth_enabled"] is False


def test_scan_safe_config():
    scanner = OpenClawConfigScanner()
    facts = scanner.scan([FIXTURES / "openclaw_safe.yaml"])

    fact_map = {f.key: f.value for f in facts}
    assert fact_map["network.bind_address"] == "127.0.0.1"
    assert fact_map["runtime.auth_enabled"] is True


def test_scan_empty_paths():
    scanner = OpenClawConfigScanner()
    facts = scanner.scan([])
    assert facts == []


# --- normalization ---

def test_normalizes_string_false_to_bool():
    scanner = OpenClawConfigScanner()
    facts = scanner.scan([FIXTURES / "openclaw_string_bools.yaml"])

    fact_map = {f.key: f.value for f in facts}
    assert fact_map["runtime.auth_enabled"] is False
    assert isinstance(fact_map["runtime.auth_enabled"], bool)


def test_normalizes_string_true_to_bool():
    scanner = OpenClawConfigScanner()
    facts = scanner.scan([FIXTURES / "openclaw_string_true.yaml"])

    fact_map = {f.key: f.value for f in facts}
    assert fact_map["runtime.auth_enabled"] is True
    assert isinstance(fact_map["runtime.auth_enabled"], bool)


def test_strips_whitespace_from_bind_address():
    scanner = OpenClawConfigScanner()
    facts = scanner.scan([FIXTURES / "openclaw_string_bools.yaml"])

    fact_map = {f.key: f.value for f in facts}
    assert fact_map["network.bind_address"] == "0.0.0.0"
    assert " " not in fact_map["network.bind_address"]


# --- JSON config format (openclaw.json) ---

def test_scan_json_vulnerable_config():
    scanner = OpenClawConfigScanner()
    facts = scanner.scan([FIXTURES / "openclaw_vulnerable.json"])

    fact_map = {f.key: f.value for f in facts}
    assert fact_map["network.bind_address"] == "0.0.0.0"
    assert fact_map["runtime.auth_enabled"] is False
    assert fact_map["runtime.auth_mode"] == "none"
    assert fact_map["sandbox.enabled"] is False
    assert fact_map["tools.shell_enabled"] is True
    assert fact_map["browser.enabled"] is True
    assert fact_map["logging.redaction_enabled"] is True
    assert fact_map["logging.file_logs_redacted"] is False


def test_scan_json_safe_config():
    scanner = OpenClawConfigScanner()
    facts = scanner.scan([FIXTURES / "openclaw_safe.json"])

    fact_map = {f.key: f.value for f in facts}
    assert fact_map["network.bind_address"] == "127.0.0.1"
    assert fact_map["runtime.auth_enabled"] is True
    assert fact_map["runtime.auth_mode"] == "token"
    assert fact_map["runtime.auth_token_length"] == 48


def test_scan_json_no_auth_section():
    """When gateway exists but auth is missing entirely, treat as auth disabled."""
    scanner = OpenClawConfigScanner()
    facts = scanner.scan([FIXTURES / "openclaw_no_auth.json"])

    fact_map = {f.key: f.value for f in facts}
    assert fact_map["network.bind_address"] == "0.0.0.0"
    assert fact_map["runtime.auth_enabled"] is False
    assert fact_map["runtime.auth_mode"] == "none"


def test_scan_json_loopback_maps_to_localhost():
    """OpenClaw's 'loopback' bind mode should map to 127.0.0.1."""
    scanner = OpenClawConfigScanner()
    facts = scanner.scan([FIXTURES / "openclaw_safe.json"])

    fact_map = {f.key: f.value for f in facts}
    assert fact_map["network.bind_address"] == "127.0.0.1"


def test_scan_json_lan_maps_to_public():
    """OpenClaw's 'lan' bind mode should map to 0.0.0.0 (public exposure)."""
    scanner = OpenClawConfigScanner()
    facts = scanner.scan([FIXTURES / "openclaw_vulnerable.json"])

    fact_map = {f.key: f.value for f in facts}
    assert fact_map["network.bind_address"] == "0.0.0.0"


def test_scan_json_token_auth_is_enabled():
    """Auth mode 'token' should be treated as auth enabled."""
    scanner = OpenClawConfigScanner()
    facts = scanner.scan([FIXTURES / "openclaw_safe.json"])

    fact_map = {f.key: f.value for f in facts}
    assert fact_map["runtime.auth_enabled"] is True


def test_scan_json_none_auth_is_disabled():
    """Auth mode 'none' should be treated as auth disabled."""
    scanner = OpenClawConfigScanner()
    facts = scanner.scan([FIXTURES / "openclaw_vulnerable.json"])

    fact_map = {f.key: f.value for f in facts}
    assert fact_map["runtime.auth_enabled"] is False


# --- Defaulted fact tests ---

def test_json_sandbox_defaults_to_disabled():
    """Absent sandbox config → sandbox.enabled=False (documented default)."""
    scanner = OpenClawConfigScanner()
    facts = scanner.scan([FIXTURES / "openclaw_safe.json"])

    fact_map = {f.key: f.value for f in facts}
    assert fact_map["sandbox.enabled"] is False
    # Source should indicate this was defaulted
    sandbox_fact = [f for f in facts if f.key == "sandbox.enabled"][0]
    assert "defaulted" in sandbox_fact.source


def test_json_shell_defaults_to_enabled():
    """Absent tools config → full profile → shell enabled (documented default)."""
    scanner = OpenClawConfigScanner()
    facts = scanner.scan([FIXTURES / "openclaw_safe.json"])

    fact_map = {f.key: f.value for f in facts}
    assert fact_map["tools.shell_enabled"] is True
    shell_fact = [f for f in facts if f.key == "tools.shell_enabled"][0]
    assert "defaulted" in shell_fact.source


def test_json_browser_defaults_to_enabled():
    """Absent browser config → browser.enabled=True (documented default)."""
    scanner = OpenClawConfigScanner()
    facts = scanner.scan([FIXTURES / "openclaw_safe.json"])

    fact_map = {f.key: f.value for f in facts}
    assert fact_map["browser.enabled"] is True
    browser_fact = [f for f in facts if f.key == "browser.enabled"][0]
    assert "defaulted" in browser_fact.source


def test_json_redaction_defaults_to_enabled():
    """Absent logging config → redaction enabled (documented default: 'tools')."""
    scanner = OpenClawConfigScanner()
    facts = scanner.scan([FIXTURES / "openclaw_safe.json"])

    fact_map = {f.key: f.value for f in facts}
    assert fact_map["logging.redaction_enabled"] is True
    assert fact_map["logging.file_logs_redacted"] is False


def test_json_file_logs_tagged_as_documented():
    """File log redaction fact should cite documented behavior."""
    scanner = OpenClawConfigScanner()
    facts = scanner.scan([FIXTURES / "openclaw_safe.json"])

    log_fact = [f for f in facts if f.key == "logging.file_logs_redacted"][0]
    assert "documented behavior" in log_fact.source


def test_json_explicit_sandbox_enabled(tmp_path):
    """Explicit sandbox mode != 'off' → sandbox.enabled=True."""
    config = tmp_path / "openclaw.json"
    config.write_text('{"gateway": {"bind": "loopback"}, "agents": {"defaults": {"sandbox": {"mode": "container"}}}}')

    scanner = OpenClawConfigScanner()
    facts = scanner.scan([config])

    fact_map = {f.key: f.value for f in facts}
    assert fact_map["sandbox.enabled"] is True
    sandbox_fact = [f for f in facts if f.key == "sandbox.enabled"][0]
    assert "defaulted" not in sandbox_fact.source


def test_json_tools_deny_disables_shell(tmp_path):
    """If exec is in tools.deny, shell should be disabled."""
    config = tmp_path / "openclaw.json"
    config.write_text('{"gateway": {"bind": "loopback"}, "tools": {"deny": ["exec"]}}')

    scanner = OpenClawConfigScanner()
    facts = scanner.scan([config])

    fact_map = {f.key: f.value for f in facts}
    assert fact_map["tools.shell_enabled"] is False


def test_json_tools_deny_disables_browser(tmp_path):
    """If browser is in tools.deny, browser should be disabled."""
    config = tmp_path / "openclaw.json"
    config.write_text('{"gateway": {"bind": "loopback"}, "tools": {"deny": ["browser"]}}')

    scanner = OpenClawConfigScanner()
    facts = scanner.scan([config])

    fact_map = {f.key: f.value for f in facts}
    assert fact_map["browser.enabled"] is False


def test_json_strong_token_not_weak():
    """A 48-char hex token should not be flagged as weak."""
    scanner = OpenClawConfigScanner()
    facts = scanner.scan([FIXTURES / "openclaw_safe.json"])

    fact_map = {f.key: f.value for f in facts}
    assert fact_map["runtime.auth_token_weak"] is False


def test_json_short_token_is_weak(tmp_path):
    """A token shorter than 32 chars should be flagged as weak."""
    config = tmp_path / "openclaw.json"
    config.write_text('{"gateway": {"auth": {"mode": "token", "token": "abc123"}}}')

    scanner = OpenClawConfigScanner()
    facts = scanner.scan([config])

    fact_map = {f.key: f.value for f in facts}
    assert fact_map["runtime.auth_token_weak"] is True
    assert fact_map["runtime.auth_token_length"] == 6


def test_json_placeholder_token_is_weak(tmp_path):
    """A common placeholder token should be flagged as weak."""
    config = tmp_path / "openclaw.json"
    config.write_text('{"gateway": {"auth": {"mode": "token", "token": "changeme"}}}')

    scanner = OpenClawConfigScanner()
    facts = scanner.scan([config])

    fact_map = {f.key: f.value for f in facts}
    assert fact_map["runtime.auth_token_weak"] is True


def test_json_redaction_off_detected(tmp_path):
    """Explicit redactSensitive=off → redaction disabled."""
    config = tmp_path / "openclaw.json"
    config.write_text('{"gateway": {"bind": "loopback"}, "logging": {"redactSensitive": "off"}}')

    scanner = OpenClawConfigScanner()
    facts = scanner.scan([config])

    fact_map = {f.key: f.value for f in facts}
    assert fact_map["logging.redaction_enabled"] is False


def test_yaml_and_json_can_coexist():
    """Scanner should handle a mix of YAML and JSON config files."""
    scanner = OpenClawConfigScanner()
    facts = scanner.scan([
        FIXTURES / "openclaw_safe.yaml",
        FIXTURES / "openclaw_vulnerable.json",
    ])

    # Should have facts from both files
    sources = {f.source for f in facts}
    assert any("openclaw_safe.yaml" in s for s in sources)
    assert any("openclaw_vulnerable.json" in s for s in sources)
