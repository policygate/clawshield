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


def test_scan_json_safe_config():
    scanner = OpenClawConfigScanner()
    facts = scanner.scan([FIXTURES / "openclaw_safe.json"])

    fact_map = {f.key: f.value for f in facts}
    assert fact_map["network.bind_address"] == "127.0.0.1"
    assert fact_map["runtime.auth_enabled"] is True


def test_scan_json_no_auth_section():
    """When gateway exists but auth is missing entirely, treat as auth disabled."""
    scanner = OpenClawConfigScanner()
    facts = scanner.scan([FIXTURES / "openclaw_no_auth.json"])

    fact_map = {f.key: f.value for f in facts}
    assert fact_map["network.bind_address"] == "0.0.0.0"
    assert fact_map["runtime.auth_enabled"] is False


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
