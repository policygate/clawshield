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
