from unittest.mock import patch

from clawshield.scanners.docker import DockerScanner, parse_inspect_output


# --- parse_inspect_output (pure, no Docker required) ---

def test_detects_root_user_empty_string():
    containers = [{
        "Id": "abc123def456",
        "Name": "/openclaw",
        "Config": {"User": "", "Image": "openclaw:latest"},
        "HostConfig": {"Privileged": False},
    }]
    facts = parse_inspect_output(containers)
    fact_map = {f.key: f.value for f in facts}
    assert fact_map["docker.user"] == "root"
    assert fact_map["docker.privileged"] is False


def test_detects_root_user_explicit():
    containers = [{
        "Id": "abc123",
        "Name": "/app",
        "Config": {"User": "root", "Image": "app:latest"},
        "HostConfig": {"Privileged": False},
    }]
    facts = parse_inspect_output(containers)
    fact_map = {f.key: f.value for f in facts}
    assert fact_map["docker.user"] == "root"


def test_detects_uid_zero_as_root():
    containers = [{
        "Id": "abc123",
        "Name": "/app",
        "Config": {"User": "0:0", "Image": "app:latest"},
        "HostConfig": {"Privileged": False},
    }]
    facts = parse_inspect_output(containers)
    fact_map = {f.key: f.value for f in facts}
    assert fact_map["docker.user"] == "root"


def test_detects_privileged_container():
    containers = [{
        "Id": "abc123",
        "Name": "/openclaw",
        "Config": {"User": "1000", "Image": "openclaw:latest"},
        "HostConfig": {"Privileged": True},
    }]
    facts = parse_inspect_output(containers)
    fact_map = {f.key: f.value for f in facts}
    assert fact_map["docker.user"] == "non-root"
    assert fact_map["docker.privileged"] is True


def test_safe_container():
    containers = [{
        "Id": "abc123",
        "Name": "/openclaw",
        "Config": {"User": "1000:1000", "Image": "openclaw:latest"},
        "HostConfig": {"Privileged": False},
    }]
    facts = parse_inspect_output(containers)
    fact_map = {f.key: f.value for f in facts}
    assert fact_map["docker.user"] == "non-root"
    assert fact_map["docker.privileged"] is False


def test_multiple_containers_worst_case():
    containers = [
        {
            "Id": "safe111",
            "Name": "/safe-app",
            "Config": {"User": "1000", "Image": "app:latest"},
            "HostConfig": {"Privileged": False},
        },
        {
            "Id": "bad222",
            "Name": "/openclaw",
            "Config": {"User": "", "Image": "openclaw:latest"},
            "HostConfig": {"Privileged": True},
        },
    ]
    facts = parse_inspect_output(containers)
    fact_map = {f.key: f.value for f in facts}
    assert fact_map["docker.user"] == "root"
    assert fact_map["docker.privileged"] is True


def test_source_identifies_offending_containers():
    containers = [
        {
            "Id": "safe111",
            "Name": "/safe-app",
            "Config": {"User": "1000", "Image": "app:latest"},
            "HostConfig": {"Privileged": False},
        },
        {
            "Id": "bad222",
            "Name": "/openclaw",
            "Config": {"User": "", "Image": "openclaw:latest"},
            "HostConfig": {"Privileged": True},
        },
    ]
    facts = parse_inspect_output(containers)
    source_map = {f.key: f.source for f in facts}
    assert "openclaw" in source_map["docker.user"]
    assert "openclaw" in source_map["docker.privileged"]
    assert "safe-app" not in source_map["docker.user"]


def test_empty_containers():
    facts = parse_inspect_output([])
    assert facts == []


def test_uses_id_when_name_missing():
    containers = [{"Id": "abcdef123456789", "Config": {"User": ""}, "HostConfig": {"Privileged": False}}]
    facts = parse_inspect_output(containers)
    source_map = {f.key: f.source for f in facts}
    assert "abcdef123456" in source_map["docker.user"]


def test_handles_missing_name_and_none_id():
    """Neither Name nor Id present, or Id is None — should not crash."""
    containers = [{"Config": {"User": ""}, "HostConfig": {"Privileged": False}}]
    facts = parse_inspect_output(containers)
    fact_map = {f.key: f.value for f in facts}
    assert fact_map["docker.user"] == "root"
    assert "unknown" in facts[0].source

    containers_none_id = [{"Id": None, "Config": {"User": ""}, "HostConfig": {"Privileged": False}}]
    facts2 = parse_inspect_output(containers_none_id)
    assert "unknown" in facts2[0].source


def test_source_capped_when_many_containers():
    """Source string should be capped at 5 names + count on hosts with many containers."""
    containers = [
        {"Id": f"id{i}", "Name": f"/container-{i}", "Config": {"User": ""}, "HostConfig": {"Privileged": False}}
        for i in range(12)
    ]
    facts = parse_inspect_output(containers)
    source = facts[0].source
    # Should show first 5 and a count
    assert "+7 more" in source
    assert "container-0" in source
    assert "container-4" in source
    # The 6th container should NOT appear
    assert "container-5" not in source


# --- DockerScanner.scan() with mocked subprocess ---

def test_scan_warns_docker_binary_not_found():
    with patch("clawshield.scanners.docker._get_running_container_ids", return_value=(None, "docker binary not found")):
        scanner = DockerScanner()
        facts, warnings = scanner.scan()
        assert facts == []
        assert any("binary not found" in w for w in warnings)


def test_scan_warns_daemon_not_running():
    reason = "docker ps failed (Cannot connect to the Docker daemon)"
    with patch("clawshield.scanners.docker._get_running_container_ids", return_value=(None, reason)):
        scanner = DockerScanner()
        facts, warnings = scanner.scan()
        assert facts == []
        assert any("Cannot connect" in w for w in warnings)


def test_scan_warns_on_timeout():
    with patch("clawshield.scanners.docker._get_running_container_ids", return_value=(None, "docker command timed out")):
        scanner = DockerScanner()
        facts, warnings = scanner.scan()
        assert facts == []
        assert any("timed out" in w for w in warnings)


def test_scan_silent_when_no_containers():
    with patch("clawshield.scanners.docker._get_running_container_ids", return_value=([], None)):
        scanner = DockerScanner()
        facts, warnings = scanner.scan()
        assert facts == []
        assert warnings == []


def test_scan_warns_on_inspect_failure():
    with (
        patch("clawshield.scanners.docker._get_running_container_ids", return_value=(["abc123"], None)),
        patch("clawshield.scanners.docker._inspect_containers", return_value=None),
    ):
        scanner = DockerScanner()
        facts, warnings = scanner.scan()
        assert facts == []
        assert any("Failed to inspect" in w for w in warnings)


def test_scan_returns_facts_on_success():
    container_data = [{
        "Id": "abc123",
        "Name": "/openclaw",
        "Config": {"User": "", "Image": "openclaw:latest"},
        "HostConfig": {"Privileged": True},
    }]
    with (
        patch("clawshield.scanners.docker._get_running_container_ids", return_value=(["abc123"], None)),
        patch("clawshield.scanners.docker._inspect_containers", return_value=container_data),
    ):
        scanner = DockerScanner()
        facts, warnings = scanner.scan()
        fact_map = {f.key: f.value for f in facts}
        assert fact_map["docker.user"] == "root"
        assert fact_map["docker.privileged"] is True
        assert warnings == []
