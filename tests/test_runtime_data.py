from sentinel_x_defense_suite.gui.runtime_data import (
    build_defense_playbook,
    build_runtime_snapshot,
    detect_service_versions,
    parse_active_connections,
    parse_listening_sockets,
    suggested_connection_defense_commands,
    suggested_service_admin_commands,
)


def test_parse_listening_sockets_detects_open_service() -> None:
    raw = 'tcp LISTEN 0 128 0.0.0.0:8080 0.0.0.0:* users:(("python3",pid=123,fd=5))'
    services = parse_listening_sockets(raw)
    assert services
    assert services[0]["port"] == 8080
    assert services[0]["process"] == "python3"
    assert services[0]["service"] in {"http-alt", "http"}


def test_parse_python_http_server_port() -> None:
    raw = 'tcp LISTEN 0 5 0.0.0.0:8000 0.0.0.0:* users:(("python3",pid=321,fd=3))'
    services = parse_listening_sockets(raw)
    assert services
    assert services[0]["port"] == 8000
    assert services[0]["process"] == "python3"


def test_parse_active_connections_detects_remote_peer() -> None:
    raw = 'tcp ESTAB 0 0 10.0.0.5:443 203.0.113.25:55123 users:(("nginx",pid=20,fd=10))'
    conns = parse_active_connections(raw)
    assert conns
    assert conns[0]["dst_ip"] == "203.0.113.25"
    assert conns[0]["dst_port"] == 55123


def test_build_runtime_snapshot_uses_commands(monkeypatch) -> None:
    outputs = {
        "-tulpenH": 'tcp LISTEN 0 128 0.0.0.0:22 0.0.0.0:* users:(("sshd",pid=1,fd=5))',
        "-tunapH": 'tcp ESTAB 0 0 10.0.0.5:22 8.8.8.8:41234 users:(("sshd",pid=1,fd=6))',
    }

    def _fake_run(command, timeout=5):
        key = command[-1]
        return outputs.get(key, "")

    monkeypatch.setattr("sentinel_x_defense_suite.gui.runtime_data.run_command", _fake_run)
    snap = build_runtime_snapshot()
    assert snap["services"][0]["port"] == 22
    assert snap["services"][0]["service"] == "ssh"
    assert snap["remote_suspicious"][0]["dst_ip"] == "8.8.8.8"
    assert snap["globe_points"]


def test_build_runtime_snapshot_exposure_count(monkeypatch) -> None:
    outputs = {
        "-tulpenH": "tcp LISTEN 0 128 0.0.0.0:8443 0.0.0.0:* users:((\"python3\",pid=7,fd=3))",
        "-tunapH": "",
    }

    def _fake_run(command, timeout=5):
        return outputs.get(command[-1], "")

    monkeypatch.setattr("sentinel_x_defense_suite.gui.runtime_data.run_command", _fake_run)
    snap = build_runtime_snapshot()
    assert snap["public_service_count"] == 1
    assert any("8443" in line for line in snap["exposure_lines"])


def test_suggested_commands_are_defensive_only() -> None:
    conn = {"dst_ip": "203.0.113.15", "dst_port": 443, "protocol": "tcp"}
    cmds = suggested_connection_defense_commands(conn)
    assert any("ufw deny" in c for c in cmds)
    assert all("contra" not in c.lower() for c in cmds)


def test_detect_service_versions_has_os() -> None:
    data = detect_service_versions()
    assert any(item["service"] == "os" for item in data)


def test_suggested_service_commands_include_systemctl() -> None:
    svc = {"service": "nginx"}
    cmds = suggested_service_admin_commands(svc)
    assert any("systemctl restart nginx" in c for c in cmds)


def test_build_defense_playbook_increases_risk_on_exposure() -> None:
    playbook = build_defense_playbook(
        exposed_services=[{"port": 22}, {"port": 443}],
        remote_suspicious=[{"dst_ip": "203.0.113.10"}],
        incoming_connections=[{"dst_port": 22}, {"dst_port": 8443}],
    )
    assert playbook["score"] < 100
    assert playbook["level"] in {"ROBUSTO", "ELEVADO", "ALTO RIESGO", "CRÍTICO"}
    assert "Postura defensiva" in playbook["summary"]
    assert any("Reducir exposición" in action for action in playbook["actions"])


def test_build_defense_playbook_healthy_baseline() -> None:
    playbook = build_defense_playbook([], [], [])
    assert playbook["score"] == 100
    assert playbook["level"] == "ROBUSTO"
    assert any("Estado saludable" in action for action in playbook["actions"])
