from sentinel_x_defense_suite.gui.runtime_data import (
    build_runtime_snapshot,
    parse_active_connections,
    parse_listening_sockets,
)


def test_parse_listening_sockets_detects_open_service() -> None:
    raw = 'tcp LISTEN 0 128 0.0.0.0:8080 0.0.0.0:* users:(("python3",pid=123,fd=5))'
    services = parse_listening_sockets(raw)
    assert services
    assert services[0]["port"] == 8080
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
    assert snap["remote_suspicious"][0]["dst_ip"] == "8.8.8.8"


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
