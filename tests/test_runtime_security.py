import pytest

from sentinel_x_defense_suite.capture.engine import CaptureRuntimeError, PacketCaptureEngine, resolve_capture_status
from sentinel_x_defense_suite.security.runtime import PrivilegeError, enforce_live_capture_privileges


def test_replay_mode_does_not_require_root() -> None:
    enforce_live_capture_privileges("any", "capture.pcap")


def test_offline_interface_does_not_require_root() -> None:
    enforce_live_capture_privileges("offline", None)


def test_live_capture_requires_root(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("os.geteuid", lambda: 1000)
    with pytest.raises(PrivilegeError):
        enforce_live_capture_privileges("eth0", None)


def test_capture_status_requires_explicit_simulation_flag() -> None:
    assert resolve_capture_status(interface="eth0", replay_pcap=None, simulate=False) == "live"
    assert resolve_capture_status(interface="eth0", replay_pcap=None, simulate=True) == "simulated"


def test_live_mode_without_scapy_fails_instead_of_simulating(monkeypatch: pytest.MonkeyPatch) -> None:
    engine = PacketCaptureEngine(interface="eth0", simulate=False)

    def _fail_scapy() -> None:
        raise CaptureRuntimeError("Scapy/libpcap ausente")

    monkeypatch.setattr(engine, "_require_scapy", _fail_scapy)
    with pytest.raises(CaptureRuntimeError):
        import asyncio

        asyncio.run(anext(engine.stream()))
