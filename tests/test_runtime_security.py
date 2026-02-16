import pytest

from sentinel_x_defense_suite.security.runtime import PrivilegeError, enforce_live_capture_privileges


def test_replay_mode_does_not_require_root() -> None:
    enforce_live_capture_privileges("any", "capture.pcap")


def test_offline_interface_does_not_require_root() -> None:
    enforce_live_capture_privileges("offline", None)


def test_live_capture_requires_root(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("os.geteuid", lambda: 1000)
    with pytest.raises(PrivilegeError):
        enforce_live_capture_privileges("eth0", None)
