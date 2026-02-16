import argparse

from decktroy import decktroy_cli


def test_main_defaults_to_desktop(monkeypatch) -> None:
    called = {"value": False}

    def _fake_desktop(args: argparse.Namespace) -> int:
        called["value"] = True
        assert args.root is True
        return 0

    monkeypatch.setattr(decktroy_cli, "cmd_desktop", _fake_desktop)
    monkeypatch.setattr("sys.argv", ["decktroy"])

    assert decktroy_cli.main() == 0
    assert called["value"]


def test_cmd_desktop_uses_sudo_when_not_root(monkeypatch) -> None:
    captured = {}

    class _Proc:
        returncode = 0

    def _fake_run(cmd, check=False):
        captured["cmd"] = cmd
        return _Proc()

    monkeypatch.setattr(decktroy_cli.os, "geteuid", lambda: 1000)
    monkeypatch.setattr(decktroy_cli.shutil, "which", lambda _name: "/usr/bin/sudo")
    monkeypatch.setattr(decktroy_cli.subprocess, "run", _fake_run)

    args = argparse.Namespace(root=True, gui_args=[])
    assert decktroy_cli.cmd_desktop(args) == 0
    assert captured["cmd"][:2] == ["sudo", "-E"]
