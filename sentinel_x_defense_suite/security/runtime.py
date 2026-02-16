from __future__ import annotations

import os


class PrivilegeError(RuntimeError):
    """Raised when capture mode needs elevated privileges."""


def enforce_live_capture_privileges(interface: str, replay_pcap: str | None) -> None:
    """Require root for live capture, but allow non-root for replay mode.

    This keeps behavior secure and explicit without forcing permanent root
    for non-capture tasks such as forensic export.
    """

    if replay_pcap:
        return
    if interface.lower() in {"", "none", "offline"}:
        return
    if os.geteuid() != 0:
        raise PrivilegeError(
            "La captura en vivo requiere privilegios elevados (root o CAP_NET_RAW/CAP_NET_ADMIN). "
            "Use modo replay para análisis sin privilegios."
        )
