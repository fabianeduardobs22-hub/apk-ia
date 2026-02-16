from __future__ import annotations

import ipaddress
import socket
import time
from dataclasses import dataclass


@dataclass(slots=True)
class DeviceInfo:
    ip: str
    hostname: str


class DefensiveScanner:
    def __init__(self, max_ports: int = 64, timeout_s: float = 0.3, min_delay_s: float = 0.02) -> None:
        self.max_ports = max_ports
        self.timeout_s = timeout_s
        self.min_delay_s = min_delay_s

    def discover_local_devices(self, cidr: str) -> list[DeviceInfo]:
        network = ipaddress.ip_network(cidr, strict=False)
        devices: list[DeviceInfo] = []
        for host in network.hosts():
            ip = str(host)
            try:
                name = socket.gethostbyaddr(ip)[0]
                devices.append(DeviceInfo(ip=ip, hostname=name))
            except Exception:
                continue
        return devices

    def safe_port_discovery(self, host: str, ports: list[int]) -> list[int]:
        open_ports: list[int] = []
        for port in ports[: self.max_ports]:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.settimeout(self.timeout_s)
                if sock.connect_ex((host, port)) == 0:
                    open_ports.append(port)
            time.sleep(self.min_delay_s)
        return open_ports
