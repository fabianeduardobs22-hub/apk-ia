from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any


class Severity(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass(slots=True)
class PacketRecord:
    timestamp: datetime
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    protocol: str
    length: int
    payload: bytes = b""
    metadata: dict[str, Any] = field(default_factory=dict)

    @classmethod
    def now(
        cls,
        src_ip: str,
        dst_ip: str,
        src_port: int,
        dst_port: int,
        protocol: str,
        length: int,
        payload: bytes = b"",
        metadata: dict[str, Any] | None = None,
    ) -> "PacketRecord":
        return cls(
            timestamp=datetime.now(tz=timezone.utc),
            src_ip=src_ip,
            dst_ip=dst_ip,
            src_port=src_port,
            dst_port=dst_port,
            protocol=protocol,
            length=length,
            payload=payload,
            metadata=metadata or {},
        )


@dataclass(slots=True)
class DetectionAlert:
    rule_id: str
    title: str
    description: str
    severity: Severity
    src_ip: str
    dst_ip: str
    confidence: float
    timestamp: datetime = field(default_factory=lambda: datetime.now(tz=timezone.utc))
    details: dict[str, Any] = field(default_factory=dict)


@dataclass(slots=True)
class RiskScore:
    ip: str
    score: float
    level: Severity
    reasons: list[str] = field(default_factory=list)
