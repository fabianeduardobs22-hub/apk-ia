from __future__ import annotations

import ipaddress
import re

SAFE_FILTER_PATTERN = re.compile(r"^[a-zA-Z0-9_. ()=><!&|:-]*$")


def validate_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


def validate_capture_filter(filter_expression: str) -> bool:
    return bool(SAFE_FILTER_PATTERN.fullmatch(filter_expression))
