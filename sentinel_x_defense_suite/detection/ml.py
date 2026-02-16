from __future__ import annotations

from collections import deque
from statistics import mean, pstdev


class LightweightAnomalyModel:
    """Modelo ligero no supervisado usando z-score para volumen de bytes."""

    def __init__(self, window: int = 100, threshold: float = 3.0) -> None:
        self.window = window
        self.threshold = threshold
        self.samples: deque[float] = deque(maxlen=window)

    def observe(self, value: float) -> bool:
        if len(self.samples) < 10:
            self.samples.append(value)
            return False

        mu = mean(self.samples)
        sigma = pstdev(self.samples) or 1.0
        z = abs((value - mu) / sigma)
        self.samples.append(value)
        return z >= self.threshold
