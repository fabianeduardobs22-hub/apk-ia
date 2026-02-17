from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable

try:
    import torch
    import torch.nn as nn
except Exception:  # pragma: no cover
    torch = None
    nn = object


if torch is not None:
    class ThreatPredictor(nn.Module):
        def __init__(self):
            super().__init__()
            self.lstm = nn.LSTM(10, 64, batch_first=True)
            self.fc = nn.Linear(64, 1)

        def forward(self, x):
            out, _ = self.lstm(x)
            return torch.sigmoid(self.fc(out[:, -1]))
else:
    class ThreatPredictor:  # fallback
        def __call__(self, sequence):
            return sequence.mean()


@dataclass
class PredictionResult:
    risk_score: float
    classification: str


def predict_attack_pattern(sequence: Iterable[Iterable[float]]) -> PredictionResult:
    if torch is None:
        values = [sum(item) / len(item) for item in sequence]
        score = min(0.99, max(0.01, sum(values) / max(1, len(values))))
    else:
        model = ThreatPredictor()
        model.eval()
        with torch.no_grad():
            tensor = torch.tensor([list(item) for item in sequence], dtype=torch.float32).unsqueeze(0)
            output = model(tensor)
            score = float(output.item())

    classification = "preventive_alert" if score > 0.75 else "normal"
    return PredictionResult(risk_score=score, classification=classification)
