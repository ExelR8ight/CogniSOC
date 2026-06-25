"""Evaluation metrics for CogniSOC research paper."""

from __future__ import annotations

import math
from dataclasses import dataclass, field
from typing import Any


@dataclass(slots=True)
class ConfusionMatrix:
    tp: int = 0
    fp: int = 0
    tn: int = 0
    fn: int = 0

    @property
    def precision(self) -> float:
        denom = self.tp + self.fp
        return self.tp / denom if denom > 0 else 0.0

    @property
    def recall(self) -> float:
        denom = self.tp + self.fn
        return self.tp / denom if denom > 0 else 0.0

    @property
    def f1(self) -> float:
        p, r = self.precision, self.recall
        return 2 * p * r / (p + r) if (p + r) > 0 else 0.0

    @property
    def fpr(self) -> float:
        """False Positive Rate = FP / (FP + TN)."""
        denom = self.fp + self.tn
        return self.fp / denom if denom > 0 else 0.0

    @property
    def accuracy(self) -> float:
        total = self.tp + self.fp + self.tn + self.fn
        return (self.tp + self.tn) / total if total > 0 else 0.0

    @property
    def total_alerts(self) -> int:
        return self.tp + self.fp

    def to_dict(self) -> dict[str, Any]:
        return {
            "tp": self.tp,
            "fp": self.fp,
            "tn": self.tn,
            "fn": self.fn,
            "precision": round(self.precision, 4),
            "recall": round(self.recall, 4),
            "f1": round(self.f1, 4),
            "fpr": round(self.fpr, 4),
            "accuracy": round(self.accuracy, 4),
            "total_alerts": self.total_alerts,
        }


def wilson_ci(successes: int, trials: int, z: float = 1.96) -> tuple[float, float]:
    """Wilson score confidence interval for proportions (small-sample safe)."""
    if trials == 0:
        return (0.0, 0.0)
    p_hat = successes / trials
    denom = 1 + z**2 / trials
    center = (p_hat + z**2 / (2 * trials)) / denom
    spread = z * math.sqrt(p_hat * (1 - p_hat) / trials + z**2 / (4 * trials**2)) / denom
    return (max(0.0, round(center - spread, 4)), min(1.0, round(center + spread, 4)))


def compute_confusion_matrix(
    predictions: list[bool],
    ground_truth: list[bool],
) -> ConfusionMatrix:
    """Compute confusion matrix from parallel boolean lists.

    Args:
        predictions: True if the detector flagged this window as malicious.
        ground_truth: True if the window actually contained attack activity.
    """
    if len(predictions) != len(ground_truth):
        raise ValueError(
            f"Length mismatch: {len(predictions)} predictions vs {len(ground_truth)} ground truth"
        )
    cm = ConfusionMatrix()
    for pred, truth in zip(predictions, ground_truth):
        if truth and pred:
            cm.tp += 1
        elif truth and not pred:
            cm.fn += 1
        elif not truth and pred:
            cm.fp += 1
        else:
            cm.tn += 1
    return cm


def alert_volume_reduction(baseline_alerts: int, system_alerts: int) -> float:
    """Percentage reduction in alert volume: (baseline - system) / baseline * 100."""
    if baseline_alerts == 0:
        return 0.0
    return round((baseline_alerts - system_alerts) / baseline_alerts * 100, 2)
