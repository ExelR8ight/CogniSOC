"""Isolation Forest baseline training and anomaly scoring."""

from __future__ import annotations

from dataclasses import asdict, dataclass
from datetime import datetime, timezone
import json
import logging
from pathlib import Path
import pickle
from typing import Any

import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler

from soc_ml_engine.processing.features import BaselineProfile, FEATURE_COLUMNS


LOGGER = logging.getLogger(__name__)


@dataclass(slots=True)
class TrainingMetadata:
    trained_at: str
    row_count: int
    feature_columns: list[str]
    contamination: float
    random_state: int


class BehavioralAnomalyModel:
    """Semi-static Isolation Forest model for SOC behavioral scoring."""

    def __init__(
        self,
        contamination: float = 0.05,
        random_state: int = 42,
        feature_columns: list[str] | None = None,
    ) -> None:
        self.feature_columns = feature_columns or FEATURE_COLUMNS.copy()
        self.contamination = contamination
        self.random_state = random_state
        self.scaler = StandardScaler()
        self.model = IsolationForest(
            n_estimators=200,
            contamination=contamination,
            random_state=random_state,
        )
        self.baseline_profile = BaselineProfile(feature_columns=self.feature_columns)
        self.training_scores: np.ndarray = np.array([])
        self.training_score_min = 0.0
        self.training_score_p95 = 0.0
        self.training_score_p99 = 0.0
        self.training_means: dict[str, float] = {}
        self.training_stds: dict[str, float] = {}
        self.metadata: TrainingMetadata | None = None

    def train(self, features: pd.DataFrame, baseline_profile: BaselineProfile) -> None:
        if features.empty:
            raise ValueError("Cannot train anomaly model with an empty feature frame")
        matrix = self._matrix(features)
        scaled = self.scaler.fit_transform(matrix)
        self.model.fit(scaled)
        raw_scores = -self.model.decision_function(scaled)
        self.training_scores = np.sort(raw_scores)
        self.training_score_min = float(np.min(raw_scores))
        self.training_score_p95 = float(np.quantile(raw_scores, 0.95))
        self.training_score_p99 = float(np.quantile(raw_scores, 0.99))
        self.training_means = matrix.mean().to_dict()
        self.training_stds = matrix.std(ddof=0).replace(0, 1.0).to_dict()
        self.baseline_profile = baseline_profile
        self.metadata = TrainingMetadata(
            trained_at=datetime.now(timezone.utc).isoformat(),
            row_count=len(features),
            feature_columns=self.feature_columns,
            contamination=self.contamination,
            random_state=self.random_state,
        )
        LOGGER.info("Trained Isolation Forest baseline on %s feature rows", len(features))

    def score(self, features: pd.DataFrame) -> pd.DataFrame:
        if self.metadata is None:
            raise ValueError("Model has not been trained or loaded")
        if features.empty:
            return features.copy()
        matrix = self._matrix(features)
        scaled = self.scaler.transform(matrix)
        raw_scores = -self.model.decision_function(scaled)
        forest_scores = [self._percentile_score(score) for score in raw_scores]
        deviation_scores = [self._deviation_score(matrix.iloc[index]) for index in range(len(matrix))]
        anomaly_scores = [max(forest, deviation) for forest, deviation in zip(forest_scores, deviation_scores)]

        scored = features.copy()
        scored["raw_anomaly_score"] = raw_scores
        scored["forest_score"] = forest_scores
        scored["baseline_deviation_score"] = deviation_scores
        scored["anomaly_score"] = anomaly_scores
        scored["severity"] = scored["anomaly_score"].apply(severity_from_score)
        scored["reason"] = [
            self._reason(row, matrix.iloc[index]) for index, row in scored.reset_index(drop=True).iterrows()
        ]
        return scored

    def suspicious_findings(self, scored: pd.DataFrame, min_score: float = 90.0) -> list[dict[str, Any]]:
        if scored.empty:
            return []
        findings = scored.loc[scored["anomaly_score"] >= min_score].copy()
        findings = findings.sort_values(["anomaly_score", "timestamp"], ascending=[False, False])
        output: list[dict[str, Any]] = []
        for _, row in findings.iterrows():
            output.append(
                {
                    "timestamp": row.get("timestamp", ""),
                    "host": row.get("host", ""),
                    "source_ip": row.get("source_ip", ""),
                    "entity": row.get("entity", ""),
                    "event_type": row.get("dominant_event_type", ""),
                    "anomaly_score": round(float(row.get("anomaly_score", 0.0)), 2),
                    "severity": row.get("severity", "low"),
                    "priority": priority_from_score(float(row.get("anomaly_score", 0.0))),
                    "confidence": confidence_from_finding(row),
                    "reason": row.get("reason", ""),
                    "score_components": {
                        "isolation_forest_percentile": round(float(row.get("forest_score", 0.0)), 2),
                        "baseline_deviation_score": round(float(row.get("baseline_deviation_score", 0.0)), 2),
                        "raw_model_score": round(float(row.get("raw_anomaly_score", 0.0)), 5),
                    },
                    "risk_factors": risk_factors_from_row(row),
                    "mitre_context": mitre_context_from_row(row),
                    "recommended_actions": recommended_actions_from_row(row),
                    "features": {
                        column: _json_safe(row.get(column, 0))
                        for column in self.feature_columns
                    },
                    "rare_processes": row.get("rare_processes", []),
                    "unexpected_parent_child_pairs": row.get("unexpected_parent_child_pairs", []),
                    "source": "soc_ml_engine",
                }
            )
        return output

    def save(self, path: str | Path) -> None:
        target = Path(path)
        target.parent.mkdir(parents=True, exist_ok=True)
        with target.open("wb") as handle:
            pickle.dump(self, handle)

    @staticmethod
    def load(path: str | Path) -> "BehavioralAnomalyModel":
        with Path(path).open("rb") as handle:
            model = pickle.load(handle)
        if not isinstance(model, BehavioralAnomalyModel):
            raise TypeError("Model file does not contain a BehavioralAnomalyModel")
        return model

    def _matrix(self, features: pd.DataFrame) -> pd.DataFrame:
        matrix = features.copy()
        for column in self.feature_columns:
            if column not in matrix:
                matrix[column] = 0
        return matrix[self.feature_columns].apply(pd.to_numeric, errors="coerce").fillna(0.0)

    def _percentile_score(self, raw_score: float) -> float:
        if self.training_scores.size == 0:
            return 0.0
        if raw_score <= self.training_score_p95:
            denominator = self.training_score_p95 - self.training_score_min
            if denominator <= 1e-9:
                return 50.0
            score = (raw_score - self.training_score_min) / denominator * 89.0
            return round(float(max(0.0, min(89.0, score))), 2)
        denominator = self.training_score_p99 - self.training_score_p95
        if denominator <= 1e-9:
            return 100.0
        return round(float(min(100.0, 90.0 + ((raw_score - self.training_score_p95) / denominator * 10.0))), 2)

    def _deviation_score(self, feature_values: pd.Series) -> float:
        """Fallback calibration for very small or low-variance lab baselines."""

        evidence = 0.0
        weighted_features = {
            "powershell_count": 25.0,
            "cmd_count": 15.0,
            "rare_process_count": 25.0,
            "unexpected_parent_child_count": 20.0,
            "suricata_alert_count": 20.0,
            "unique_dest_ports": 10.0,
            "connection_count": 10.0,
        }
        for column, weight in weighted_features.items():
            value = float(feature_values.get(column, 0.0))
            mean = float(self.training_means.get(column, 0.0))
            std = float(self.training_stds.get(column, 1.0))
            if value > 0 and (value >= mean + (2 * std) or mean == 0):
                evidence += weight
        if evidence <= 0:
            return 0.0
        return round(float(min(100.0, 70.0 + evidence)), 2)

    def _reason(self, row: pd.Series, feature_values: pd.Series) -> str:
        reasons: list[str] = []
        named_reasons = {
            "powershell_count": "PowerShell activity above baseline",
            "cmd_count": "cmd.exe activity above baseline",
            "unique_dest_ports": "unusual number of destination ports",
            "connection_count": "connection volume above baseline",
            "rare_process_count": "rare process observed",
            "unexpected_parent_child_count": "unusual parent-child process relationship",
            "suricata_alert_count": "Suricata alert activity present",
        }
        for column, label in named_reasons.items():
            value = float(feature_values.get(column, 0.0))
            mean = float(self.training_means.get(column, 0.0))
            std = float(self.training_stds.get(column, 1.0))
            if value > 0 and (value >= mean + (2 * std) or mean == 0):
                reasons.append(label)
        rare_processes = row.get("rare_processes", [])
        if rare_processes:
            reasons.append(f"rare process sample: {', '.join(map(str, rare_processes[:3]))}")
        unexpected_pairs = row.get("unexpected_parent_child_pairs", [])
        if unexpected_pairs:
            reasons.append(f"unexpected parent-child pair: {', '.join(map(str, unexpected_pairs[:2]))}")
        if not reasons:
            reasons.append("combined behavior differs from the trained baseline")
        return "; ".join(reasons[:4])


def severity_from_score(score: float) -> str:
    if score >= 99:
        return "critical"
    if score >= 97:
        return "high"
    if score >= 90:
        return "medium"
    return "low"


def priority_from_score(score: float) -> str:
    if score >= 99:
        return "P1"
    if score >= 97:
        return "P2"
    if score >= 90:
        return "P3"
    return "P4"


def confidence_from_finding(row: pd.Series) -> str:
    score = float(row.get("anomaly_score", 0.0))
    risk_count = len(risk_factors_from_row(row))
    if score >= 99 and risk_count >= 2:
        return "high"
    if score >= 90:
        return "medium"
    return "low"


def risk_factors_from_row(row: pd.Series) -> list[str]:
    factors: list[str] = []
    checks = [
        ("powershell_count", "PowerShell execution volume"),
        ("cmd_count", "Command shell execution volume"),
        ("rare_process_count", "Rare process execution"),
        ("unexpected_parent_child_count", "Unusual process lineage"),
        ("suricata_alert_count", "Network IDS alert activity"),
        ("unique_dest_ports", "Destination port diversity"),
        ("connection_count", "Network connection volume"),
    ]
    features = row.get("features", {}) if isinstance(row.get("features", {}), dict) else {}
    for column, label in checks:
        value = row.get(column, features.get(column, 0))
        try:
            if float(value) > 0:
                factors.append(label)
        except (TypeError, ValueError):
            continue
    return factors


def mitre_context_from_row(row: pd.Series) -> list[str]:
    context: list[str] = []
    if float(row.get("powershell_count", 0) or 0) > 0:
        context.append("Execution: PowerShell")
    if float(row.get("cmd_count", 0) or 0) > 0:
        context.append("Execution: Command and Scripting Interpreter")
    if float(row.get("unexpected_parent_child_count", 0) or 0) > 0:
        context.append("Defense Evasion / Initial Access: unusual process lineage")
    if float(row.get("unique_dest_ports", 0) or 0) >= 20:
        context.append("Discovery: network service scanning pattern")
    if float(row.get("connection_count", 0) or 0) >= 100:
        context.append("Command and Control / Discovery: high connection volume")
    if float(row.get("suricata_alert_count", 0) or 0) > 0:
        context.append("Network IDS: Suricata alert context")
    if row.get("rare_processes"):
        context.append("Execution: uncommon process observed")
    return context[:5]


def recommended_actions_from_row(row: pd.Series) -> list[str]:
    actions = [
        "Pivot in Splunk on host/source IP and the 15-minute time window.",
        "Review parent-child process chain and command line for the listed processes.",
    ]
    if float(row.get("powershell_count", 0) or 0) > 0:
        actions.append("Inspect PowerShell Script Block, Sysmon Event ID 1, and encoded command usage.")
    if float(row.get("connection_count", 0) or 0) > 100 or float(row.get("unique_dest_ports", 0) or 0) > 20:
        actions.append("Review Suricata flows and destination port spread for scanning or beaconing.")
    if row.get("rare_processes"):
        actions.append("Validate rare process hashes, signer, path, and user context.")
    if row.get("severity") in {"critical", "high"}:
        actions.append("Open an incident case if activity is not expected lab/admin behavior.")
    return actions[:5]


def write_findings(path: str | Path, findings: list[dict[str, Any]]) -> None:
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps(findings, indent=2), encoding="utf-8")


def write_splunk_hec_events(path: str | Path, findings: list[dict[str, Any]], index: str = "main") -> None:
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    lines: list[str] = []
    for finding in findings:
        timestamp = pd.to_datetime(finding.get("timestamp"), errors="coerce", utc=True)
        event_time = None if pd.isna(timestamp) else timestamp.timestamp()
        lines.append(
            json.dumps(
                {
                    "time": event_time,
                    "host": finding.get("host") or finding.get("source_ip") or "soc_ml_engine",
                    "sourcetype": "soc:ml:anomaly",
                    "index": index,
                    "event": finding,
                }
            )
        )
    target.write_text("\n".join(lines) + ("\n" if lines else ""), encoding="utf-8")


def model_summary(model: BehavioralAnomalyModel) -> dict[str, Any]:
    return {
        "metadata": asdict(model.metadata) if model.metadata else None,
        "common_process_count": len(model.baseline_profile.common_processes),
        "parent_child_pair_count": len(model.baseline_profile.parent_child_pairs),
    }


def _json_safe(value: Any) -> Any:
    if isinstance(value, (np.integer,)):
        return int(value)
    if isinstance(value, (np.floating,)):
        return float(value)
    return value
