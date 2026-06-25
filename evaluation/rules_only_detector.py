"""
Rules-Only Detector — Baseline comparison for CogniSOC paper.

This detector applies the same 13 Sigma rules (loaded from YAML) to the
feature-windowed telemetry WITHOUT using any ML model. It serves as the
"traditional SIEM detection" baseline against which CogniSOC is compared.
"""

from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any

import yaml

LOGGER = logging.getLogger(__name__)
SIGMA_RULES_DIR = Path("soc_ml_engine/sigma_rules")


def load_sigma_rules(rules_dir: Path | None = None) -> list[dict[str, Any]]:
    """Load all Sigma YAML rules from the rules directory."""
    directory = rules_dir or SIGMA_RULES_DIR
    rules: list[dict[str, Any]] = []
    for yml_file in sorted(directory.glob("*.yml")):
        try:
            rule = yaml.safe_load(yml_file.read_text(encoding="utf-8"))
            if rule:
                rules.append(rule)
        except Exception as exc:
            LOGGER.warning("Failed to load %s: %s", yml_file, exc)
    return rules


def _check_feature_condition(feature_value: float, condition: dict[str, Any]) -> bool:
    """Check if a feature value satisfies a Sigma rule condition."""
    if isinstance(condition, dict):
        for op, threshold in condition.items():
            if op == "gte" and feature_value < threshold:
                return False
            elif op == "gt" and feature_value <= threshold:
                return False
            elif op == "lte" and feature_value > threshold:
                return False
            elif op == "lt" and feature_value >= threshold:
                return False
            elif op == "eq" and feature_value != threshold:
                return False
        return True
    # Simple threshold (int/float) treated as gte
    return feature_value >= float(condition)


def evaluate_rule(rule: dict[str, Any], feature_window: dict[str, Any]) -> dict[str, Any] | None:
    """Evaluate a single Sigma rule against a feature window.

    Returns an alert dict if the rule fires, else None.
    """
    detection = rule.get("detection", {})
    features_required = detection.get("features", {})

    # Check all feature conditions (AND logic for condition: all)
    for feature_name, condition in features_required.items():
        value = float(feature_window.get(feature_name, 0))
        if not _check_feature_condition(value, condition):
            return None

    # Check severity filter (if present)
    severity_filter = detection.get("severity_filter")
    if severity_filter:
        # For rules-only, we don't have ML severity.
        # We infer severity from the rule itself — this is the "rules-only" approach.
        pass

    # Rule fires — create alert
    return {
        "rule_id": rule.get("id", "unknown"),
        "rule_title": rule.get("title", "Unknown Rule"),
        "incident_type": rule.get("incident_type", "Unknown"),
        "severity": rule.get("severity", "medium"),
        "confidence": rule.get("confidence", "low"),
        "entity": feature_window.get("entity", ""),
        "timestamp": feature_window.get("timestamp", ""),
        "host": feature_window.get("host", ""),
        "mitre_technique": _extract_technique(rule),
        "evidence": _format_evidence(rule, feature_window),
    }


def _extract_technique(rule: dict[str, Any]) -> str:
    mitre = rule.get("mitre_attack", [])
    if mitre and isinstance(mitre, list):
        return mitre[0].get("technique", "")
    return ""


def _format_evidence(rule: dict[str, Any], feature_window: dict[str, Any]) -> list[str]:
    evidence: list[str] = []
    templates = rule.get("evidence_template", [])
    for template in templates:
        try:
            evidence.append(template.format(**feature_window))
        except (KeyError, ValueError):
            evidence.append(template)
    return evidence


class RulesOnlyDetector:
    """Applies Sigma rules directly to feature windows (no ML)."""

    def __init__(self, rules_dir: Path | None = None) -> None:
        self.rules = load_sigma_rules(rules_dir)
        LOGGER.info("Loaded %d Sigma rules for rules-only detection", len(self.rules))

    def detect(self, feature_windows: list[dict[str, Any]]) -> list[dict[str, Any]]:
        """Run all rules against all feature windows.

        Returns list of alerts (a window can generate multiple alerts if
        multiple rules fire).
        """
        all_alerts: list[dict[str, Any]] = []
        for window in feature_windows:
            for rule in self.rules:
                alert = evaluate_rule(rule, window)
                if alert is not None:
                    all_alerts.append(alert)
        return all_alerts

    def detect_windows(self, feature_windows: list[dict[str, Any]]) -> list[bool]:
        """Return a boolean per window: True if ANY rule fired."""
        results: list[bool] = []
        for window in feature_windows:
            fired = False
            for rule in self.rules:
                if evaluate_rule(rule, window) is not None:
                    fired = True
                    break
            results.append(fired)
        return results

    def detect_with_details(
        self, feature_windows: list[dict[str, Any]]
    ) -> tuple[list[bool], list[list[dict[str, Any]]]]:
        """Return both boolean flags and detailed alerts per window."""
        flags: list[bool] = []
        details: list[list[dict[str, Any]]] = []
        for window in feature_windows:
            window_alerts: list[dict[str, Any]] = []
            for rule in self.rules:
                alert = evaluate_rule(rule, window)
                if alert is not None:
                    window_alerts.append(alert)
            flags.append(len(window_alerts) > 0)
            details.append(window_alerts)
        return flags, details
