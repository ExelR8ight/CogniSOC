"""Parse Sysmon/Suricata telemetry and build explainable anomaly features."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import timezone
import json
import logging
from pathlib import Path
import re
from typing import Any, Iterable
import xml.etree.ElementTree as ET

import pandas as pd


LOGGER = logging.getLogger(__name__)

PROCESS_CREATE_IDS = {"1", "4688"}
NETWORK_EVENT_IDS = {"3", "5156"}
DNS_EVENT_IDS = {"22"}
FILE_EVENT_IDS = {"11"}

FEATURE_COLUMNS = [
    "event_count",
    "process_event_count",
    "network_event_count",
    "suricata_alert_count",
    "powershell_count",
    "cmd_count",
    "unique_process_count",
    "top_process_frequency",
    "unique_dest_ports",
    "connection_count",
    "unique_parent_child_pairs",
    "rare_process_count",
    "unexpected_parent_child_count",
    "event_type_process_create",
    "event_type_network_connection",
    "event_type_suricata_alert",
    "event_type_dns_query",
    "event_type_file_created",
    "event_type_other",
]


@dataclass(slots=True)
class BaselineProfile:
    common_processes: set[str] = field(default_factory=set)
    parent_child_pairs: set[str] = field(default_factory=set)
    feature_columns: list[str] = field(default_factory=lambda: FEATURE_COLUMNS.copy())


def load_json_events(path: str | Path) -> list[dict[str, Any]]:
    """Load Splunk-like records from either JSON array or JSON lines."""

    source = Path(path)
    text = source.read_text(encoding="utf-8").strip()
    if not text:
        return []
    if text.startswith("["):
        payload = json.loads(text)
        if not isinstance(payload, list):
            raise ValueError(f"{source} must contain a JSON array or JSON lines")
        return [dict(item) for item in payload]
    return [json.loads(line) for line in text.splitlines() if line.strip()]


def parse_splunk_events(records: Iterable[dict[str, Any]]) -> pd.DataFrame:
    """Normalize raw Splunk result dictionaries into SOC event rows."""

    parsed = [_normalize_record(record) for record in records]
    frame = pd.DataFrame(parsed)
    if frame.empty:
        return _empty_events_frame()

    frame["timestamp"] = pd.to_datetime(frame["timestamp"], errors="coerce", utc=True)
    frame["timestamp"] = frame["timestamp"].fillna(pd.Timestamp.now(tz=timezone.utc))
    for column in [
        "host",
        "source_ip",
        "destination_ip",
        "process_name",
        "parent_process_name",
        "event_type",
        "image",
        "parent_image",
        "command_line",
    ]:
        if column in frame:
            frame[column] = frame[column].fillna("").astype(str)
    frame["destination_port"] = pd.to_numeric(frame["destination_port"], errors="coerce").fillna(0).astype(int)
    frame["entity"] = frame.apply(_entity_from_row, axis=1)
    return frame


def derive_baseline_profile(events: pd.DataFrame, rare_process_min_count: int = 2) -> BaselineProfile:
    """Capture stable baseline context without constantly retraining the model."""

    if events.empty:
        return BaselineProfile()
    process_counts = events["process_name"].value_counts()
    common_processes = {
        process for process, count in process_counts.items() if process and count >= rare_process_min_count
    }
    pairs = {
        pair for pair in events.apply(_parent_child_pair, axis=1).tolist() if pair and not pair.endswith("->")
    }
    return BaselineProfile(common_processes=common_processes, parent_child_pairs=pairs)


def build_feature_frame(
    events: pd.DataFrame,
    window_minutes: int = 15,
    baseline_profile: BaselineProfile | None = None,
) -> pd.DataFrame:
    """Aggregate telemetry into entity/time-window rows for Isolation Forest."""

    if events.empty:
        return _empty_feature_frame()

    working = events.copy()
    profile = baseline_profile or derive_baseline_profile(working)
    working["time_window"] = working["timestamp"].dt.floor(f"{window_minutes}min")
    working["is_process"] = working["event_type"].eq("process_create")
    working["is_network"] = working["event_type"].eq("network_connection")
    working["is_suricata"] = working["event_type"].eq("suricata_alert")
    working["is_powershell"] = working["process_name"].str.contains("powershell|pwsh", case=False, na=False)
    working["is_cmd"] = working["process_name"].str.fullmatch("cmd\\.exe|cmd", case=False, na=False)
    working["parent_child_pair"] = working.apply(_parent_child_pair, axis=1)
    working["is_rare_process"] = working["process_name"].apply(
        lambda process: bool(process) and process not in profile.common_processes
    )
    working["is_unexpected_pair"] = working["parent_child_pair"].apply(
        lambda pair: bool(pair) and pair not in profile.parent_child_pairs
    )

    grouped = working.groupby(["entity", "time_window"], dropna=False)
    rows: list[dict[str, Any]] = []
    for (entity, time_window), group in grouped:
        process_counts = group.loc[group["process_name"] != "", "process_name"].value_counts()
        event_type_counts = group["event_type"].value_counts()
        row: dict[str, Any] = {
            "entity": str(entity),
            "timestamp": time_window.isoformat(),
            "host": _most_common(group["host"]),
            "source_ip": _most_common(group["source_ip"]),
            "dominant_event_type": _most_common(group["event_type"]),
            "rare_processes": sorted(group.loc[group["is_rare_process"], "process_name"].dropna().unique().tolist()),
            "unexpected_parent_child_pairs": sorted(
                group.loc[group["is_unexpected_pair"], "parent_child_pair"].dropna().unique().tolist()
            ),
            "event_count": int(len(group)),
            "process_event_count": int(group["is_process"].sum()),
            "network_event_count": int(group["is_network"].sum()),
            "suricata_alert_count": int(group["is_suricata"].sum()),
            "powershell_count": int(group["is_powershell"].sum()),
            "cmd_count": int(group["is_cmd"].sum()),
            "unique_process_count": int(group.loc[group["process_name"] != "", "process_name"].nunique()),
            "top_process_frequency": int(process_counts.iloc[0]) if not process_counts.empty else 0,
            "unique_dest_ports": int(group.loc[group["destination_port"] > 0, "destination_port"].nunique()),
            "connection_count": int(group["destination_ip"].astype(bool).sum()),
            "unique_parent_child_pairs": int(group.loc[group["parent_child_pair"] != "", "parent_child_pair"].nunique()),
            "rare_process_count": int(group["is_rare_process"].sum()),
            "unexpected_parent_child_count": int(group["is_unexpected_pair"].sum()),
            "event_type_process_create": int(event_type_counts.get("process_create", 0)),
            "event_type_network_connection": int(event_type_counts.get("network_connection", 0)),
            "event_type_suricata_alert": int(event_type_counts.get("suricata_alert", 0)),
            "event_type_dns_query": int(event_type_counts.get("dns_query", 0)),
            "event_type_file_created": int(event_type_counts.get("file_created", 0)),
            "event_type_other": int(event_type_counts.get("other", 0) + event_type_counts.get("unknown", 0)),
        }
        rows.append(row)

    features = pd.DataFrame(rows)
    for column in FEATURE_COLUMNS:
        if column not in features:
            features[column] = 0
    return features


def _normalize_record(record: dict[str, Any]) -> dict[str, Any]:
    raw_payload = record.get("_raw") or record.get("raw_payload") or ""
    raw_fields = _parse_raw(raw_payload)
    merged = {**raw_fields, **{key: _first(value) for key, value in record.items()}}
    event_id = str(merged.get("EventCode") or merged.get("EventID") or merged.get("event_id") or "")
    image = str(merged.get("Image") or merged.get("image") or "")
    parent_image = str(merged.get("ParentImage") or merged.get("parent_image") or "")
    event_type = _event_type(merged, event_id)
    return {
        "timestamp": merged.get("_time") or merged.get("TimeCreated") or merged.get("timestamp"),
        "host": merged.get("host") or merged.get("Computer") or merged.get("ComputerName") or "",
        "source_type": merged.get("sourcetype") or merged.get("source") or "",
        "event_id": event_id,
        "event_type": event_type,
        "image": image,
        "process_name": _basename(image),
        "parent_image": parent_image,
        "parent_process_name": _basename(parent_image),
        "command_line": merged.get("CommandLine") or merged.get("command_line") or "",
        "parent_command_line": merged.get("ParentCommandLine") or "",
        "source_ip": merged.get("SourceIp") or merged.get("src_ip") or merged.get("src") or "",
        "destination_ip": merged.get("DestinationIp") or merged.get("dest_ip") or merged.get("dest") or "",
        "destination_port": merged.get("DestinationPort") or merged.get("dest_port") or 0,
        "protocol": merged.get("Protocol") or merged.get("proto") or "",
        "signature": merged.get("signature") or merged.get("alert.signature") or "",
        "category": merged.get("alert.category") or merged.get("category") or "",
        "raw": merged.get("_raw") or merged.get("raw_payload") or "",
    }


def _parse_raw(raw: Any) -> dict[str, Any]:
    if not isinstance(raw, str) or not raw.strip():
        return {}
    raw = raw.strip()
    if raw.startswith("{"):
        try:
            payload = json.loads(raw)
            return _flatten_json(payload)
        except json.JSONDecodeError:
            LOGGER.debug("Unable to parse raw JSON payload")
    if raw.startswith("<"):
        try:
            return _parse_sysmon_xml(raw)
        except ET.ParseError:
            LOGGER.debug("Unable to parse raw XML payload")
    return {}


def _flatten_json(payload: dict[str, Any], prefix: str = "") -> dict[str, Any]:
    flattened: dict[str, Any] = {}
    for key, value in payload.items():
        full_key = f"{prefix}.{key}" if prefix else str(key)
        if isinstance(value, dict):
            flattened.update(_flatten_json(value, full_key))
        else:
            flattened[full_key] = value
            flattened[str(key)] = value
    return flattened


def _parse_sysmon_xml(raw: str) -> dict[str, Any]:
    root = ET.fromstring(raw)
    parsed: dict[str, Any] = {}
    for element in root.iter():
        tag = _strip_namespace(element.tag)
        if tag == "EventID":
            parsed["EventID"] = element.text
        elif tag == "Computer":
            parsed["Computer"] = element.text
        elif tag == "Data":
            name = element.attrib.get("Name")
            if name:
                parsed[name] = element.text or ""
    return parsed


def _event_type(fields: dict[str, Any], event_id: str) -> str:
    sourcetype = str(fields.get("sourcetype") or fields.get("source") or "").lower()
    raw_event_type = str(fields.get("event_type") or "").lower()
    has_suricata_alert_fields = bool(fields.get("alert.signature") or fields.get("signature") or fields.get("alert.category"))
    if has_suricata_alert_fields and raw_event_type in {"alert", ""}:
        return "suricata_alert"
    if "suricata" in sourcetype or raw_event_type in {"alert", "dns", "http", "tls", "flow"}:
        return "suricata_alert" if raw_event_type in {"alert", ""} else raw_event_type
    if event_id in PROCESS_CREATE_IDS:
        return "process_create"
    if event_id in NETWORK_EVENT_IDS:
        return "network_connection"
    if event_id in DNS_EVENT_IDS:
        return "dns_query"
    if event_id in FILE_EVENT_IDS:
        return "file_created"
    return raw_event_type or "unknown"


def _basename(path: str) -> str:
    if not path:
        return ""
    return re.split(r"[\\/]", path)[-1].lower()


def _parent_child_pair(row: pd.Series) -> str:
    parent = str(row.get("parent_process_name", "") or "")
    child = str(row.get("process_name", "") or "")
    if not parent or not child:
        return ""
    return f"{parent}->{child}"


def _entity_from_row(row: pd.Series) -> str:
    host = str(row.get("host", "") or "").strip()
    source_ip = str(row.get("source_ip", "") or "").strip()
    event_type = str(row.get("event_type", "") or "").strip()
    source_type = str(row.get("source_type", "") or "").strip().lower()
    if source_ip and ("suricata" in source_type or event_type in {"suricata_alert", "dns", "http", "tls", "flow"}):
        return source_ip
    return host or source_ip or "unknown_entity"


def _most_common(series: pd.Series) -> str:
    values = series.dropna().astype(str)
    values = values[values != ""]
    if values.empty:
        return ""
    return str(values.value_counts().index[0])


def _first(value: Any) -> Any:
    if isinstance(value, list):
        return value[0] if value else None
    return value


def _strip_namespace(tag: str) -> str:
    return tag.split("}", 1)[-1] if "}" in tag else tag


def _empty_events_frame() -> pd.DataFrame:
    return pd.DataFrame(
        columns=[
            "timestamp",
            "host",
            "source_type",
            "event_id",
            "event_type",
            "image",
            "process_name",
            "parent_image",
            "parent_process_name",
            "command_line",
            "parent_command_line",
            "source_ip",
            "destination_ip",
            "destination_port",
            "protocol",
            "signature",
            "category",
            "raw",
            "entity",
        ]
    )


def _empty_feature_frame() -> pd.DataFrame:
    return pd.DataFrame(columns=["entity", "timestamp", "host", "source_ip", "dominant_event_type"] + FEATURE_COLUMNS)
