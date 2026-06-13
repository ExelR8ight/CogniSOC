"""Command-line runner for SOC behavioral analytics."""

from __future__ import annotations

import argparse
import json
import logging
from pathlib import Path
import sys
import time
from typing import Any

from soc_ml_engine.config.settings import EngineConfig, load_config
from soc_ml_engine.fetcher.splunk_fetcher import SplunkFetcher
from soc_ml_engine.models.anomaly_model import (
    BehavioralAnomalyModel,
    model_summary,
    write_findings,
    write_splunk_hec_events,
)
from soc_ml_engine.processing.features import (
    build_feature_frame,
    derive_baseline_profile,
    load_json_events,
    parse_splunk_events,
)


LOGGER = logging.getLogger("soc_ml_engine")


def main(argv: list[str] | None = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)
    _configure_logging(args.log_level)
    config = load_config(args.config)

    try:
        if args.command == "baseline":
            return _run_baseline(args, config)
        if args.command == "detect":
            return _run_detect(args, config)
    except Exception as exc:
        LOGGER.exception("SOC ML engine failed: %s", exc)
        return 1
    parser.print_help()
    return 2


def _run_baseline(args: argparse.Namespace, config: EngineConfig) -> int:
    records = _load_records(args, config)
    events = parse_splunk_events(records)
    profile = derive_baseline_profile(events)
    window_minutes = args.window_minutes if args.window_minutes is not None else config.window_minutes
    contamination = args.contamination if args.contamination is not None else config.contamination
    features = build_feature_frame(events, window_minutes=window_minutes, baseline_profile=profile)

    model = BehavioralAnomalyModel(
        contamination=contamination,
        random_state=config.random_state,
    )
    model.train(features, profile)
    model.save(args.model_path or config.model_path)
    print(json.dumps({"status": "baseline_trained", **model_summary(model)}, indent=2))
    return 0


def _run_detect(args: argparse.Namespace, config: EngineConfig) -> int:
    model_path = args.model_path or config.model_path
    output_path = args.output_file or config.suspicious_output_path
    hec_path = args.splunk_hec_file or config.splunk_hec_output_path

    while True:
        model = BehavioralAnomalyModel.load(model_path)
        records = _load_records(args, config)
        events = parse_splunk_events(records)
        features = build_feature_frame(
            events,
            window_minutes=args.window_minutes if args.window_minutes is not None else config.window_minutes,
            baseline_profile=model.baseline_profile,
        )
        scored = model.score(features)
        min_score = args.min_score if args.min_score is not None else config.output_min_score
        findings = model.suspicious_findings(scored, min_score=min_score)
        write_findings(output_path, findings)
        if args.write_splunk_hec:
            write_splunk_hec_events(hec_path, findings, index=config.splunk.index)
        print(
            json.dumps(
                {
                    "status": "scoring_complete",
                    "feature_rows": len(features),
                    "finding_count": len(findings),
                    "output_file": str(output_path),
                    "splunk_hec_file": str(hec_path) if args.write_splunk_hec else None,
                },
                indent=2,
            )
        )
        if not args.loop:
            return 0
        time.sleep(args.interval_seconds)


def _load_records(args: argparse.Namespace, config: EngineConfig) -> list[dict[str, Any]]:
    if args.input_file:
        LOGGER.info("Loading telemetry from %s", args.input_file)
        return load_json_events(args.input_file)
    LOGGER.info("Fetching telemetry from Splunk index=%s", config.splunk.index)
    fetcher = SplunkFetcher(config.splunk)
    return fetcher.fetch_recent_telemetry(
        earliest_time=args.earliest_time or config.splunk.earliest_time,
        latest_time=args.latest_time or config.splunk.latest_time,
        max_events=args.max_events if args.max_events is not None else config.max_events,
    )


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="SOC behavioral analytics for Splunk Sysmon and Suricata telemetry")
    parser.add_argument("--config", help="Path to JSON config file")
    parser.add_argument("--log-level", default="INFO", choices=["DEBUG", "INFO", "WARNING", "ERROR"])
    subparsers = parser.add_subparsers(dest="command")

    baseline = subparsers.add_parser("baseline", help="Train a semi-static Isolation Forest baseline")
    _add_common_runtime_args(baseline)
    baseline.add_argument("--contamination", type=float, help="Expected anomaly proportion in baseline telemetry")

    detect = subparsers.add_parser("detect", help="Score recent telemetry using an existing baseline model")
    _add_common_runtime_args(detect)
    detect.add_argument("--output-file", type=Path, help="JSON file for suspicious findings")
    detect.add_argument("--min-score", type=float, help="Minimum anomaly score percentile to output")
    detect.add_argument("--loop", action="store_true", help="Run continuously at a fixed interval")
    detect.add_argument("--interval-seconds", type=int, default=900, help="Delay between scoring passes in loop mode")
    detect.add_argument("--write-splunk-hec", action="store_true", help="Also write Splunk HEC-ready NDJSON")
    detect.add_argument("--splunk-hec-file", type=Path, help="Path for Splunk HEC-ready NDJSON output")
    return parser


def _add_common_runtime_args(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--input-file", type=Path, help="Read Splunk-like JSON/JSONL telemetry instead of using the API")
    parser.add_argument("--model-path", type=Path, help="Path to read/write the trained model")
    parser.add_argument("--earliest-time", help="Splunk earliest_time, for example -24h")
    parser.add_argument("--latest-time", help="Splunk latest_time, for example now")
    parser.add_argument("--max-events", type=int, help="Maximum Splunk events to pull")
    parser.add_argument("--window-minutes", type=int, help="Feature aggregation window size")


def _configure_logging(level: str) -> None:
    logging.basicConfig(
        level=getattr(logging, level.upper()),
        format="%(asctime)s %(levelname)s %(name)s - %(message)s",
    )


if __name__ == "__main__":
    sys.exit(main())
