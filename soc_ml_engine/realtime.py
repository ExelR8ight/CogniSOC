"""Run continuous detection and the SOC dashboard in one process."""

from __future__ import annotations

import argparse
import logging
from pathlib import Path
import signal
import sys
import threading
import time

from soc_ml_engine.config.settings import load_config
from soc_ml_engine.dashboard import DEFAULT_FINDINGS, make_handler
from soc_ml_engine.fetcher.splunk_fetcher import SplunkFetcher
from soc_ml_engine.models.anomaly_model import BehavioralAnomalyModel, write_findings, write_splunk_hec_events
from soc_ml_engine.processing.features import build_feature_frame, parse_splunk_events

from http.server import ThreadingHTTPServer


LOGGER = logging.getLogger("soc_ml_engine.realtime")


def detection_loop(args: argparse.Namespace, stop_event: threading.Event) -> None:
    config = load_config(args.config)
    output_path = args.output_file or config.suspicious_output_path
    hec_path = args.splunk_hec_file or config.splunk_hec_output_path
    model_path = args.model_path or config.model_path

    while not stop_event.is_set():
        started_at = time.time()
        try:
            model = BehavioralAnomalyModel.load(model_path)
            fetcher = SplunkFetcher(config.splunk)
            records = fetcher.fetch_recent_telemetry(
                earliest_time=args.score_window,
                latest_time="now",
                max_events=args.max_events if args.max_events is not None else config.max_events,
            )
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
            LOGGER.info(
                "Realtime scoring complete: records=%s feature_rows=%s findings=%s output=%s",
                len(records),
                len(features),
                len(findings),
                output_path,
            )
        except Exception as exc:
            LOGGER.exception("Realtime scoring pass failed: %s", exc)

        elapsed = time.time() - started_at
        wait_seconds = max(1.0, args.interval_seconds - elapsed)
        stop_event.wait(wait_seconds)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Run continuous SOC ML scoring and dashboard")
    parser.add_argument("--config", help="Path to JSON config file")
    parser.add_argument("--model-path", type=Path, help="Trained Isolation Forest model path")
    parser.add_argument("--output-file", type=Path, help="Findings JSON file")
    parser.add_argument("--splunk-hec-file", type=Path, help="HEC-ready NDJSON output path")
    parser.add_argument("--write-splunk-hec", action="store_true", help="Write HEC-ready NDJSON each cycle")
    parser.add_argument("--score-window", default="-2h", help="Rolling Splunk window to score each cycle")
    parser.add_argument("--interval-seconds", type=int, default=60, help="Seconds between scoring passes")
    parser.add_argument("--max-events", type=int, help="Max events to pull per scoring pass")
    parser.add_argument("--min-score", type=float, help="Minimum score to write as a finding")
    parser.add_argument("--window-minutes", type=int, help="Feature aggregation window")
    parser.add_argument("--dashboard-host", default="127.0.0.1")
    parser.add_argument("--dashboard-port", type=int, default=8050)
    parser.add_argument("--log-level", default="INFO", choices=["DEBUG", "INFO", "WARNING", "ERROR"])
    args = parser.parse_args(argv)

    logging.basicConfig(level=getattr(logging, args.log_level), format="%(asctime)s %(levelname)s %(name)s - %(message)s")
    config = load_config(args.config)
    if args.output_file is None:
        args.output_file = config.suspicious_output_path or DEFAULT_FINDINGS

    stop_event = threading.Event()
    signal.signal(signal.SIGINT, lambda _sig, _frame: stop_event.set())
    signal.signal(signal.SIGTERM, lambda _sig, _frame: stop_event.set())

    worker = threading.Thread(target=detection_loop, args=(args, stop_event), daemon=True)
    worker.start()

    handler = make_handler(args.output_file)
    server = ThreadingHTTPServer((args.dashboard_host, args.dashboard_port), handler)
    server.timeout = 1.0
    print(f"SOC realtime dashboard: http://{args.dashboard_host}:{args.dashboard_port}")
    print(f"Scoring Splunk window: {args.score_window} every {args.interval_seconds}s")
    print(f"Reading/writing findings: {args.output_file}")

    while not stop_event.is_set():
        server.handle_request()
    server.server_close()
    worker.join(timeout=5)
    return 0


if __name__ == "__main__":
    sys.exit(main())
