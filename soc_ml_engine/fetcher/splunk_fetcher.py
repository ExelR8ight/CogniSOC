"""Splunk REST API client for recent Sysmon and Suricata telemetry."""

from __future__ import annotations

import logging
import time
from typing import Any

import requests
import urllib3

from soc_ml_engine.config.settings import SplunkConfig


LOGGER = logging.getLogger(__name__)


class SplunkSearchError(RuntimeError):
    """Raised when Splunk search creation or retrieval fails."""


class SplunkFetcher:
    """Small resilient client for Splunk Enterprise search jobs."""

    def __init__(self, config: SplunkConfig) -> None:
        self.config = config
        self.session = requests.Session()
        self.session.verify = config.verify_ssl
        if not config.verify_ssl:
            urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
        if config.token:
            self.session.headers.update({"Authorization": f"Bearer {config.token}"})
        elif config.username and config.password:
            self.session.auth = (config.username, config.password)
        else:
            raise SplunkSearchError(
                "Splunk credentials are missing. Set SPLUNK_TOKEN or SPLUNK_USERNAME/SPLUNK_PASSWORD."
            )

    def fetch_recent_telemetry(
        self,
        earliest_time: str | None = None,
        latest_time: str | None = None,
        max_events: int | None = None,
    ) -> list[dict[str, Any]]:
        """Run a broad lab-friendly search for Sysmon and Suricata records."""

        search = self._default_search(max_events=max_events)
        return self.run_search(
            search=search,
            earliest_time=earliest_time or self.config.earliest_time,
            latest_time=latest_time or self.config.latest_time,
        )

    def run_search(self, search: str, earliest_time: str, latest_time: str) -> list[dict[str, Any]]:
        sid = self._create_search_job(search, earliest_time, latest_time)
        self._wait_for_job(sid)
        return self._read_results(sid)

    def _default_search(self, max_events: int | None) -> str:
        limit = f" | head {int(max_events)}" if max_events else ""
        return (
            f'search index="{self.config.index}" '
            '(sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" '
            'OR sourcetype="sysmon" OR source="*Sysmon*" '
            'OR sourcetype="suricata" OR source="/var/log/suricata/eve.json" '
            'OR source="*suricata*" OR event_type=*) '
            '| eval raw_payload=substr(_raw,1,5000) '
            '| fields _time host source sourcetype EventCode EventID Computer Image ParentImage '
            'CommandLine ParentCommandLine ProcessGuid ParentProcessGuid User SourceIp DestinationIp '
            'DestinationPort Protocol src_ip src_port dest_ip dest_port proto app_proto event_type '
            'signature alert* flow* http* dns* tls* fileinfo* anomaly* raw_payload'
            f"{limit}"
        )

    def _create_search_job(self, search: str, earliest_time: str, latest_time: str) -> str:
        url = f"{self.config.base_url}/services/search/jobs"
        payload = {
            "search": search,
            "earliest_time": earliest_time,
            "latest_time": latest_time,
            "output_mode": "json",
        }
        response = self._request("POST", url, data=payload)
        sid = response.json().get("sid")
        if not sid:
            raise SplunkSearchError(f"Splunk did not return a search id: {response.text[:300]}")
        LOGGER.info("Created Splunk search job sid=%s", sid)
        return str(sid)

    def _wait_for_job(self, sid: str) -> None:
        url = f"{self.config.base_url}/services/search/jobs/{sid}"
        while True:
            response = self._request("GET", url, params={"output_mode": "json"})
            entry = response.json().get("entry", [{}])[0]
            content = entry.get("content", {})
            if content.get("isDone"):
                LOGGER.info("Splunk search sid=%s completed with %s results", sid, content.get("resultCount", 0))
                return
            time.sleep(1.0)

    def _read_results(self, sid: str) -> list[dict[str, Any]]:
        url = f"{self.config.base_url}/services/search/jobs/{sid}/results"
        offset = 0
        records: list[dict[str, Any]] = []
        while True:
            response = self._request(
                "GET",
                url,
                params={
                    "output_mode": "json",
                    "count": self.config.page_size,
                    "offset": offset,
                },
            )
            batch = response.json().get("results", [])
            if not batch:
                break
            records.extend(batch)
            LOGGER.debug("Fetched %s Splunk records so far", len(records))
            if len(batch) < self.config.page_size:
                break
            offset += self.config.page_size
        return records

    def _request(self, method: str, url: str, **kwargs: Any) -> requests.Response:
        last_error: Exception | None = None
        for attempt in range(1, self.config.retry_count + 1):
            try:
                response = self.session.request(method, url, timeout=self.config.timeout_seconds, **kwargs)
                if response.status_code >= 500:
                    raise SplunkSearchError(f"Splunk temporary error {response.status_code}: {response.text[:300]}")
                if response.status_code >= 400:
                    raise SplunkSearchError(f"Splunk API error {response.status_code}: {response.text[:500]}")
                return response
            except (requests.RequestException, SplunkSearchError) as exc:
                last_error = exc
                LOGGER.warning("Splunk request failed on attempt %s/%s: %s", attempt, self.config.retry_count, exc)
                if attempt < self.config.retry_count:
                    time.sleep(float(attempt))
        raise SplunkSearchError(f"Splunk request failed after retries: {last_error}")
