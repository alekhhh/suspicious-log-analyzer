import csv
from collections import Counter
from io import StringIO
from pathlib import Path

from log_types import Detection, LogEvent


THREAT_LABELS = {
    "failed_login_burst": "Multiple Failed Logins",
    "bruteforce_ip_to_many_users": "Brute Force Attack",
    "distributed_attack_many_ips_to_user": "Distributed Brute Force",
    "unusual_login_time": "Unusual Login Time",
}

SEVERITY_LABELS = {
    "critical": "High",
    "high": "High",
    "medium": "Medium",
    "low": "Low",
}


def _timestamp_range(events: list[LogEvent]) -> str:
    if not events:
        return ""
    start = min(e.timestamp for e in events)
    end = max(e.timestamp for e in events)
    return f"{start.isoformat(sep=' ')} -> {end.isoformat(sep=' ')}"


def build_report_rows(events: list[LogEvent], detections: list[Detection]) -> list[dict[str, str]]:
    events_by_ip: dict[str, list[LogEvent]] = {}
    for event in events:
        events_by_ip.setdefault(event.ip, []).append(event)

    rows: list[dict[str, str]] = []
    for detection in detections:
        candidate_events = []
        ip_value = detection.ip or "-"
        if detection.ip:
            candidate_events = events_by_ip.get(detection.ip, [])
        elif detection.user:
            candidate_events = [e for e in events if e.user == detection.user]

        total_attempts = len(candidate_events)
        failed_attempts = sum(1 for e in candidate_events if e.action == "login_failed")
        endpoint_counts = Counter(e.endpoint for e in candidate_events if e.endpoint)
        endpoint = endpoint_counts.most_common(1)[0][0] if endpoint_counts else ""

        rows.append(
            {
                "IP Address": ip_value,
                "Total Attempts": str(total_attempts),
                "Failed Attempts": str(failed_attempts),
                "Threat Type": THREAT_LABELS.get(detection.kind, detection.kind),
                "Details": detection.message,
                "Timestamp range": _timestamp_range(candidate_events),
                "Endpoint": endpoint,
                "Severity": SEVERITY_LABELS.get(detection.severity.lower(), "Medium"),
            }
        )

    return rows


def write_report_csv(rows: list[dict[str, str]], output_path: str) -> None:
    path = Path(output_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    fieldnames = [
        "IP Address",
        "Total Attempts",
        "Failed Attempts",
        "Threat Type",
        "Details",
        "Timestamp range",
        "Endpoint",
        "Severity",
    ]
    with path.open("w", encoding="utf-8", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)


def report_rows_to_csv_text(rows: list[dict[str, str]]) -> str:
    fieldnames = [
        "IP Address",
        "Total Attempts",
        "Failed Attempts",
        "Threat Type",
        "Details",
        "Timestamp range",
        "Endpoint",
        "Severity",
    ]
    buffer = StringIO()
    writer = csv.DictWriter(buffer, fieldnames=fieldnames)
    writer.writeheader()
    writer.writerows(rows)
    return buffer.getvalue()
