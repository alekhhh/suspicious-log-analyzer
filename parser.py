import csv
import re
from datetime import datetime
from pathlib import Path

from log_types import LogEvent


CUSTOM_PATTERN = re.compile(
    r"^(?P<ts>\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2})\s+"
    r"IP=(?P<ip>[0-9a-fA-F\.:]+)\s+"
    r"USER=(?P<user>[^\s]+)\s+"
    r"ACTION=(?P<action>login_success|login_failed)\s*$"
)

AUTH_FAILED_PATTERN = re.compile(
    r"^(?P<mon>[A-Z][a-z]{2})\s+(?P<day>\d{1,2})\s+(?P<hms>\d{2}:\d{2}:\d{2})\s+"
    r".*sshd\[\d+\]:\s+Failed password for(?: invalid user)?\s+(?P<user>\S+)\s+"
    r"from\s+(?P<ip>[0-9a-fA-F\.:]+)\s+"
)

AUTH_SUCCESS_PATTERN = re.compile(
    r"^(?P<mon>[A-Z][a-z]{2})\s+(?P<day>\d{1,2})\s+(?P<hms>\d{2}:\d{2}:\d{2})\s+"
    r".*sshd\[\d+\]:\s+Accepted (?:password|publickey) for\s+(?P<user>\S+)\s+"
    r"from\s+(?P<ip>[0-9a-fA-F\.:]+)\s+"
)

APACHE_PATTERN = re.compile(
    r"^(?P<ip>[0-9a-fA-F\.:]+)\s+\S+\s+\S+\s+\[(?P<ts>[^\]]+)\]\s+"
    r"\"(?P<method>[A-Z]+)\s+(?P<path>\S+)\s+\S+\"\s+(?P<status>\d{3})\s+\S+"
)


def _parse_authlog_timestamp(month: str, day: str, hms: str) -> datetime:
    year = datetime.now().year
    return datetime.strptime(f"{year} {month} {day} {hms}", "%Y %b %d %H:%M:%S")


def _apache_to_event(stripped: str) -> LogEvent | None:
    match = APACHE_PATTERN.match(stripped)
    if not match:
        return None

    path = match.group("path").lower()
    if not any(keyword in path for keyword in ("/login", "/signin", "/auth")):
        return None

    status = int(match.group("status"))
    if status in (401, 403):
        action = "login_failed"
    elif status in (200, 201, 204, 302):
        action = "login_success"
    else:
        return None

    ts_str = match.group("ts")
    timestamp = datetime.strptime(ts_str, "%d/%b/%Y:%H:%M:%S %z").replace(tzinfo=None)
    return LogEvent(
        timestamp=timestamp,
        ip=match.group("ip"),
        user="web_user",
        action=action,
        raw_line=stripped,
        endpoint=match.group("path"),
    )


def _parse_line(stripped: str) -> LogEvent | None:
    custom = CUSTOM_PATTERN.match(stripped)
    if custom:
        return LogEvent(
            timestamp=datetime.strptime(custom.group("ts"), "%Y-%m-%d %H:%M:%S"),
            ip=custom.group("ip"),
            user=custom.group("user"),
            action=custom.group("action"),
            raw_line=stripped,
            endpoint="/login",
        )

    auth_failed = AUTH_FAILED_PATTERN.match(stripped)
    if auth_failed:
        return LogEvent(
            timestamp=_parse_authlog_timestamp(
                auth_failed.group("mon"),
                auth_failed.group("day"),
                auth_failed.group("hms"),
            ),
            ip=auth_failed.group("ip"),
            user=auth_failed.group("user"),
            action="login_failed",
            raw_line=stripped,
            endpoint="/ssh",
        )

    auth_success = AUTH_SUCCESS_PATTERN.match(stripped)
    if auth_success:
        return LogEvent(
            timestamp=_parse_authlog_timestamp(
                auth_success.group("mon"),
                auth_success.group("day"),
                auth_success.group("hms"),
            ),
            ip=auth_success.group("ip"),
            user=auth_success.group("user"),
            action="login_success",
            raw_line=stripped,
            endpoint="/ssh",
        )

    apache_event = _apache_to_event(stripped)
    if apache_event:
        return apache_event

    return None


def _parse_csv_timestamp(value: str) -> datetime | None:
    text = value.strip()
    if not text:
        return None
    for fmt in ("%Y-%m-%d %H:%M:%S", "%Y-%m-%dT%H:%M:%S"):
        try:
            return datetime.strptime(text, fmt)
        except ValueError:
            continue
    try:
        return datetime.fromisoformat(text.replace("Z", "+00:00")).replace(tzinfo=None)
    except ValueError:
        return None


def _parse_csv_file(path: Path) -> tuple[list[LogEvent], list[str]]:
    events: list[LogEvent] = []
    invalid_lines: list[str] = []
    with path.open("r", encoding="utf-8", newline="") as f:
        reader = csv.DictReader(f)
        required = {"timestamp", "ip", "user", "action"}
        fieldnames = {name.strip().lower() for name in (reader.fieldnames or [])}
        if not required.issubset(fieldnames):
            return events, [f"Invalid CSV header in {path.name}"]

        for row in reader:
            ts = _parse_csv_timestamp((row.get("timestamp") or "").strip())
            ip = (row.get("ip") or "").strip()
            user = (row.get("user") or "").strip()
            action = (row.get("action") or "").strip()
            endpoint = (row.get("endpoint") or "/login").strip() or "/login"
            if not ts or not ip or not user or action not in {"login_success", "login_failed"}:
                invalid_lines.append(str(row))
                continue
            events.append(
                LogEvent(
                    timestamp=ts,
                    ip=ip,
                    user=user,
                    action=action,
                    raw_line=str(row),
                    endpoint=endpoint,
                )
            )
    events.sort(key=lambda e: e.timestamp)
    return events, invalid_lines


def parse_log_file(log_file: str | Path) -> tuple[list[LogEvent], list[str]]:
    events: list[LogEvent] = []
    invalid_lines: list[str] = []
    path = Path(log_file)

    if not path.exists():
        raise FileNotFoundError(f"Log file not found: {path}")

    if path.suffix.lower() == ".csv":
        return _parse_csv_file(path)

    with path.open("r", encoding="utf-8") as f:
        for line in f:
            stripped = line.strip()
            if not stripped:
                continue

            event = _parse_line(stripped)
            if not event:
                invalid_lines.append(stripped)
                continue

            events.append(event)

    events.sort(key=lambda e: e.timestamp)
    return events, invalid_lines


def parse_log_directory(log_dir: str | Path) -> tuple[list[LogEvent], list[str]]:
    path = Path(log_dir)
    if not path.exists() or not path.is_dir():
        raise FileNotFoundError(f"Input log directory not found: {path}")

    events: list[LogEvent] = []
    invalid_lines: list[str] = []

    log_files: list[Path] = []
    for pattern in ("*.log", "*.txt", "*.csv"):
        log_files.extend(path.glob(pattern))
    log_files = sorted(set(log_files))
    if not log_files:
        raise FileNotFoundError(f"No .log/.txt/.csv files found in: {path}")

    for log_file in log_files:
        file_events, file_invalid = parse_log_file(log_file)
        events.extend(file_events)
        invalid_lines.extend(file_invalid)

    events.sort(key=lambda e: e.timestamp)
    return events, invalid_lines
