from dataclasses import dataclass
from datetime import datetime


@dataclass(frozen=True)
class LogEvent:
    timestamp: datetime
    ip: str
    user: str
    action: str
    raw_line: str
    endpoint: str = "/login"


@dataclass(frozen=True)
class Detection:
    kind: str
    severity: str
    message: str
    timestamp: datetime
    ip: str | None = None
    user: str | None = None
