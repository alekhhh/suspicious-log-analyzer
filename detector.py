from collections import Counter, defaultdict, deque
from dataclasses import dataclass
from datetime import timedelta

from log_types import Detection, LogEvent


@dataclass(frozen=True)
class DetectionConfig:
    failed_limit: int = 5
    brute_force_user_limit: int = 4
    brute_force_ip_limit: int = 4
    unusual_start_hour: int = 0
    unusual_end_hour: int = 5
    burst_window_minutes: int = 10


class DetectionEngine:
    def __init__(self, config: DetectionConfig):
        self.config = config

    def analyze(self, events: list[LogEvent]) -> list[Detection]:
        detections: list[Detection] = []
        detections.extend(self._detect_failed_login_bursts(events))
        detections.extend(self._detect_bruteforce_patterns(events))
        detections.extend(self._detect_unusual_time_logins(events))
        return sorted(detections, key=lambda d: d.timestamp)

    def _detect_failed_login_bursts(self, events: list[LogEvent]) -> list[Detection]:
        detections: list[Detection] = []
        window = timedelta(minutes=self.config.burst_window_minutes)

        failed_by_ip: dict[str, deque[LogEvent]] = defaultdict(deque)
        already_alerted: set[str] = set()

        for event in events:
            if event.action != "login_failed":
                continue

            q = failed_by_ip[event.ip]
            q.append(event)
            cutoff = event.timestamp - window

            while q and q[0].timestamp < cutoff:
                q.popleft()

            if len(q) >= self.config.failed_limit and event.ip not in already_alerted:
                detections.append(
                    Detection(
                        kind="failed_login_burst",
                        severity="high",
                        message=(
                            f"IP {event.ip} reached {len(q)} failed logins "
                            f"in {self.config.burst_window_minutes} minutes."
                        ),
                        timestamp=event.timestamp,
                        ip=event.ip,
                    )
                )
                already_alerted.add(event.ip)

        return detections

    def _detect_bruteforce_patterns(self, events: list[LogEvent]) -> list[Detection]:
        detections: list[Detection] = []

        ip_to_users: dict[str, set[str]] = defaultdict(set)
        user_to_ips: dict[str, set[str]] = defaultdict(set)
        failed_per_ip = Counter()
        failed_per_user = Counter()

        for event in events:
            if event.action != "login_failed":
                continue
            ip_to_users[event.ip].add(event.user)
            user_to_ips[event.user].add(event.ip)
            failed_per_ip[event.ip] += 1
            failed_per_user[event.user] += 1

        for ip, users in ip_to_users.items():
            if len(users) >= self.config.brute_force_user_limit:
                detections.append(
                    Detection(
                        kind="bruteforce_ip_to_many_users",
                        severity="critical",
                        message=(
                            f"IP {ip} failed against {len(users)} users "
                            f"({failed_per_ip[ip]} failures total)."
                        ),
                        timestamp=max(
                            e.timestamp
                            for e in events
                            if e.ip == ip and e.action == "login_failed"
                        ),
                        ip=ip,
                    )
                )

        for user, ips in user_to_ips.items():
            if len(ips) >= self.config.brute_force_ip_limit:
                detections.append(
                    Detection(
                        kind="distributed_attack_many_ips_to_user",
                        severity="critical",
                        message=(
                            f"User {user} targeted from {len(ips)} IPs "
                            f"({failed_per_user[user]} failures total)."
                        ),
                        timestamp=max(
                            e.timestamp
                            for e in events
                            if e.user == user and e.action == "login_failed"
                        ),
                        user=user,
                    )
                )

        return detections

    def _detect_unusual_time_logins(self, events: list[LogEvent]) -> list[Detection]:
        detections: list[Detection] = []

        for event in events:
            if event.action != "login_success":
                continue

            if self._is_unusual_hour(event.timestamp.hour):
                detections.append(
                    Detection(
                        kind="unusual_login_time",
                        severity="medium",
                        message=(
                            f"User {event.user} successful login from {event.ip} "
                            f"at unusual hour {event.timestamp.hour:02d}:00."
                        ),
                        timestamp=event.timestamp,
                        ip=event.ip,
                        user=event.user,
                    )
                )

        return detections

    def _is_unusual_hour(self, hour: int) -> bool:
        start = self.config.unusual_start_hour
        end = self.config.unusual_end_hour

        if start == end:
            return True
        if start < end:
            return start <= hour < end
        return hour >= start or hour < end
