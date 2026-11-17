
from collections import defaultdict
from datetime import datetime, timedelta


class ThreatDetector:
    """
    Detect suspicious activities in security log events.
    """

    def __init__(
        self,
        failed_login_threshold=5,
        time_window_minutes=10,
        username_threshold=5,
        allowed_ips=None
    ):
        self.failed_login_threshold = failed_login_threshold
        self.time_window = timedelta(minutes=time_window_minutes)
        self.username_threshold = username_threshold
        self.allowed_ips = set(allowed_ips or [])

    def create_alert(self, rule, severity, description, evidence):
        return {
            "detection_time": datetime.now().isoformat(sep=" "),
            "rule": rule,
            "severity": severity,
            "description": description,
            "evidence": evidence
        }

    def detect_repeated_failed_logins(self, events):
        alerts = []
        grouped_events = defaultdict(list)

        for event in events:
            if (
                event.get("login_outcome") == "failed"
                and event.get("source_ip")
                and event.get("timestamp")
            ):
                try:
                    timestamp = datetime.fromisoformat(
                        event["timestamp"]
                    )
                    grouped_events[event["source_ip"]].append(
                        (timestamp, event)
                    )
                except (ValueError, TypeError):
                    continue

        for ip_address, records in grouped_events.items():
            records.sort(key=lambda item: item[0])

            for index, (start_time, _) in enumerate(records):
                matching_events = [
                    event
                    for timestamp, event in records[index:]
                    if timestamp - start_time <= self.time_window
                ]

                if len(matching_events) >= self.failed_login_threshold:
                    alerts.append(
                        self.create_alert(
                            rule="Repeated Failed Login Attempts",
                            severity="High",
                            description=(
                                f"{len(matching_events)} failed login "
                                f"attempts detected from {ip_address}."
                            ),
                            evidence={
                                "source_ip": ip_address,
                                "attempt_count": len(matching_events),
                                "time_window_minutes": (
                                    self.time_window.total_seconds() / 60
                                )
                            }
                        )
                    )
                    break

        return alerts

    def detect_unapproved_ips(self, events):
        alerts = []

        for event in events:
            ip_address = event.get("source_ip")

            if (
                ip_address
                and self.allowed_ips
                and ip_address not in self.allowed_ips
                and event.get("login_outcome") in ("failed", "success")
            ):
                alerts.append(
                    self.create_alert(
                        rule="Unapproved IP Address",
                        severity="Medium",
                        description=(
                            f"Authentication activity detected "
                            f"from unapproved IP {ip_address}."
                        ),
                        evidence={
                            "source_ip": ip_address,
                            "username": event.get("username"),
                            "login_outcome": event.get("login_outcome")
                        }
                    )
                )

        return alerts

    def detect_username_enumeration(self, events):
        alerts = []
        grouped_events = defaultdict(list)

        for event in events:
            if (
                event.get("source_ip")
                and event.get("username")
                and event.get("timestamp")
                and event.get("login_outcome") == "failed"
            ):
                try:
                    timestamp = datetime.fromisoformat(
                        event["timestamp"]
                    )
                    grouped_events[event["source_ip"]].append(
                        (timestamp, event)
                    )
                except (ValueError, TypeError):
                    continue

        for ip_address, records in grouped_events.items():
            records.sort(key=lambda item: item[0])

            for index, (start_time, _) in enumerate(records):
                matching_events = [
                    event
                    for timestamp, event in records[index:]
                    if timestamp - start_time <= self.time_window
                ]

                usernames = {
                    event.get("username")
                    for event in matching_events
                    if event.get("username")
                }

                if len(usernames) >= self.username_threshold:
                    alerts.append(
                        self.create_alert(
                            rule="Possible Account Enumeration",
                            severity="High",
                            description=(
                                f"Attempts involving {len(usernames)} "
                                f"different usernames detected from "
                                f"{ip_address}."
                            ),
                            evidence={
                                "source_ip": ip_address,
                                "usernames": sorted(usernames)
                            }
                        )
                    )
                    break

        return alerts

    def detect_administrative_events(self, events):
        alerts = []

        for event in events:
            if event.get("event_type") == "administrative":
                alerts.append(
                    self.create_alert(
                        rule="Administrative Activity",
                        severity="Low",
                        description=(
                            "An administrative activity requires review."
                        ),
                        evidence={
                            "username": event.get("username"),
                            "description": event.get("description"),
                            "source_ip": event.get("source_ip")
                        }
                    )
                )

        return alerts

    def analyze(self, events):
        alerts = []

        alerts.extend(
            self.detect_repeated_failed_logins(events)
        )

        alerts.extend(
            self.detect_unapproved_ips(events)
        )

        alerts.extend(
            self.detect_username_enumeration(events)
        )

        alerts.extend(
            self.detect_administrative_events(events)
        )

        return alerts
