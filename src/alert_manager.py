
from datetime import datetime
from uuid import uuid4


class AlertManager:
    """
    Organise, manage and summarise security alerts.
    """

    def __init__(self):
        self.alerts = []

    def add_alert(self, alert):
        """Add a new security alert."""

        required_fields = [
            "rule",
            "severity",
            "description",
            "evidence"
        ]

        for field in required_fields:
            if field not in alert:
                raise ValueError(
                    f"Missing required alert field: {field}"
                )

        severity_levels = [
            "Informational",
            "Low",
            "Medium",
            "High",
            "Critical"
        ]

        if alert["severity"] not in severity_levels:
            raise ValueError("Invalid alert severity.")

        managed_alert = alert.copy()

        managed_alert["alert_id"] = str(uuid4())
        managed_alert["status"] = "New"
        managed_alert["created_at"] = datetime.now().isoformat(
            sep=" "
        )

        self.alerts.append(managed_alert)

        return managed_alert

    def get_all_alerts(self):
        """Return all recorded alerts."""
        return self.alerts.copy()

    def get_alerts_by_severity(self, severity):
        """Find alerts belonging to a particular severity level."""

        return [
            alert
            for alert in self.alerts
            if alert["severity"].lower() == severity.lower()
        ]

    def update_alert_status(self, alert_id, new_status):
        """Update the status of an alert."""

        allowed_statuses = [
            "New",
            "Under Investigation",
            "Resolved"
        ]

        if new_status not in allowed_statuses:
            raise ValueError("Invalid alert status.")

        for alert in self.alerts:
            if alert["alert_id"] == alert_id:
                alert["status"] = new_status
                return True

        return False

    def get_alert_summary(self):
        """Count alerts according to their severity."""

        summary = {
            "total": len(self.alerts),
            "Informational": 0,
            "Low": 0,
            "Medium": 0,
            "High": 0,
            "Critical": 0
        }

        for alert in self.alerts:
            severity = alert["severity"]
            summary[severity] += 1

        return summary
