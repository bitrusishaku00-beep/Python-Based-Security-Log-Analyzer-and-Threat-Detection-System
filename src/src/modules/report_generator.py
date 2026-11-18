
from pathlib import Path

import pandas as pd
import matplotlib.pyplot as plt


class ReportGenerator:
    """
    Generate security reports and charts from stored records.
    """

    def __init__(self, database, output_dir="reports"):
        self.database = database
        self.output_dir = Path(output_dir)

        self.output_dir.mkdir(
            parents=True,
            exist_ok=True
        )

    def load_data(self):
        """Retrieve events and alerts from the database."""

        events = self.database.get_all_events()
        alerts = self.database.get_all_alerts()

        events_df = pd.DataFrame(events)
        alerts_df = pd.DataFrame(alerts)

        return events_df, alerts_df

    def generate_summary(self):
        """Calculate important security statistics."""

        events_df, alerts_df = self.load_data()

        summary = {
            "total_events": len(events_df),
            "total_alerts": len(alerts_df),
            "successful_logins": 0,
            "failed_logins": 0,
            "unknown_events": 0
        }

        if not events_df.empty:
            outcomes = events_df["login_outcome"].value_counts()

            summary["successful_logins"] = int(
                outcomes.get("success", 0)
            )

            summary["failed_logins"] = int(
                outcomes.get("failed", 0)
            )

            summary["unknown_events"] = int(
                outcomes.get("unknown", 0)
            )

        if not alerts_df.empty:
            summary["alerts_by_severity"] = (
                alerts_df["severity"].value_counts().to_dict()
            )
        else:
            summary["alerts_by_severity"] = {}

        return summary

    def export_events_csv(self):
        """Export security events into a CSV file."""

        events_df, _ = self.load_data()

        file_path = self.output_dir / "security_events.csv"

        events_df.to_csv(file_path, index=False)

        return file_path

    def export_alerts_csv(self):
        """Export security alerts into a CSV file."""

        _, alerts_df = self.load_data()

        file_path = self.output_dir / "security_alerts.csv"

        alerts_df.to_csv(file_path, index=False)

        return file_path

    def generate_text_report(self):
        """Create a readable summary report."""

        summary = self.generate_summary()

        report_path = self.output_dir / "security_summary.txt"

        with report_path.open("w", encoding="utf-8") as report:

            report.write("SECURITY LOG ANALYSIS REPORT\n")
            report.write("============================\n\n")

            report.write(
                f"Total security events: {summary['total_events']}\n"
            )

            report.write(
                f"Total security alerts: {summary['total_alerts']}\n"
            )

            report.write(
                f"Successful logins: {summary['successful_logins']}\n"
            )

            report.write(
                f"Failed logins: {summary['failed_logins']}\n"
            )

            report.write(
                f"Unknown login outcomes: {summary['unknown_events']}\n"
            )

            report.write("\nALERTS BY SEVERITY\n")
            report.write("------------------\n")

            for severity, count in summary[
                "alerts_by_severity"
            ].items():

                report.write(f"{severity}: {count}\n")

        return report_path

    def generate_charts(self):
        """Create charts showing security activity."""

        events_df, alerts_df = self.load_data()

        chart_paths = []

        if not events_df.empty:
            login_counts = events_df[
                "login_outcome"
            ].value_counts()

            plt.figure(figsize=(8, 5))
            login_counts.plot(kind="bar")

            plt.title("Login Activity")
            plt.xlabel("Login Outcome")
            plt.ylabel("Number of Events")
            plt.tight_layout()

            login_chart = self.output_dir / "login_activity.png"

            plt.savefig(login_chart)
            plt.close()

            chart_paths.append(login_chart)

        if not alerts_df.empty:
            severity_counts = alerts_df[
                "severity"
            ].value_counts()

            plt.figure(figsize=(8, 5))
            severity_counts.plot(kind="bar")

            plt.title("Security Alerts by Severity")
            plt.xlabel("Severity")
            plt.ylabel("Number of Alerts")
            plt.tight_layout()

            alert_chart = self.output_dir / "alert_severity.png"

            plt.savefig(alert_chart)
            plt.close()

            chart_paths.append(alert_chart)

        return chart_paths

    def generate_all_reports(self):
        """Generate all available reports and charts."""

        return {
            "summary": self.generate_text_report(),
            "events_csv": self.export_events_csv(),
            "alerts_csv": self.export_alerts_csv(),
            "charts": self.generate_charts()
        }
