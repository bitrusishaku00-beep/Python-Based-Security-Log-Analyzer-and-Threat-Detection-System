
import argparse

from modules.log_reader import read_linux_auth_log
from modules.threat_detector import ThreatDetector
from modules.alert_manager import AlertManager
from modules.database import SecurityDatabase
from modules.report_generator import ReportGenerator


def run_application(log_file):
    """
    Run the complete security log analysis process.
    """

    print("\n======================================")
    print(" SECURITY LOG ANALYZER")
    print(" THREAT DETECTION SYSTEM")
    print("======================================\n")

    # STEP 1: Read and parse the log file
    print("[1] Reading security log file...")

    events = read_linux_auth_log(log_file)

    print(f"Records processed: {len(events)}")

    # STEP 2: Connect to the database
    print("\n[2] Connecting to security database...")

    database = SecurityDatabase()

    # STEP 3: Save security events
    print("\n[3] Saving security events...")

    for event in events:
        database.save_event(event)

    print("Security events saved.")

    # STEP 4: Detect suspicious activities
    print("\n[4] Analysing security events...")

    detector = ThreatDetector(
        failed_login_threshold=5,
        time_window_minutes=10,
        username_threshold=5,
        allowed_ips=[]
    )

    detected_alerts = detector.analyze(events)

    print(f"Suspicious activities detected: {len(detected_alerts)}")

    # STEP 5: Manage and save alerts
    print("\n[5] Managing security alerts...")

    alert_manager = AlertManager()

    for alert in detected_alerts:
        managed_alert = alert_manager.add_alert(alert)
        database.save_alert(managed_alert)

    print("Security alerts saved.")

    # STEP 6: Generate reports
    print("\n[6] Generating security reports...")

    report_generator = ReportGenerator(database)

    reports = report_generator.generate_all_reports()

    print("\nReports generated successfully.")

    # STEP 7: Display results
    print("\n========== ANALYSIS SUMMARY ==========")

    summary = report_generator.generate_summary()

    for item, value in summary.items():
        print(f"{item}: {value}")

    print("\nReport files:")

    print(f"Summary: {reports['summary']}")
    print(f"Events: {reports['events_csv']}")
    print(f"Alerts: {reports['alerts_csv']}")

    for chart in reports["charts"]:
        print(f"Chart: {chart}")

    print("\nAnalysis completed successfully!")


def main():
    parser = argparse.ArgumentParser(
        description="Python Security Log Analyzer"
    )

    parser.add_argument(
        "log_file",
        help="Path to the Linux authentication log file"
    )

    args = parser.parse_args()

    try:
        run_application(args.log_file)

    except FileNotFoundError as error:
        print(f"\nERROR: {error}")

    except Exception as error:
        print(f"\nAPPLICATION ERROR: {error}")


if __name__ == "__main__":
    main()
