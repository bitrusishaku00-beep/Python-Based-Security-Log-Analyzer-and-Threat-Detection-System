
import re
import ipaddress
from datetime import datetime


# Pattern for reading Linux authentication log records
SYSLOG_PATTERN = re.compile(
    r"^(?P<timestamp>[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})"
    r"\s+(?P<hostname>\S+)"
    r"\s+(?P<process>[\w./-]+)(?:\[\d+\])?:\s*(?P<message>.*)$"
)

# Pattern for detecting failed login attempts
FAILED_LOGIN_PATTERN = re.compile(
    r"Failed password for (?:invalid user )?"
    r"(?P<username>\S+) from (?P<source_ip>[0-9A-Fa-f:.]+)",
    re.IGNORECASE
)

# Pattern for detecting successful login attempts
SUCCESS_LOGIN_PATTERN = re.compile(
    r"Accepted (?:password|publickey) for "
    r"(?P<username>\S+) from (?P<source_ip>[0-9A-Fa-f:.]+)",
    re.IGNORECASE
)


def validate_ip(ip_address):
    """Check whether an IP address is valid."""
    try:
        return str(ipaddress.ip_address(ip_address))
    except ValueError:
        return None


def convert_timestamp(timestamp):
    """Convert a Linux log timestamp into a standard date format."""
    try:
        current_year = datetime.now().year

        parsed_date = datetime.strptime(
            f"{current_year} {timestamp}",
            "%Y %b %d %H:%M:%S"
        )

        return parsed_date.isoformat(sep=" ")

    except ValueError:
        return timestamp


def parse_linux_auth_line(line, source_file="unknown"):
    """Extract useful security information from one Linux log line."""

    if not line or not line.strip():
        return None

    match = SYSLOG_PATTERN.match(line.strip())

    # Preserve records that our parser cannot understand.
    if not match:
        return {
            "timestamp": None,
            "hostname": None,
            "process": None,
            "username": None,
            "source_ip": None,
            "event_type": "unknown",
            "login_outcome": "unknown",
            "description": line.strip(),
            "source_file": source_file,
            "parse_status": "unparsed"
        }

    timestamp = convert_timestamp(match.group("timestamp"))
    hostname = match.group("hostname")
    process = match.group("process")
    message = match.group("message")

    username = None
    source_ip = None
    event_type = "other"
    login_outcome = "unknown"

    failed_match = FAILED_LOGIN_PATTERN.search(message)
    success_match = SUCCESS_LOGIN_PATTERN.search(message)

    if failed_match:
        username = failed_match.group("username")
        source_ip = validate_ip(failed_match.group("source_ip"))
        event_type = "authentication"
        login_outcome = "failed"

    elif success_match:
        username = success_match.group("username")
        source_ip = validate_ip(success_match.group("source_ip"))
        event_type = "authentication"
        login_outcome = "success"

    elif process.lower().startswith("sudo") or "COMMAND=" in message:
        event_type = "administrative"

    return {
        "timestamp": timestamp,
        "hostname": hostname,
        "process": process,
        "username": username,
        "source_ip": source_ip,
        "event_type": event_type,
        "login_outcome": login_outcome,
        "description": message,
        "source_file": source_file,
        "parse_status": "parsed"
    }
