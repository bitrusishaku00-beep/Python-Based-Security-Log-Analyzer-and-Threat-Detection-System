
from pathlib import Path

from modules.log_parser import parse_linux_auth_line


def read_linux_auth_log(file_path):
    """
    Read a Linux authentication log file
    and parse each line.
    """

    parsed_events = []

    path = Path(file_path)

    if not path.exists():
        raise FileNotFoundError(
            f"Log file not found: {file_path}"
        )

    with path.open("r", encoding="utf-8", errors="replace") as log_file:

        for line_number, line in enumerate(log_file, start=1):

            if not line.strip():
                continue

            event = parse_linux_auth_line(
                line,
                source_file=path.name
            )

            if event is not None:
                event["line_number"] = line_number
                parsed_events.append(event)

    return parsed_events
