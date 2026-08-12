from datetime import datetime


def format_datetime(datetime_string):
    if not datetime_string:
        return "N/A"

    try:
        dt = datetime.fromisoformat(datetime_string.replace("Z", "+00:00"))

        return dt.strftime("%Y-%m-%d %H:%M UTC")

    except ValueError:
        return datetime_string
