from datetime import datetime, timezone


def format_datetime(value):
    if value is None:
        return "N/A"

    if isinstance(value, (int, float)):
        try:
            converted = datetime.fromtimestamp(
                value,
                tz=timezone.utc,
            )

            return converted.strftime("%Y-%m-%d %H:%M UTC")

        except (ValueError, OSError, OverflowError):
            return "N/A"

    if isinstance(value, str):
        try:
            normalized_value = value.replace(
                "Z",
                "+00:00",
            )

            converted = datetime.fromisoformat(normalized_value)

            if converted.tzinfo is None:
                converted = converted.replace(tzinfo=timezone.utc)
            else:
                converted = converted.astimezone(timezone.utc)

            return converted.strftime("%Y-%m-%d %H:%M UTC")

        except ValueError:
            return "N/A"

    return "N/A"
