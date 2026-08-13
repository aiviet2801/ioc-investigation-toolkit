from pathlib import Path


def get_reports_directory():
    reports_directory = (
        Path.home() / "Documents" / "IOC Investigation Toolkit" / "Reports"
    )

    reports_directory.mkdir(
        parents=True,
        exist_ok=True,
    )

    return reports_directory
