from builders.report_builder import build_html_data
from exporters.html_report import export_html_report
from exporters.pdf_report import export_pdf_report
from utils.path_utils import get_reports_directory

REPORT_CONFIG = {
    "IP": {
        "title": "IOC Investigation Report",
        "sources": ["VirusTotal", "AbuseIPDB"],
    },
    "DOMAIN": {
        "title": "Domain Investigation Report",
        "sources": ["VirusTotal"],
    },
    "URL": {
        "title": "URL Investigation Report",
        "sources": ["VirusTotal"],
    },
    "MD5": {
        "title": "Hash Investigation Report",
        "sources": ["VirusTotal"],
    },
    "SHA1": {
        "title": "Hash Investigation Report",
        "sources": ["VirusTotal"],
    },
    "SHA256": {
        "title": "Hash Investigation Report",
        "sources": ["VirusTotal"],
    },
}


def export_report(
    report,
    ioc_type,
    labels,
    export_format,
):
    config = REPORT_CONFIG.get(ioc_type)

    if config is None:
        raise ValueError(f"Không có cấu hình export cho IOC type: {ioc_type}")

    report_data = build_html_data(
        report,
        labels,
    )

    output_directory = get_reports_directory()

    if export_format == "html":
        return export_html_report(
            config["title"],
            ioc_type,
            config["sources"],
            report_data,
            output_directory=output_directory,
        )

    if export_format == "pdf":
        return export_pdf_report(
            config["title"],
            ioc_type,
            config["sources"],
            report_data,
            output_directory=output_directory,
        )

    raise ValueError(f"Định dạng export không được hỗ trợ: {export_format}")
