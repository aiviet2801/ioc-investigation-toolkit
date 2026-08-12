import os

from dotenv import load_dotenv

from core.investigator import investigate

from presenters.console_report import (
    print_domain_report,
    print_hash_report,
    print_report,
    print_url_report,
)

from utils.logger import log

from exporters.report_exporter import export_report

from presenters.console_report import (
    DOMAIN_LABELS,
    HASH_LABELS,
    IP_LABELS,
    URL_LABELS,
    print_domain_report,
    print_hash_report,
    print_report,
    print_url_report,
)


def ask_export(report, ioc_type, labels):
    choice = input("Export report? [html/pdf/none]: ").strip().lower()

    if choice == "none" or not choice:
        return

    if choice not in {"html", "pdf"}:
        log(
            "ERROR",
            f"Định dạng export không hợp lệ: {choice}",
        )
        return

    try:
        file_path = export_report(
            report,
            ioc_type,
            labels,
            choice,
        )

    except (ValueError, OSError) as error:
        log(
            "ERROR",
            f"Không thể export report: {error}",
        )
        return

    log(
        "INFO",
        f"Report exported: {file_path}",
    )


def main():
    load_dotenv()

    vt_api_key = os.getenv("VT_API_KEY")
    abuse_api_key = os.getenv("ABUSEIPDB_API_KEY")

    if not vt_api_key:
        log(
            "ERROR",
            "Không tìm thấy VT_API_KEY trong file .env.",
        )
        return

    if not abuse_api_key:
        log(
            "ERROR",
            "Không tìm thấy ABUSEIPDB_API_KEY trong file .env.",
        )
        return

    log(
        "INFO",
        f"VirusTotal API Key loaded (...{vt_api_key[-6:]})",
    )

    log(
        "INFO",
        f"AbuseIPDB API Key loaded (...{abuse_api_key[-6:]})",
    )

    ioc_value = input("Nhập IOC cần kiểm tra: ").strip()

    result = investigate(
        ioc_value,
        vt_api_key,
        abuse_api_key,
    )

    ioc_type = result.ioc_type
    report = result.report

    log(
        "INFO",
        f"IOC Type detected: {ioc_type}",
    )

    if report is None:
        log(
            "ERROR",
            f"Không thể điều tra IOC type '{ioc_type}'.",
        )
        return

    if ioc_type == "IP":
        print_report(report)
        labels = IP_LABELS

    elif ioc_type == "DOMAIN":
        print_domain_report(report)
        labels = DOMAIN_LABELS

    elif ioc_type == "URL":
        print_url_report(report)
        labels = URL_LABELS

    elif ioc_type in {
        "MD5",
        "SHA1",
        "SHA256",
    }:
        print_hash_report(report)
        labels = HASH_LABELS

    else:
        log(
            "ERROR",
            f"IOC type '{ioc_type}' chưa được hỗ trợ.",
        )
        return

    ask_export(
        report,
        ioc_type,
        labels,
    )


if __name__ == "__main__":
    main()
