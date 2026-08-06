import ipaddress
import os
from datetime import datetime

from dotenv import load_dotenv

from models.report import Report
from services.abuseipdb import get_ip_report as get_abuseipdb_report
from services.virustotal import get_ip_report as get_virustotal_report
from utils.ioc_detector import detect_ioc_type
from utils.logger import log

from services.virustotal import (
    get_domain_report,
    get_ip_report as get_virustotal_report,
    get_url_report,
)


def format_datetime(datetime_string):
    if not datetime_string:
        return "N/A"

    try:
        dt = datetime.fromisoformat(datetime_string.replace("Z", "+00:00"))

        return dt.strftime("%Y-%m-%d %H:%M UTC")

    except ValueError:
        return datetime_string


def validate_ip_address(ip_address):
    try:
        parsed_ip = ipaddress.ip_address(ip_address)

    except ValueError:
        return False, "Địa chỉ IP không hợp lệ."

    if parsed_ip.is_private:
        return False, ("Đây là địa chỉ IP nội bộ, " "không phù hợp để tra cứu OSINT.")

    return True, ""


def build_report(ip_address, vt_attributes, abuse_data):
    vt_attributes = vt_attributes or {}
    abuse_data = abuse_data or {}

    stats = vt_attributes.get("last_analysis_stats", {})

    report = Report()

    report.ip = ip_address

    report.country = (
        vt_attributes.get("country") or abuse_data.get("countryCode") or "N/A"
    )

    report.owner = vt_attributes.get("as_owner") or abuse_data.get("isp") or "N/A"

    report.asn = vt_attributes.get("asn") or abuse_data.get("asn") or "N/A"

    report.reputation = vt_attributes.get(
        "reputation",
        "N/A",
    )

    report.malicious = stats.get("malicious", 0)
    report.harmless = stats.get("harmless", 0)
    report.undetected = stats.get("undetected", 0)

    report.abuse_score = abuse_data.get(
        "abuseConfidenceScore",
        0,
    )

    report.total_reports = abuse_data.get(
        "totalReports",
        0,
    )

    report.last_reported_at = format_datetime(abuse_data.get("lastReportedAt"))

    return report


def build_domain_report(domain, attributes):
    attributes = attributes or {}

    stats = attributes.get("last_analysis_stats", {})

    return {
        "domain": domain,
        "reputation": attributes.get("reputation", "N/A"),
        "malicious": stats.get("malicious", 0),
        "harmless": stats.get("harmless", 0),
        "suspicious": stats.get("suspicious", 0),
        "undetected": stats.get("undetected", 0),
        "registrar": attributes.get("registrar", "N/A"),
        "creation_date": attributes.get("creation_date", "N/A"),
        "expiration_date": attributes.get("expiration_date", "N/A"),
        "tags": attributes.get("tags", []),
    }


def print_report(report):
    print()
    print("=" * 40)
    print("IOC Investigation Report")
    print("=" * 40)

    labels = {
        "ip": "IP Address",
        "country": "Country",
        "owner": "Owner",
        "asn": "ASN",
        "reputation": "Reputation",
        "malicious": "Malicious",
        "harmless": "Harmless",
        "undetected": "Undetected",
        "abuse_score": "Abuse Score",
        "total_reports": "Total Reports",
        "last_reported_at": "Last Reported",
    }

    for key, label in labels.items():
        print(f"{label:14}: {getattr(report, key)}")

    print("=" * 40)


def print_domain_report(report):
    print()
    print("=" * 40)
    print("Domain Investigation Report")
    print("=" * 40)

    print(f"{'Domain':15}: {report['domain']}")
    print(f"{'Reputation':15}: {report['reputation']}")
    print(f"{'Malicious':15}: {report['malicious']}")
    print(f"{'Harmless':15}: {report['harmless']}")
    print(f"{'Suspicious':15}: {report['suspicious']}")
    print(f"{'Undetected':15}: {report['undetected']}")
    print(f"{'Registrar':15}: {report['registrar']}")
    print(f"{'Creation Date':15}: {report['creation_date']}")
    print(f"{'Expiration Date':15}: {report['expiration_date']}")

    tags = report["tags"]

    if tags:
        print(f"{'Tags':15}: {', '.join(tags)}")
    else:
        print(f"{'Tags':15}: N/A")

    print("=" * 40)


def print_url_report(report):
    print()
    print("=" * 40)
    print("URL Investigation Report")
    print("=" * 40)

    labels = {
        "url": "URL",
        "final_url": "Final URL",
        "title": "Title",
        "reputation": "Reputation",
        "malicious": "Malicious",
        "harmless": "Harmless",
        "suspicious": "Suspicious",
        "undetected": "Undetected",
        "status_code": "Status Code",
        "content_type": "Content Type",
    }

    for key, label in labels.items():
        print(f"{label:15}: {report[key]}")

    print("=" * 40)


def build_url_report(url_value, attributes):
    attributes = attributes or {}

    stats = attributes.get("last_analysis_stats", {})

    return {
        "url": url_value,
        "final_url": attributes.get("last_final_url", url_value),
        "title": attributes.get("title", "N/A"),
        "reputation": attributes.get("reputation", "N/A"),
        "malicious": stats.get("malicious", 0),
        "harmless": stats.get("harmless", 0),
        "suspicious": stats.get("suspicious", 0),
        "undetected": stats.get("undetected", 0),
        "status_code": attributes.get("last_http_response_code", "N/A"),
        "content_type": attributes.get(
            "last_http_response_content_type",
            "N/A",
        ),
    }


def investigate_ip(ip_address, vt_api_key, abuse_api_key):
    is_valid, error_message = validate_ip_address(ip_address)

    if not is_valid:
        log("ERROR", error_message)
        return

    vt_attributes = get_virustotal_report(
        ip_address,
        vt_api_key,
    )

    abuse_data = get_abuseipdb_report(
        ip_address,
        abuse_api_key,
    )

    if vt_attributes is None and abuse_data is None:
        log(
            "ERROR",
            "Cả VirusTotal và AbuseIPDB đều không trả dữ liệu.",
        )
        return

    report = build_report(
        ip_address,
        vt_attributes,
        abuse_data,
    )

    print_report(report)


def investigate_domain(domain, vt_api_key):
    attributes = get_domain_report(
        domain,
        vt_api_key,
    )

    if attributes is None:
        log(
            "ERROR",
            "VirusTotal không trả dữ liệu domain.",
        )
        return

    report = build_domain_report(
        domain,
        attributes,
    )

    print_domain_report(report)


def investigate_url(url_value, vt_api_key):
    attributes = get_url_report(
        url_value,
        vt_api_key,
    )

    if attributes is None:
        log(
            "ERROR",
            "VirusTotal không trả dữ liệu URL.",
        )
        return

    report = build_url_report(
        url_value,
        attributes,
    )

    print_url_report(report)


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

    log("INFO", f"VirusTotal API Key loaded (...{vt_api_key[-6:]})")
    log(
        "INFO",
        f"AbuseIPDB API Key loaded (...{abuse_api_key[-6:]})",
    )

    ioc_value = input("Nhập IOC cần kiểm tra: ").strip()

    ioc_type = detect_ioc_type(ioc_value)

    log("INFO", f"IOC Type detected: {ioc_type}")

    if ioc_type == "IP":
        investigate_ip(
            ioc_value,
            vt_api_key,
            abuse_api_key,
        )

    elif ioc_type == "DOMAIN":
        investigate_domain(
            ioc_value,
            vt_api_key,
        )

    elif ioc_type == "URL":
        investigate_url(
            ioc_value,
            vt_api_key,
        )

    else:
        log(
            "ERROR",
            (f"IOC type '{ioc_type}' chưa được hỗ trợ " "trong phiên bản hiện tại."),
        )


if __name__ == "__main__":
    main()
