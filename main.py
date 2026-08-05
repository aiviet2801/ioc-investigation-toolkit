import ipaddress
import os

from dotenv import load_dotenv

from services.virustotal import get_ip_report
from utils.logger import log


def validate_ip_address(ip_address):
    try:
        parsed_ip = ipaddress.ip_address(ip_address)
    except ValueError:
        return False, "Địa chỉ IP không hợp lệ."

    if parsed_ip.is_private:
        return False, ("Đây là địa chỉ IP nội bộ, " "không phù hợp để tra cứu OSINT.")

    return True, ""


def build_report(ip_address, attributes):
    stats = attributes.get("last_analysis_stats", {})

    return {
        "ip": ip_address,
        "country": attributes.get("country", "N/A"),
        "owner": attributes.get("as_owner", "N/A"),
        "asn": attributes.get("asn", "N/A"),
        "reputation": attributes.get("reputation", "N/A"),
        "malicious": stats.get("malicious", 0),
        "harmless": stats.get("harmless", 0),
        "undetected": stats.get("undetected", 0),
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
    }

    for key, label in labels.items():
        print(f"{label:11}: {report[key]}")

    print("=" * 40)


def main():
    load_dotenv()

    api_key = os.getenv("VT_API_KEY")

    if not api_key:
        log(
            "ERROR",
            "Không tìm thấy VT_API_KEY trong file .env.",
        )
        return

    log("INFO", f"API Key loaded (...{api_key[-6:]})")

    ip_address = input("Nhập địa chỉ IP cần kiểm tra: ").strip()

    is_valid, error_message = validate_ip_address(ip_address)

    if not is_valid:
        log("ERROR", error_message)
        return

    attributes = get_ip_report(
        ip_address,
        api_key,
    )

    if attributes is None:
        log("ERROR", "Không thể tạo báo cáo.")
        return

    report = build_report(
        ip_address,
        attributes,
    )

    print_report(report)


if __name__ == "__main__":
    main()
