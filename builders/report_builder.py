from models.report import Report
from utils.datetime_utils import format_datetime


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
        "creation_date": format_datetime(attributes.get("creation_date")),
        "expiration_date": format_datetime(attributes.get("expiration_date")),
        "tags": attributes.get("tags", []),
    }


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


def build_html_data(report, labels):
    html_data = {}

    for key, label in labels.items():
        if isinstance(report, dict):
            value = report.get(key, "N/A")
        else:
            value = getattr(report, key, "N/A")

        html_data[label] = value

    return html_data


def build_hash_report(file_hash, hash_type, attributes):
    attributes = attributes or {}

    stats = attributes.get("last_analysis_stats", {})

    return {
        "input_hash": file_hash,
        "hash_type": hash_type,
        "meaningful_name": attributes.get("meaningful_name", "N/A"),
        "type_description": attributes.get("type_description", "N/A"),
        "size": attributes.get("size", "N/A"),
        "md5": attributes.get("md5", "N/A"),
        "sha1": attributes.get("sha1", "N/A"),
        "sha256": attributes.get("sha256", "N/A"),
        "reputation": attributes.get("reputation", "N/A"),
        "malicious": stats.get("malicious", 0),
        "harmless": stats.get("harmless", 0),
        "suspicious": stats.get("suspicious", 0),
        "undetected": stats.get("undetected", 0),
        "times_submitted": attributes.get("times_submitted", 0),
        "tags": attributes.get("tags", []),
    }
