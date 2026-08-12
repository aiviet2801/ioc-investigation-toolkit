IP_LABELS = {
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


DOMAIN_LABELS = {
    "domain": "Domain",
    "reputation": "Reputation",
    "malicious": "Malicious",
    "harmless": "Harmless",
    "suspicious": "Suspicious",
    "undetected": "Undetected",
    "registrar": "Registrar",
    "creation_date": "Creation Date",
    "expiration_date": "Expiration Date",
    "tags": "Tags",
}


URL_LABELS = {
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


HASH_LABELS = {
    "input_hash": "Input Hash",
    "hash_type": "Hash Type",
    "meaningful_name": "Meaningful Name",
    "type_description": "File Type",
    "size": "File Size",
    "md5": "MD5",
    "sha1": "SHA1",
    "sha256": "SHA256",
    "reputation": "Reputation",
    "malicious": "Malicious",
    "harmless": "Harmless",
    "suspicious": "Suspicious",
    "undetected": "Undetected",
    "times_submitted": "Times Submitted",
    "tags": "Tags",
}


def _format_value(value):
    if value is None:
        return "N/A"

    if isinstance(value, list):
        return ", ".join(str(item) for item in value) or "N/A"

    return value


def _print_dict_report(title, report, labels):
    print()
    print("=" * 40)
    print(title)
    print("=" * 40)

    for key, label in labels.items():
        value = _format_value(report.get(key, "N/A"))

        print(f"{label:16}: {value}")

    print("=" * 40)


def print_report(report):
    print()
    print("=" * 40)
    print("IOC Investigation Report")
    print("=" * 40)

    for key, label in IP_LABELS.items():
        value = _format_value(getattr(report, key, "N/A"))

        print(f"{label:16}: {value}")

    print("=" * 40)


def print_domain_report(report):
    _print_dict_report(
        "Domain Investigation Report",
        report,
        DOMAIN_LABELS,
    )


def print_url_report(report):
    _print_dict_report(
        "URL Investigation Report",
        report,
        URL_LABELS,
    )


def print_hash_report(report):
    _print_dict_report(
        "Hash Investigation Report",
        report,
        HASH_LABELS,
    )
