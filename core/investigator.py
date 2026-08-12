from builders.report_builder import (
    build_domain_report,
    build_hash_report,
    build_report,
    build_url_report,
)

from services.abuseipdb import (
    get_ip_report as get_abuseipdb_report,
)

from services.virustotal import (
    get_domain_report,
    get_hash_report,
    get_ip_report as get_virustotal_report,
    get_url_report,
)

from utils.ip_utils import validate_ip_address
from utils.logger import log

from utils.ioc_detector import detect_ioc_type

from models.investigation_result import InvestigationResult


def investigate(
    ioc_value,
    vt_api_key,
    abuse_api_key,
):
    ioc_type = detect_ioc_type(ioc_value)

    if ioc_type == "IP":
        report = investigate_ip(
            ioc_value,
            vt_api_key,
            abuse_api_key,
        )

    elif ioc_type == "DOMAIN":
        report = investigate_domain(
            ioc_value,
            vt_api_key,
        )

    elif ioc_type == "URL":
        report = investigate_url(
            ioc_value,
            vt_api_key,
        )

    elif ioc_type in {
        "MD5",
        "SHA1",
        "SHA256",
    }:
        report = investigate_hash(
            ioc_value,
            ioc_type,
            vt_api_key,
        )

    else:
        return InvestigationResult(
            ioc_type="UNKNOWN",
            report=None,
        )

    return InvestigationResult(
        ioc_type=ioc_type,
        report=report,
    )


def investigate_ip(
    ip_address,
    vt_api_key,
    abuse_api_key,
):
    is_valid, error_message = validate_ip_address(ip_address)

    if not is_valid:
        log("ERROR", error_message)
        return None

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
            ("Cả VirusTotal và AbuseIPDB " "đều không trả dữ liệu."),
        )
        return None

    return build_report(
        ip_address,
        vt_attributes,
        abuse_data,
    )


def investigate_domain(
    domain,
    vt_api_key,
):
    attributes = get_domain_report(
        domain,
        vt_api_key,
    )

    if attributes is None:
        log(
            "ERROR",
            "VirusTotal không trả dữ liệu domain.",
        )
        return None

    return build_domain_report(
        domain,
        attributes,
    )


def investigate_url(
    url_value,
    vt_api_key,
):
    attributes = get_url_report(
        url_value,
        vt_api_key,
    )

    if attributes is None:
        log(
            "ERROR",
            "VirusTotal không trả dữ liệu URL.",
        )
        return None

    return build_url_report(
        url_value,
        attributes,
    )


def investigate_hash(
    file_hash,
    hash_type,
    vt_api_key,
):
    attributes = get_hash_report(
        file_hash,
        vt_api_key,
    )

    if attributes is None:
        log(
            "ERROR",
            "VirusTotal không trả dữ liệu hash.",
        )
        return None

    return build_hash_report(
        file_hash,
        hash_type,
        attributes,
    )
