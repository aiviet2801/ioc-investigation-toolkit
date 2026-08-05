import ipaddress
import re
from urllib.parse import urlparse


def detect_ioc_type(value):
    value = value.strip()

    if not value:
        return "UNKNOWN"

    try:
        ipaddress.ip_address(value)
        return "IP"
    except ValueError:
        pass

    parsed_url = urlparse(value)

    if parsed_url.scheme in {"http", "https"} and parsed_url.netloc:
        return "URL"

    if re.fullmatch(r"[a-fA-F0-9]{32}", value):
        return "MD5"

    if re.fullmatch(r"[a-fA-F0-9]{40}", value):
        return "SHA1"

    if re.fullmatch(r"[a-fA-F0-9]{64}", value):
        return "SHA256"

    domain_pattern = (
        r"^(?=.{1,253}$)"
        r"(?:[a-zA-Z0-9]"
        r"(?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+"
        r"[a-zA-Z]{2,63}$"
    )

    if re.fullmatch(domain_pattern, value):
        return "DOMAIN"

    return "UNKNOWN"
