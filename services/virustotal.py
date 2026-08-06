import requests
import base64

from utils.logger import log


def get_ip_report(ip_address, api_key):
    url = "https://www.virustotal.com/api/v3/" f"ip_addresses/{ip_address}"

    headers = {
        "accept": "application/json",
        "x-apikey": api_key,
    }

    log("INFO", "Đang gửi yêu cầu tới VirusTotal...")

    try:
        response = requests.get(
            url,
            headers=headers,
            timeout=15,
        )

        response.raise_for_status()

    except requests.exceptions.Timeout:
        log("ERROR", "Yêu cầu bị quá thời gian chờ.")
        return None

    except requests.exceptions.ConnectionError:
        log("ERROR", "Không thể kết nối tới VirusTotal.")
        return None

    except requests.exceptions.HTTPError:
        log("ERROR", f"Lỗi HTTP: {response.status_code}")
        return None

    except requests.exceptions.RequestException as error:
        log("ERROR", f"Lỗi khi gửi yêu cầu: {error}")
        return None

    log("INFO", f"HTTP Status: {response.status_code}")

    try:
        json_data = response.json()
        attributes = json_data["data"]["attributes"]
    except (ValueError, KeyError, TypeError):
        log("ERROR", "Dữ liệu VirusTotal trả về không hợp lệ.")
        return None

    return attributes


def get_domain_report(domain, api_key):
    url = "https://www.virustotal.com/api/v3/" f"domains/{domain}"

    headers = {
        "accept": "application/json",
        "x-apikey": api_key,
    }

    log("INFO", "Đang gửi yêu cầu domain tới VirusTotal...")

    try:
        response = requests.get(
            url,
            headers=headers,
            timeout=15,
        )

        response.raise_for_status()

    except requests.exceptions.Timeout:
        log("ERROR", "Yêu cầu domain bị quá thời gian chờ.")
        return None

    except requests.exceptions.ConnectionError:
        log("ERROR", "Không thể kết nối tới VirusTotal.")
        return None

    except requests.exceptions.HTTPError:
        log(
            "ERROR",
            f"VirusTotal domain trả lỗi HTTP: {response.status_code}",
        )
        return None

    except requests.exceptions.RequestException as error:
        log(
            "ERROR",
            f"Lỗi khi gửi yêu cầu domain: {error}",
        )
        return None

    log(
        "INFO",
        f"VirusTotal Domain HTTP Status: {response.status_code}",
    )

    try:
        json_data = response.json()
        attributes = json_data["data"]["attributes"]

    except (ValueError, KeyError, TypeError):
        log(
            "ERROR",
            "Dữ liệu domain VirusTotal trả về không hợp lệ.",
        )
        return None

    return attributes


def get_url_report(url_value, api_key):
    url_id = (
        base64.urlsafe_b64encode(url_value.encode("utf-8")).decode("utf-8").rstrip("=")
    )

    endpoint = "https://www.virustotal.com/api/v3/" f"urls/{url_id}"

    headers = {
        "accept": "application/json",
        "x-apikey": api_key,
    }

    log("INFO", "Đang gửi yêu cầu URL tới VirusTotal...")

    try:
        response = requests.get(
            endpoint,
            headers=headers,
            timeout=15,
        )

        response.raise_for_status()

    except requests.exceptions.Timeout:
        log("ERROR", "Yêu cầu URL bị quá thời gian chờ.")
        return None

    except requests.exceptions.ConnectionError:
        log("ERROR", "Không thể kết nối tới VirusTotal.")
        return None

    except requests.exceptions.HTTPError:
        log(
            "ERROR",
            f"VirusTotal URL trả lỗi HTTP: {response.status_code}",
        )
        return None

    except requests.exceptions.RequestException as error:
        log(
            "ERROR",
            f"Lỗi khi gửi yêu cầu URL: {error}",
        )
        return None

    log(
        "INFO",
        f"VirusTotal URL HTTP Status: {response.status_code}",
    )

    try:
        json_data = response.json()
        attributes = json_data["data"]["attributes"]

    except (ValueError, KeyError, TypeError):
        log(
            "ERROR",
            "Dữ liệu URL VirusTotal trả về không hợp lệ.",
        )
        return None

    return attributes


def get_hash_report(file_hash, api_key):
    endpoint = "https://www.virustotal.com/api/v3/" f"files/{file_hash}"

    headers = {
        "accept": "application/json",
        "x-apikey": api_key,
    }

    log("INFO", "Đang gửi yêu cầu hash tới VirusTotal...")

    try:
        response = requests.get(
            endpoint,
            headers=headers,
            timeout=15,
        )

        response.raise_for_status()

    except requests.exceptions.Timeout:
        log("ERROR", "Yêu cầu hash bị quá thời gian chờ.")
        return None

    except requests.exceptions.ConnectionError:
        log("ERROR", "Không thể kết nối tới VirusTotal.")
        return None

    except requests.exceptions.HTTPError:
        log(
            "ERROR",
            f"VirusTotal hash trả lỗi HTTP: {response.status_code}",
        )
        return None

    except requests.exceptions.RequestException as error:
        log(
            "ERROR",
            f"Lỗi khi gửi yêu cầu hash: {error}",
        )
        return None

    log(
        "INFO",
        f"VirusTotal Hash HTTP Status: {response.status_code}",
    )

    try:
        json_data = response.json()
        attributes = json_data["data"]["attributes"]

    except (ValueError, KeyError, TypeError):
        log(
            "ERROR",
            "Dữ liệu hash VirusTotal trả về không hợp lệ.",
        )
        return None

    return attributes
