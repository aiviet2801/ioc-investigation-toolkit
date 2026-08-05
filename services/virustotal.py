import requests

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
