import requests

from utils.logger import log


def get_ip_report(ip_address, api_key):
    url = "https://api.abuseipdb.com/api/v2/check"

    headers = {
        "Accept": "application/json",
        "Key": api_key,
    }

    params = {
        "ipAddress": ip_address,
        "maxAgeInDays": 90,
    }

    log("INFO", "Đang gửi yêu cầu tới AbuseIPDB...")

    try:
        response = requests.get(
            url,
            headers=headers,
            params=params,
            timeout=15,
        )

        response.raise_for_status()

    except requests.exceptions.Timeout:
        log("ERROR", "AbuseIPDB bị quá thời gian chờ.")
        return None

    except requests.exceptions.ConnectionError:
        log("ERROR", "Không thể kết nối tới AbuseIPDB.")
        return None

    except requests.exceptions.HTTPError:
        log(
            "ERROR",
            f"AbuseIPDB trả lỗi HTTP: {response.status_code}",
        )
        return None

    except requests.exceptions.RequestException as error:
        log("ERROR", f"Lỗi khi gọi AbuseIPDB: {error}")
        return None

    log("INFO", f"AbuseIPDB HTTP Status: {response.status_code}")

    try:
        json_data = response.json()
        data = json_data["data"]
    except (ValueError, KeyError, TypeError):
        log("ERROR", "Dữ liệu AbuseIPDB trả về không hợp lệ.")
        return None

    return data
