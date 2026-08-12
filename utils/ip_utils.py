import ipaddress


def validate_ip_address(ip_address):
    try:
        parsed_ip = ipaddress.ip_address(ip_address)

    except ValueError:
        return False, "Địa chỉ IP không hợp lệ."

    if parsed_ip.is_private:
        return False, ("Đây là địa chỉ IP nội bộ, " "không phù hợp để tra cứu OSINT.")

    return True, ""
