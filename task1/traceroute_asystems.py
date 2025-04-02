import subprocess
import requests
import re
from ipaddress import ip_address, IPv4Address


def is_private_ip(ip):
    try:
        return ip_address(ip).is_private
    except ValueError:
        return False


def trace_as(target):
    trace_output = []
    try:
        trace_result = subprocess.check_output(['tracert', '-d', target]).decode('cp866', errors='ignore')
        trace_output = trace_result.splitlines()
    except Exception as e:
        trace_output.append("Error: " + str(e))

    as_info = {}
    ipv4_regex = r'\b(?:\d{1,3}\.){3}\d{1,3}\b'

    for line in trace_output:
        if '***' in line:
            break  # Прекращаем обработку, если встретили ***

        ipv4_match = re.search(ipv4_regex, line)
        if ipv4_match:
            ip_address = ipv4_match.group()
            if is_private_ip(ip_address):
                as_info[ip_address] = ("N/A (private)", "N/A", "N/A")
            else:
                as_info[ip_address] = get_as(ip_address)

    return as_info


def get_as(ip_address):
    try:
        response = requests.get(f"https://stat.ripe.net/data/prefix-overview/data.json?resource={ip_address}", timeout=5)
        response_country = requests.get(f"https://stat.ripe.net/data/rir/data.json?resource={ip_address}&lod=2", timeout=5)
        data = response.json()
        data_country = response_country.json()

        as_number = data["data"]["asns"][0]["asn"] if data["data"]["asns"] else "Unknown"

        country = None
        if "data" in data_country and "rirs" in data_country["data"] and data_country["data"]["rirs"]:
            for rir in data_country["data"]["rirs"]:
                if rir.get("country"):
                    country = rir["country"]
                    break

        provider = data["data"]["asns"][0]["holder"] if data["data"]["asns"] else "Unknown"

        return as_number, country, provider
    except Exception as e:
        print(f"Error fetching AS info for {ip_address}: {e}")
        return "Unknown", "Unknown", "Unknown"


if __name__ == "__main__":
    target = input("Введите доменное имя или IP адрес: ")
    as_info = trace_as(target)
    print("{: >5} {: >20} {: >10} {: >15} {: >30}".format("# N", "IP", "AS", "Country", "Provider"))
    for i, (ip, (as_number, country, provider)) in enumerate(as_info.items(), start=1):
        print("{: >5} {: >20} {: >10} {: >15} {: >30}".format(i, ip, as_number, country or "N/A", provider))
