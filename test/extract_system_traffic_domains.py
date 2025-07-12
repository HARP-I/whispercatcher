import json
import os
from urllib.parse import urlparse, parse_qs


# mitmdump -s src/traffic/httpdump.py --set pkg_name=TEST --set apk_name=TEST, keep the device silent for a while
def extract_domains_from_json_lst():
    domains = set()
    traffic_json_path = "test/TEST-TEST-simple.json"
    with open(traffic_json_path, "r", encoding="utf-8") as f:
        traffic_lst = json.load(f)
        for traffic_item in traffic_lst:
            url = traffic_item["url"]
            domain = urlparse(url).netloc
            domains.add(domain)
    for domain in domains:
        print(domain)
    print(len(domains))


if __name__ == "__main__":
    extract_domains_from_json_lst()
