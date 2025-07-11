import json
import os
import ast
import re
import sys

sys.path.append("src")
from urllib.parse import urlparse, parse_qs
from config import traffic_keywords_output_dir
from utils import is_json_string, extract_traffic_entry_plaintext_and_ciphertext


def extract_all_json_keys(data, key_set):
    """Recursively extract all keys from nested json object."""
    if isinstance(data, dict):
        for key, value in data.items():
            key_set.add(key)
            extract_all_json_keys(value, key_set)
    elif isinstance(data, list):
        for item in data:
            extract_all_json_keys(item, key_set)


def extract_ciphertext_keywords_from_traffic_file(traffic_file):
    traffic_keywords = []
    with open(traffic_file, "r", encoding="utf-8") as file:
        traffic_file_json = json.load(file)
        traffic_lst = traffic_file_json["traffic"]
        for traffic_entry in traffic_lst:
            traffic_id = traffic_entry["traffic_id"]
            request_method = traffic_entry["request_method"]
            url = traffic_entry["url"]
            parsed_url = urlparse(url)
            host = parsed_url.netloc
            subpaths = parsed_url.path.strip("/").split("/")
            _, ciphertext_info = extract_traffic_entry_plaintext_and_ciphertext(traffic_entry)
            ciphertext_keys_without_index_set = set([re.sub(r'\[.*?\]', '', k) for k in ciphertext_info.keys()])
            ciphertext_keys_set = set()
            for key in ciphertext_keys_without_index_set:
                if key.find(".") != -1:
                    for item in key.split("."):
                        ciphertext_keys_set.add(item)
                else:
                    ciphertext_keys_set.add(key)

            # ignore traffic without ciphertext
            if len(ciphertext_keys_set) == 0:
                continue

            # content data from traffic entry
            content_data = ""
            if "content" in traffic_entry and not (traffic_entry["content"]).startswith("RAW_CONTENT_"):
                content_dict = ast.literal_eval(traffic_entry["content"])
                if "content" in content_dict and content_dict["content"]:
                    content_data = content_dict["content"]  # Check if content is json format

            entry_result = {
                "id": traffic_id,
                "url": url,
                "content": content_data,
                "method": request_method,
                "keys": list(set([host] + subpaths + host.split(".")) - ciphertext_keys_set),
                "doubleWeightKeys": list(ciphertext_keys_set),
            }
            traffic_keywords.append(entry_result)
    return traffic_keywords


def extract_all_keywords_from_traffic_file(traffic_file, enable_headers_keywords=True):
    traffic_keywords = []
    unstandard_json_pattern_str = r'([\w.-]+)=((?:\{[\s\S]*?\})|\[[\s\S]*?\])'  # key=json_data
    common_request_headers = [
        "host",
        "user-agent",
        "accept",
        "accept-encoding",
        "accept-language",
        "connection",
        "referer",
        "origin",
        "cookie",
        "authorization",
        "content-type",
        "content-length",
        "x-requested-with",
        "dnt",
        "cache-control",
        "upgrade-insecure-requests",
        "te",
        "pragma",
        "if-modified-since",
        "if-none-match",
        "sec-fetch-dest",
        "sec-fetch-mode",
        "sec-fetch-site",
        "sec-fetch-user",
        "forwarded",
        "x-forwarded-for",
        "x-forwarded-proto",
        "x-real-ip",
        "x-frame-options",
    ]
    with open(traffic_file, "r", encoding="utf-8") as file:
        traffic_file_json = json.load(file)
        traffic_lst = traffic_file_json["traffic"]
        for traffic_entry in traffic_lst:
            traffic_id = traffic_entry["traffic_id"]
            package_name = traffic_entry["package_name"]
            request_method = traffic_entry["request_method"]
            url = traffic_entry["url"]
            headers = traffic_entry["headers"] if enable_headers_keywords and "headers" in traffic_entry else {}
            parsed_url = urlparse(url)
            host = parsed_url.netloc
            subpaths = parsed_url.path.strip("/").split("/")
            query_params = parse_qs(parsed_url.query).keys()

            # extract keys from the headers
            headers_keys = set()
            if enable_headers_keywords:
                for key in headers.keys():
                    if key.lower() not in common_request_headers:
                        headers_keys.add(key)

            # extract keys from the content
            body_keys = set()
            content_data = ""
            if "content" in traffic_entry and not (traffic_entry["content"]).startswith("RAW_CONTENT_"):
                content_dict = ast.literal_eval(traffic_entry["content"])
                if "content" in content_dict and content_dict["content"]:
                    content_data = content_dict["content"]  # Check if content is json format
                    # If the content is in json format, parse it
                    is_json, json_data = is_json_string(content_data)
                    if is_json:
                        extract_all_json_keys(json_data, body_keys)
                    else:
                        # try to parse as URL-encoded form data
                        try:
                            params_dict = parse_qs(content_data)
                            extract_all_json_keys(params_dict, body_keys)
                        except Exception:
                            # If not, try to parse it as non-standard json format e.g. msg=["a": 1, "b": 2]
                            matches = re.findall(unstandard_json_pattern_str, content_data)
                            for match in matches:
                                key, value = match[0], match[1]
                                body_keys.add(key)
                                item_is_json, item_json_data = is_json_string(value)
                                if item_is_json:
                                    extract_all_json_keys(item_json_data, body_keys)
            double_weight_keywords = [host]
            double_weight_keywords.extend(host.split("."))
            double_weight_keywords.extend(subpaths)
            entry_result = {
                "id": traffic_id,
                "url": url,
                "content": content_data,
                "method": request_method,
                "keys": list(query_params) + list(headers_keys) + list(body_keys),
                "doubleWeightKeys": double_weight_keywords,
            }
            traffic_keywords.append(entry_result)

    return traffic_keywords


# parse traffic keywords and output to files
def parse_traffic_keywords(apk_path, package_name, apk_name, traffic_path, logger):
    try:
        traffic_keywords = extract_all_keywords_from_traffic_file(traffic_path)
        traffic_keywords_info = {"apkId": apk_name, "pkgName": package_name, "pkgPath": apk_path, "flows": traffic_keywords}
        traffic_keywords_info_path = os.path.join(traffic_keywords_output_dir, f"{package_name}-{apk_name}-traffic_keywords_info.json")
        with open(traffic_keywords_info_path, "w", encoding="utf-8") as f:
            json.dump(traffic_keywords_info, f, indent=4, ensure_ascii=False)
        logger.info(f"[extract traffic keywords] Extract traffic keywords info success. | Output file = {traffic_keywords_info_path}")
    except Exception as e:
        logger.error(f"[extract traffic keywords] Extract traffic keywords info failed. | Error message = {e}")
