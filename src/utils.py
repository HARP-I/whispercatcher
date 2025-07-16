import os, sys
import traceback
import re
import json
import time
import subprocess
import shutil
import pandas as pd
import ast
import math
import random
import zipfile
import tempfile
import magic
from multiprocessing import Process
from androguard.core.bytecodes.apk import APK as andro_APK
from adbutils import AdbDevice
from config import adbutils, device, adb_client
from urllib.parse import unquote, urlparse, parse_qs
from collections import defaultdict, Counter
from nltk.corpus import words
from binary_infer import decode_by_mime


def collect_apks(path: str, logger) -> list[str]:
    """Return paths of all apks in the given directory."""
    apks_lst = []
    queue = [path]
    info_exists = os.path.exists(os.path.join(path, "apks_info.json"))
    if not info_exists:
        apks_info = {}
        apk_info_json = open(os.path.join(path, "apks_info.json"), "w", encoding="utf-8") if not info_exists else None
        while len(queue):
            cur_item = queue.pop()
            for file in os.listdir(cur_item):
                try:
                    f_path = os.path.join(cur_item, file)
                    if os.path.isdir(f_path):
                        queue.append(f_path)
                    elif file.endswith(".apk"):
                        apks_lst.append(f_path)
                        apk = andro_APK(f_path)
                        apks_info[f_path] = {"pkg_name": apk.get_package(), "file_name": os.path.basename(f_path)[:-4]}
                        del apk
                    elif file.endswith(".xapk"):
                        apks_lst.append(f_path)
                        pkg_name, _ = get_xapk_pakgename_permissions(f_path)
                        apks_info[f_path] = {"pkg_name": pkg_name, "file_name": os.path.basename(f_path)[:-5]}
                except:
                    logger.error(f"[capture_traffic] Error from collecting apks: {traceback.format_exc()}")
        json.dump(apks_info, apk_info_json, indent=4, ensure_ascii=False)
        apk_info_json.close()
    else:
        while len(queue):
            cur_item = queue.pop()
            for file in os.listdir(cur_item):
                f_path = os.path.join(cur_item, file)
                if os.path.isdir(f_path):
                    queue.append(f_path)
                elif file.endswith("apk"):
                    apks_lst.append(f_path)
    return apks_lst


def get_xapk_pakgename_permissions(xapk_path):
    with tempfile.TemporaryDirectory() as tmp_dir:
        with zipfile.ZipFile(xapk_path, "r") as zip_ref:
            zip_ref.extractall(tmp_dir)
            manifest_json_path = os.path.join(tmp_dir, "manifest.json")
            with open(manifest_json_path, "r", encoding="utf-8") as f:
                manifest_data = json.load(f)
                pkg_name = manifest_data["package_name"]
                permissions = manifest_data["permissions"]
    return pkg_name, permissions


def adb_shell(cmd, adb_client, device):
    return adb_client.shell(device.get_serialno(), cmd)


# for frida forwarding
def adb_forwards(device, logger):
    if device is None:
        logger.error("No device found.")
        sys.exit(1)
    else:
        logger.info(f"[adb forward] Current device: {device.get_serialno()}")

    try:
        device.forward("tcp:27042", "tcp:27042")
        device.forward("tcp:27043", "tcp:27043")
    except:
        logger.warning(f"Execution: adb forward failed.")


def apk_install(apk_path, device: AdbDevice, frida_path):
    def callback_wrapper(flag):
        if flag == "FINALLY":
            wake_up_device_if_shutdown(adb_client, device, frida_path, kill_frida_first=False)

    if os.path.exists(apk_path) and device:
        try:
            # for apk
            device.install(apk_path, nolaunch=True, uninstall=True, callback=callback_wrapper)
        except:
            # for xpak
            with tempfile.TemporaryDirectory() as tmp_dir:
                with zipfile.ZipFile(apk_path, "r") as zip_ref:
                    zip_ref.extractall(tmp_dir)
                    subapk_path = [os.path.join(tmp_dir, file) for file in os.listdir(tmp_dir) if file.endswith(".apk")]
                    os.system(f"{adbutils.adb_path()} install-multiple {' '.join(subapk_path)}")
            wake_up_device_if_shutdown(adb_client, device, frida_path, kill_frida_first=False)


def adb_uninstall(pkg_name, device: AdbDevice):
    device.uninstall(pkg_name)


def adb_su_shell(serial, cmd):
    def run_cmd():
        p = subprocess.Popen(f"adb -s {serial} shell", shell=True, stdin=subprocess.PIPE, stdout=subprocess.PIPE)
        p.stdin.write(bytes("su\n", encoding="utf-8"))
        p.stdin.flush()
        p.stdin.write(bytes(f"{cmd}\n", encoding="utf-8"))
        p.stdin.flush()  # get root shell and execute commands
        p.communicate()
        p.kill()

    proc = Process(target=run_cmd).start()
    time.sleep(2)  # wait for cmd execution
    proc.terminate()


def run_frida(adb_client, device, fr="/data/local/tmp/fs16.1.5arm64"):
    keyword = os.path.basename(fr)
    # check if frida server is running
    pid = adb_shell("su -c netstat -tunlp | grep " + keyword + """ | awk '{print $7}' | cut -d '/' -f1""", adb_client, device)
    if pid == "":
        adb_shell(f"su -c \"{fr}\"", adb_client, device)


def kill_frida(adb_client, device, fr="/data/local/tmp/fs16.1.5arm64"):
    keyword = os.path.basename(fr)
    pid = adb_shell("su -c netstat -tunlp | grep " + keyword + """ | awk '{print $7}' | cut -d '/' -f1""", adb_client, device)
    adb_shell(f"su -c kill -9 {pid}", adb_client, device)


def wake_up_device_if_shutdown(adb_client, device, frida_path, kill_frida_first=True):
    ret = False
    if kill_frida_first:
        kill_frida(adb_client, device, frida_path)  # from exception
    display_state = adb_shell("dumpsys window policy | grep 'screenState'", adb_client, device)
    if display_state.find("screenState=SCREEN_STATE_OFF") != -1 or display_state.find("screenState=2") != -1:
        adb_shell("input keyevent 224", adb_client, device)  # power
        time.sleep(3)
        adb_shell("input swipe 300 1500 300 200", adb_client, device)  # swipe up
        time.sleep(3)
        adb_shell("input tap 200 200", adb_client, device)  # cancel pop up window if exists
        time.sleep(3)
        ret = True
    if kill_frida_first:
        # from exception
        for i in range(5):
            adb_shell("input keyevent 3", adb_client, device)  # back to home
            time.sleep(1)
    return ret


def check_device_connection(logger, retry=3):
    if retry == 0:
        logger.error("Cannot connect to the device.")
        sys.exit(1)
    f = os.popen("adb devices")
    output = f.readlines()
    f.close()
    if len(output) < 3:
        logger.warning(f"No devices etected. Retrying: {4-retry}")
        time.sleep(3)
        os.system("adb devices")
        time.sleep(6)
        check_device_connection(retry - 1)
    elif len(output) > 3:
        logger.warning(f"Multiple devices detected. Use the first one.")
        logger.info(f"[adb devices] Device info: {output[1]}")
    else:
        logger.info(f"[adb devices] Device info: {output[1]}")
        global device, adb_client
        adb_client = adbutils.AdbClient()
        devices = adb_client.device_list()
        device = devices[0]


def check_permission_full_screen_window(adb_client, device):
    resumed_info = adb_shell("dumpsys activity activities | grep mResumedActivity", adb_client, device)
    return resumed_info.find("com.android.permissioncontroller/") != -1


def clear_and_archive_output_dir(src_dir, archive_dir):
    timestamp = time.strftime("%Y-%m-%d_%H_%M_%S", time.localtime())  # for logger
    os.makedirs(archive_dir, exist_ok=True)
    shutil.make_archive(f"{archive_dir}/{os.path.basename(src_dir)}-{timestamp}", "zip", src_dir)
    shutil.rmtree(src_dir)


def unquote_url_encoded_string(suspicious_str):
    unquote_before = suspicious_str
    unquote_res = unquote(suspicious_str)
    while unquote_res != unquote_before:
        unquote_before = unquote_res
        unquote_res = unquote(unquote_res)
    return unquote_res


def prepare_apk(apk_path):
    # for apk
    apk = andro_APK(apk_path)
    pkg_name, permissions = apk.get_package(), apk.get_permissions()
    del apk
    # for xpak
    if pkg_name == "" and apk_path.endswith(".xapk"):
        pkg_name, permissions = get_xapk_pakgename_permissions(apk_path)
    return pkg_name, permissions


def grant_permissions(pers, pkg_name, adb_client, device):
    for per in pers:
        adb_shell(f"su -c pm grant {pkg_name} {per}", adb_client, device)


def reformat_data_map(data_map, magic_detector):
    new_data_map = defaultdict(list)
    new_data_map_set_map = defaultdict(set)  # deduplicate data_map
    for item in data_map:
        api, args, ret = item["api"], item["args"], item["ret"] if "ret" in item else None
        # parse args
        for ind in range(len(args)):
            if isinstance(args[ind], list) and all(isinstance(item, int) for item in args[ind]):
                args[ind] = [(elem + 256) % 256 for elem in args[ind]]
                bytes_data = bytes(args[ind])
                mime_type = magic_detector.from_buffer(bytes_data)
                args[ind] = decode_by_mime(bytes_data, mime_type)
        # parse url encode
        for ind in range(len(args)):
            if str(args[ind]).startswith("http"):
                args[ind] = unquote_url_encoded_string(args[ind])
        # parse ret
        if isinstance(ret, list) and all(isinstance(item, int) for item in ret):
            ret = [(elem + 256) % 256 for elem in ret]
            ret_bytes = bytes(ret)
            mime_type = magic_detector.from_buffer(ret_bytes)
            ret = decode_by_mime(ret_bytes, mime_type)
        # deduplicate
        str_api_info = str({"args": args, "ret": ret})
        if str_api_info not in new_data_map_set_map[api]:
            new_data_map_set_map[api].add(str_api_info)
            new_data_map[api].append({"args": args, "ret": ret})
    return new_data_map


def reformat_data_map_with_param_ver(data_map, magic_detector):
    new_data_map = defaultdict(list)
    new_data_map_set_map = defaultdict(set)  # deduplicate data_map
    for api_name, api_calls in data_map.items():
        if not isinstance(api_calls, list):
            continue
        for call_record in api_calls:
            if not isinstance(call_record, dict):
                continue
            args = call_record.get("args", [])
            ret = call_record.get("ret", None)
            # parse args
            for ind in range(len(args)):
                if isinstance(args[ind], list) and all(isinstance(item, int) for item in args[ind]):
                    args[ind] = [(elem + 256) % 256 for elem in args[ind]]
                    bytes_data = bytes(args[ind])
                    mime_type = magic_detector.from_buffer(bytes_data)
                    args[ind] = decode_by_mime(bytes_data, mime_type)
            # parse url encode
            for ind in range(len(args)):
                if str(args[ind]).startswith("http"):
                    args[ind] = unquote_url_encoded_string(args[ind])
            # parse ret
            if isinstance(ret, list) and all(isinstance(item, int) for item in ret):
                ret = [(elem + 256) % 256 for elem in ret]
                ret_bytes = bytes(ret)
                mime_type = magic_detector.from_buffer(ret_bytes)
                ret = decode_by_mime(ret_bytes, mime_type)
            # deduplicate
            str_api_info = str({"args": args, "ret": ret})
            if str_api_info not in new_data_map_set_map[api_name]:
                new_data_map_set_map[api_name].add(str_api_info)
                new_data_map[api_name].append({"args": args, "ret": ret})
    return new_data_map


def extract_method_name_from_signature(method_signature):
    if '(' in method_signature:
        return method_signature.split('(')[0]
    return method_signature


def mapping_single_traffic_file_with_instrumentation(traffic_data, key_apis_data, data_map, magic_detector):
    traffic_map = []
    # if data_map is not parsed, reformat it
    # new_data_map = reformat_data_map(data_map, magic_detector)
    new_data_map = reformat_data_map_with_param_ver(data_map, magic_detector)

    # save mapping data
    for traffic_item in traffic_data["traffic"]:
        plaintext_info, ciphertext_info = extract_traffic_entry_plaintext_and_ciphertext(traffic_item)
        traffic_id, url, request_method, headers, content = (
            traffic_item["traffic_id"],
            traffic_item["url"],
            traffic_item["request_method"],
            traffic_item["headers"] if "headers" in traffic_item else {},
            ast.literal_eval(traffic_item["content"]),
        )
        # parse headers
        for key, value in headers.items():
            if isinstance(value, str) and value.count("%") > 0:
                headers[key] = unquote_url_encoded_string(value)
        # parse mapping data
        key_apis_lst = key_apis_data.get(traffic_id, [])
        instrumentation_result = {}
        for key_api_signature in key_apis_lst:
            method_name = extract_method_name_from_signature(key_api_signature)
            if method_name in new_data_map:
                instrumentation_result[method_name] = new_data_map[method_name]
        if len(ciphertext_info) > 0:
            traffic_map.append(
                {
                    "traffic_id": traffic_id,
                    "request_method": request_method,
                    "url": url,
                    "headers": headers,
                    "content": content,
                    "plaintext_info": plaintext_info,
                    "ciphertext_info": ciphertext_info,
                    "instrumentation_result": instrumentation_result,
                }
            )

        else:
            # no ciphertext info
            traffic_map.append(
                {
                    "traffic_id": traffic_id,
                    "request_method": request_method,
                    "url": url,
                    "headers": headers,
                    "content": content,
                    "plaintext_info": plaintext_info,
                }
            )
    return traffic_map


def mapping_single_traffic_file_without_instrumentation(traffic_data):
    traffic_map = []
    for traffic_item in traffic_data["traffic"]:
        plaintext_info, ciphertext_info = extract_traffic_entry_plaintext_and_ciphertext(traffic_item)
        traffic_id, url, request_method, headers, content = (
            traffic_item["traffic_id"],
            traffic_item["url"],
            traffic_item["request_method"],
            traffic_item["headers"] if "headers" in traffic_item else {},
            ast.literal_eval(traffic_item["content"]),
        )
        # parse headers
        for key, value in headers.items():
            if isinstance(value, str) and value.count("%") > 0:
                headers[key] = unquote_url_encoded_string(value)
        if len(ciphertext_info) > 0:
            traffic_map.append(
                {
                    "traffic_id": traffic_id,
                    "request_method": request_method,
                    "url": url,
                    "headers": headers,
                    "content": content,
                    "plaintext_info": plaintext_info,
                    "ciphertext_info": ciphertext_info,
                    "instrumentation_result": None,
                }
            )
        else:
            # no ciphertext info
            traffic_map.append(
                {
                    "traffic_id": traffic_id,
                    "request_method": request_method,
                    "url": url,
                    "headers": headers,
                    "content": content,
                    "plaintext_info": plaintext_info,
                }
            )
    return traffic_map


def map_traffic_entry_with_api_instrumentation(filtered_traffic_files_lst, key_apis_files_lst, data_map_files_lst):
    """Traffic entry with related apis"""
    if len(data_map_files_lst) == 0 or len(data_map_files_lst) == 0:
        print("[map_traffic_entry_with_api_instrumentation] No data map files or key apis files found, exit.")
        sys.exit(0)
    data_map_files = [os.path.basename(data_map_file) for data_map_file in data_map_files_lst]
    key_apis_filenames = [os.path.basename(key_apis_file) for key_apis_file in key_apis_files_lst]
    data_map_dir = os.path.dirname(data_map_files_lst[0])
    key_apis_dir = os.path.dirname(key_apis_files_lst[0])
    magic_detector = magic.Magic(mime=True)

    # filtered_traffic_file, key_apis_file, data_map_file mapping
    for traffic_file in filtered_traffic_files_lst:
        traffic_file_basename = os.path.basename(traffic_file)
        basename_lst = traffic_file_basename.split("-")
        mapping_data_map_filename = f"{basename_lst[0]}-{basename_lst[1]}-data_map.json"
        mapping_key_apis_filename = f"{basename_lst[0]}-{basename_lst[1]}-key-apis.json"
        traffic_entry_map_file = os.path.join(data_map_dir, f"{basename_lst[0]}-{basename_lst[1]}-traffic_entry_map.json")

        # check if traffic file is empty
        with open(traffic_file, "r", encoding="utf-8") as f:
            traffic_data = json.load(f)
            if os.stat(traffic_file).st_size == 0 or len(traffic_data["traffic"]) == 0:
                print(f"[map_traffic_entry_with_api_instrumentation] Current traffic file: {traffic_file} is empty, skip.")
                continue

        # organize related data
        complete_flag = True
        if mapping_data_map_filename in data_map_files and mapping_key_apis_filename in key_apis_filenames:
            # load instrumentation data map
            if os.stat(os.path.join(data_map_dir, mapping_data_map_filename)).st_size == 0:
                complete_flag = False
            else:
                try:
                    with open(os.path.join(data_map_dir, mapping_data_map_filename), "r", encoding="utf-8") as f:
                        data_map = json.load(f)
                        data_map = data_map["data_map"]
                except json.decoder.JSONDecodeError:
                    print(
                        f"[map_traffic_entry_with_api_instrumentation] Error occurred, current data_map.json file: {os.path.join(data_map_dir, mapping_data_map_filename)} is empty or invalid, skip."
                    )
                    input("please fix the issue and press Enter to continue...")
                if len(data_map) == 0:
                    complete_flag = False
            # load key apis
            with open(os.path.join(key_apis_dir, mapping_key_apis_filename), "r", encoding="utf-8") as f:
                key_apis_data = json.load(f)
        else:
            complete_flag = False

        # check completeness
        print(
            f"[map_traffic_entry_with_api_instrumentation] Current traffic file: {traffic_file}, current key_apis file: {os.path.join(key_apis_dir, mapping_key_apis_filename)}, current data_map.json file: {os.path.join(data_map_dir, mapping_data_map_filename)}"
        )
        if complete_flag:
            traffic_map = mapping_single_traffic_file_with_instrumentation(traffic_data, key_apis_data, data_map, magic_detector)
        else:
            traffic_map = mapping_single_traffic_file_without_instrumentation(traffic_data)
        try:
            with open(traffic_entry_map_file, "w", encoding="utf-8") as f:
                json.dump(traffic_map, f, indent=4, ensure_ascii=False)
        except Exception as e:
            print(f"[map_traffic_entry_with_api_instrumentation] Error occurred: {e}")
            input("please fix the issue and press Enter to continue...")


# filter finished traffic files
def filter_traffic_finished_apks(traffic_files_input_dir="output/traffic"):
    finished_apks_lst = []
    traffic_files = [traffic_file for traffic_file in os.listdir(traffic_files_input_dir) if traffic_file.endswith("simple.json")]
    for traffic_file_name in traffic_files:
        package_name = traffic_file_name.split("-")[0]
        if package_name not in finished_apks_lst:
            finished_apks_lst.append(package_name)
    return finished_apks_lst


# filter unrelated traffic using blacklist
def traffic_filter(blacklist_path, traffic_files_input_dir, traffic_files_output_dir, logger, end_with):
    with open(blacklist_path, "r", encoding="utf-8") as f:
        blacklist = [item.strip() for item in f.readlines()]
    traffic_files = [
        os.path.join(traffic_files_input_dir, traffic_file) for traffic_file in os.listdir(traffic_files_input_dir) if traffic_file.endswith(end_with)
    ]
    logger.info(f"[capture traffic] Filtering traffic using blacklist: {blacklist}")
    for traffic_file in traffic_files:
        try:
            new_traffic_data = []
            try:
                with open(traffic_file, "r", encoding="utf-8") as f:
                    original_traffic_data = json.load(f)
            except json.decoder.JSONDecodeError:
                with open(traffic_file, "r", encoding="utf-8") as f1:
                    content = f1.read()
                    content = "{ \"traffic\": [" + content[:-2] + "] }"
                with open(traffic_file, "w", encoding="utf-8") as f2:
                    f2.write(json.dumps(json.loads(content), indent=4, ensure_ascii=False))
                with open(traffic_file, "r", encoding="utf-8") as f3:
                    original_traffic_data = json.load(f3)
            for item in original_traffic_data["traffic"]:
                if urlparse(item["url"]).hostname not in blacklist:
                    new_traffic_data.append(item)
            with open(os.path.join(traffic_files_output_dir, os.path.basename(traffic_file)), "w", encoding="utf-8") as f:
                json.dump({"traffic": new_traffic_data}, f, indent=4, ensure_ascii=False)
        except Exception as e:
            logger.error(f"[capture traffic] Error from filtering traffic file: {traffic_file} | {e}")


def is_json_string(data):
    try:
        json_data = json.loads(data)
        return True, json_data
    except ValueError:
        return False, data


def flat_json_data(data, prefix="", result=None):
    if result is None:
        result = {}
    if isinstance(data, dict):
        for key, value in data.items():
            new_key = f"{prefix}.{key}" if prefix else key
            if not isinstance(value, (dict, list)):
                result[new_key] = value
            else:
                flat_json_data(value, new_key, result)
    elif isinstance(data, list):
        for index, item in enumerate(data):
            new_key = f"{prefix}[{index}]"
            if not isinstance(item, (dict, list)):
                result[new_key] = item
            else:
                flat_json_data(item, new_key, result)
    return result


def format_list_item_in_dict(dict_data):
    for key, value in dict_data.items():
        if isinstance(value, list) and len(value) == 1:
            dict_data[key] = value[0]
    return dict_data


def flat_key_str(key_str):
    """remove index"""
    key = re.sub(r"\[\d+\]", "", key_str)  # remove index in list
    return [item for item in key.split(".") if item]



def str_contains_natural_lang(test_str):
    # split elems: . _ - / \ : ; , | @ # ~ & = + * space
    split_elems = [".", "_", "-"]
    for split_elem in split_elems:
        str_elems = test_str.split(split_elem)
        if any(str_elem in words.words() for str_elem in str_elems if len(str_elem) > 1):  # ignore single char
            return True
    return False


def extract_traffic_entry_plaintext_and_ciphertext(traffic_entry):
    """Url query param keys and content data param keys."""
    if traffic_entry is None or len(traffic_entry) == 0:
        return {}, {}
    enc_pattern = re.compile(
        r"\b(" + "|".join(["cipher", "encrypt", "encode", "hash", "sign", "digest", "enc", "iv", "crypto", "cypher"]) + r")\b", re.IGNORECASE
    )
    id_pattern = re.compile(
        r"(\w*(id|token)(?=_[a-zA-Z0-9]|[A-Z]|$)|imei\d*|\w*key|" + "|".join(["serial", "num", "version", "url", "name"]) + r")", re.IGNORECASE
    )
    encode_pattern = re.compile(r"[A-Za-z0-9+/=_-]{16,}")
    unstandard_json_pattern_str = r'([\w.-]+)=((?:\{[\s\S]*?\})|\[[\s\S]*?\])'  # key=json_data
    request_method = traffic_entry["request_method"]
    traffic_content = ast.literal_eval(traffic_entry["content"])  # query content
    query, content = flat_json_data(traffic_content["query"]), traffic_content["content"]

    # encryption pattern detection in query keys
    ciphertext_info = defaultdict(list)
    plaintext_info = defaultdict(list)
    for query_key, query_value in query.items():
        if enc_pattern.search(query_key) is not None:
            ciphertext_info[query_key].append(query_value)
        elif encode_pattern.search(query_value) is not None:
            if id_pattern.search(query_key) is None and not str_contains_natural_lang(query_value):
                ciphertext_info[query_key].append(query_value)
            else:
                plaintext_info[query_key].append(query_value)
        else:
            plaintext_info[query_key].append(query_value)

    # encryption pattern detection in content
    is_json_format, data = is_json_string(content)
    if is_json_format:
        data = flat_json_data(data)
        for key, value in data.items():
            if enc_pattern.search(key) is not None:
                ciphertext_info[key] = value
            elif encode_pattern.search(str(value)) is not None:
                if id_pattern.search(key) is None and not str_contains_natural_lang(str(value)):
                    ciphertext_info[key] = value
                else:
                    plaintext_info[key] = value
            else:
                plaintext_info[key] = value
    else:
        parse_multi_jsons = False
        json_lines = content.split("\n")
        for line in json_lines:
            line = line.strip()
            if not line:
                continue
            is_json_line, data_line = is_json_string(line)
            if is_json_line:
                parse_multi_jsons = True
                data_line = flat_json_data(data_line)
                for key, value in data_line.items():
                    if enc_pattern.search(key) is not None:
                        ciphertext_info[key] = value
                    elif encode_pattern.search(str(value)) is not None:
                        if id_pattern.search(key) is None and not str_contains_natural_lang(str(value)):
                            ciphertext_info[key] = value
                        else:
                            plaintext_info[key] = value
                    else:
                        plaintext_info[key] = value
        if not parse_multi_jsons:
            try:
                # try to parse as URL-encoded form data
                params_dict = parse_qs(content)  # the values are lists
                for key, value in params_dict.items():
                    if isinstance(value, list) and len(value) == 1:
                        params_dict[key] = value[0]
                params_data = flat_json_data(params_dict)
                if len(params_data) == 0:
                    raise ValueError("Empty params data after parsing. This maybe one encrypted form data.")
                for key, value in params_data.items():
                    if enc_pattern.search(key) is not None:
                        ciphertext_info[key] = value
                    elif encode_pattern.search(value) is not None:
                        if id_pattern.search(key) is None and not str_contains_natural_lang(value):
                            ciphertext_info[key] = value
                        else:
                            plaintext_info[key] = value
                    else:
                        plaintext_info[key] = value
            except Exception as e:
                # try to parse it as non-standard json format e.g. msg=["a": 1, "b": 2]
                matches = re.findall(unstandard_json_pattern_str, content)
                if len(matches) > 0:
                    for match in matches:
                        key, value = match[0], match[1]
                        if enc_pattern.search(key) is not None:
                            ciphertext_info[key] = value
                        elif encode_pattern.search(value) is not None:
                            if id_pattern.search(key) is None and not str_contains_natural_lang(value):
                                ciphertext_info[key] = value
                            else:
                                plaintext_info[key] = value
                        else:
                            plaintext_info[key] = value
                # if not, treat it as a string
                else:
                    if encode_pattern.search(content) is not None:
                        ciphertext_info["WHOLE_CONTENT"] = content

    return format_list_item_in_dict(plaintext_info), format_list_item_in_dict(ciphertext_info)
