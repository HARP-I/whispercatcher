import json
import os, sys
import tempfile
import zipfile
from collections import defaultdict
from static_analyzer.traffic_keywords_extractor import parse_traffic_keywords
from config import (
    soot_analyzer_path,
    soot_analyze_output_dir,
    key_apis_output_dir,
    sdk_path,
    traffic_filtered_output_dir,
    traffic_keywords_output_dir,
)


def parse_keywords_with_soot(keywords_file_name, apk_path, logger):
    split_name = keywords_file_name.split("-")
    package_name, apk_name = split_name[0], split_name[1]
    soot_output = os.path.join(soot_analyze_output_dir, f"{package_name}-{apk_name}-soot-apis.json")
    keywords_file_path = os.path.join(traffic_keywords_output_dir, keywords_file_name)
    try:
        if apk_path.endswith(".apk"):
            ret = os.system(
                f"java -cp {soot_analyzer_path} Analyzer.Application -apk {apk_path} -sdk {sdk_path} -input {keywords_file_path} -output {soot_output} -chainsLimit -1"
            )
            if ret == 0:
                logger.info(f"[parse keywords with soot] Extract keywords related apis success. | Output = {soot_output}")
            else:
                logger.error(f"[parse keywords with soot] Extract keywords related apis failed. | Output = {soot_output} | Java execution failed.")
        elif apk_path.endswith(".xapk"):
            logger.info(f"[parse keywords with soot] Analyzing sub-apks from xapk file...")
            with tempfile.TemporaryDirectory() as tmp_dir:
                with zipfile.ZipFile(apk_path, "r") as zip_ref:
                    zip_ref.extractall(tmp_dir)
                    subapk_paths = [os.path.join(tmp_dir, file) for file in os.listdir(tmp_dir) if file.endswith(".apk")]
                    sub_apis_paths = []
                    for idx, subapk_path in enumerate(subapk_paths):
                        sub_apis_path = os.path.join(tmp_dir, f"{idx}-soot-apis.json")
                        ret = os.system(
                            f"java -cp {soot_analyzer_path} Analyzer.Application -apk {subapk_path} -sdk {sdk_path} -input {keywords_file_path} -output {sub_apis_path} -chainsLimit -1"
                        )
                        if ret == 0:
                            logger.info(f"[parse keywords with soot] Extract keywords related sub apis success. | Output = {sub_apis_path}")
                        else:
                            logger.error(
                                f"[parse keywords with soot] Extract keywords related sub apis failed. | Output = {sub_apis_path} | Java execution failed."
                            )
                        sub_apis_paths.append(sub_apis_path)
                    # merge sub apis files
                    merged_apis = defaultdict(list)
                    for sub_apis_path in sub_apis_paths:
                        with open(sub_apis_path, "r", encoding="utf-8") as f:
                            sub_apis_data = json.load(f)
                            for data_item in sub_apis_data:  # [{traffic-id: call chains list}, {traffic-id: call chains list}]
                                for traffic_id, call_chains in data_item.items():
                                    merged_apis[traffic_id].extend(call_chains)
                    formated_merged_apis = []  # list format
                    for traffic_id, call_chains in merged_apis.items():
                        formated_merged_apis.append({traffic_id: call_chains})
                    with open(soot_output, "w", encoding="utf-8") as f:
                        json.dump(formated_merged_apis, f, indent=4, ensure_ascii=False)
    except Exception as e:
        logger.error(f"[parse keywords with soot] Extract keywords related apis failed. | Output = {soot_output} | {e}")


def extract_key_apis(parsed_api_file_path, logger):
    try:
        split_name = os.path.basename(parsed_api_file_path).split("-")
        package_name, apk_name = split_name[0], split_name[1]
        with open(parsed_api_file_path, "r", encoding="utf-8") as f:
            parsed_call_chains = json.load(f)
        key_apis = {}
        for traffic_id_with_call_chains in parsed_call_chains:
            if traffic_id_with_call_chains is None or len(traffic_id_with_call_chains) == 0:
                continue
            for traffic_id, call_chains in traffic_id_with_call_chains.items():  # length == 1, call_chains is related to chains_limit param
                key_apis_set = set()
                for call_chain in call_chains:
                    for entry in call_chain["stack"]:
                        if entry["source"] is not None:
                            key_apis_set.add(entry["source"])
                        if entry["target"] is not None:
                            key_apis_set.add(entry["target"])
                key_apis[traffic_id] = list(key_apis_set)
        key_apis_output = os.path.join(key_apis_output_dir, f"{package_name}-{apk_name}-key-apis.json")
        with open(key_apis_output, "w", encoding="utf-8") as f:
            json.dump(key_apis, f, indent=4, ensure_ascii=False)
    except Exception as e:
        logger.error(f"[extract key apis] Extract key apis failed. | {e}")
    return key_apis


def static_analyzer(logger, apk_dir):
    logger.info(f"[static analyzer] Starting static analysis...")
    apks_info_file = os.path.join(apk_dir, "apks_info.json") # auto-generated info file
    if not os.path.exists(apks_info_file):
        logger.error(f"[static analyzer] Apks info file not found. | File = {apks_info_file}")
        sys.exit(1)
    apks_info = open(apks_info_file, "r", encoding="utf-8")
    apks_info = json.load(apks_info)
    api_files = [file for file in os.listdir(key_apis_output_dir) if file.endswith("key-apis.json")]
    traffic_filtered_files = [file for file in os.listdir(traffic_filtered_output_dir) if file.endswith("simple.json")]
    total_apks = len(apks_info)
    for idx, apk_path in enumerate(apks_info):
        try:
            logger.info(f"[static analyzer] [start] {idx+1}/{total_apks}: apk_path = {apk_path}")
            pkg_name, file_name = apks_info[apk_path]["pkg_name"], apks_info[apk_path]["file_name"]
            traffic_path = os.path.join(traffic_filtered_output_dir, f"{pkg_name}-{file_name}-simple.json")
            # test existence
            if f"{pkg_name}-{file_name}-simple.json" not in traffic_filtered_files:
                logger.warning(f"[static analyzer] Filtered traffic file not found, skipping apk = {apk_path}.")
                continue
            if f"{pkg_name}-{file_name}-key-apis.json" in api_files:
                logger.warning(f"[static analyzer] Key apis file already exists, skipping apk = {apk_path}.")
                continue
            # write traffic keywords to file: {package_name}-{apk_name}-traffic_keywords_info.json
            logger.info(f"[static analyzer] Parsing traffic keywords for apk = {apk_path}")
            parse_traffic_keywords(apk_path, pkg_name, file_name, traffic_path, logger)

            # parse keywords with soot
            logger.info(f"[static analyzer] Parsing keywords with soot for apk = {apk_path}")
            traffic_keywords_file = f"{pkg_name}-{file_name}-traffic_keywords_info.json"
            # write parsed file: {package_name}-{apk_name}-soot-apis.json in soot_analyze_output_path
            parse_keywords_with_soot(traffic_keywords_file, apk_path, logger)

            # write extracted key apis to file: {package_name}-{apk_name}-key-apis.json in key_apis_output_path
            logger.info(f"[static analyzer] Extracting key apis for apk = {apk_path}")
            key_apis_file = os.path.join(soot_analyze_output_dir, f"{pkg_name}-{file_name}-soot-apis.json")
            extract_key_apis(key_apis_file, logger)
        except Exception as e:
            logger.error(f"[static analyzer] Static analysis failed, apk = {apk_path}. | {e}")
    logger.info(f"[static analyzer] Finished static analysis...")
