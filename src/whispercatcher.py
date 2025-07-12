import os, sys
import time

sys.path.append("src")
from traffic.capture_traffic import capture_traffic
from static_analyzer.key_apis_extractor import static_analyzer
from instrumentation.data_extractor import hook_analyzer
from llm.privacy_extractor import privacy_analyzer
from config import (
    apk_dir,
    log_path,
    traffic_blacklist_path,
    traffic_filtered_output_dir,
    key_apis_output_dir,
    hook_output_dir,
    llm_privacy_extraction_output_dir,
)
from loguru import logger
from loguru._defaults import LOGURU_FORMAT
from utils import map_traffic_entry_with_api_instrumentation

frida_path = "/data/local/tmp/fs16.1.5arm64"
timestamp = time.strftime("%Y-%m-%d_%H_%M_%S", time.localtime())  # for logger

if __name__ == "__main__":
    # caputre traffic
    traffic_capture_logger_config = {
        "bind_name": "traffic_capture",
        "file_sink": f"{log_path}/traffic_capture_{timestamp}.log",
    }
    traffic_capture_logger = logger.bind(name=traffic_capture_logger_config["bind_name"])
    traffic_capture_logger.add(
        traffic_capture_logger_config["file_sink"],
        encoding="utf-8",
        enqueue=True,
        filter=lambda msg: msg["extra"].get("name") == traffic_capture_logger_config["bind_name"],
    )
    capture_traffic(traffic_capture_logger, traffic_capture_logger_config, apk_dir, frida_path, traffic_blacklist_path)
    # files are written to traffic_output_dir
    # default: output/traffic/pkgname-apkname-simple.json & output/traffic/pkgname-apkname-raw.bin
    # first run: generate apks_info.json in apk_dir

    # static analyzer: extract cgs & key apis
    static_analyze_logger = logger.bind(name="static_analyze")
    static_analyze_logger.add(
        f"{log_path}/static_analyze_{timestamp}.log", encoding="utf-8", enqueue=True, filter=lambda msg: msg["extra"].get("name") == "static_analyze"
    )
    static_analyzer(static_analyze_logger, apk_dir)
    # files are written to soot_analyze_output_dir & key_apis_output_dir
    # default: output/soot_analyze/pkgname-apkname-soot-apis.json & output/key_apis/pkgname-apkname-key-apis.json

    # hook analyzer: instrument and extract data
    logger.remove()  # remove default logger, for creating recorders
    hook_logger_config = {
        "bind_name": "hook_analyze",
        "format": LOGURU_FORMAT,
        "file_sink": f"{log_path}/hook_analyze_{timestamp}.log",
    }
    hook_logger = logger.bind(name=hook_logger_config["bind_name"])
    hook_logger.add(
        sys.stdout,
        format=hook_logger_config["format"],
        enqueue=True,
        filter=lambda msg: msg["extra"].get("name") == hook_logger_config["bind_name"],
    )
    hook_logger.add(
        hook_logger_config["file_sink"],
        format=hook_logger_config["format"],
        enqueue=True,
        encoding="utf-8",
        filter=lambda msg: msg["extra"].get("name") == hook_logger_config["bind_name"],
    )
    hook_analyzer(hook_logger, hook_logger_config, apk_dir, frida_path)
    # files are written to hook_output_dir
    # default: output/hook/pkgname-apkname-loaded_classes.json (enable debug) & output/hook/pkgname-apkname-hooked_methods.json (enable debug) &
    # output/hook/pkgname-apkname-data_map.json (all app level recovered data)

    # fine-grained analysis: map traffic entries with instrumentation results & extract plaintext and ciphertext content (all traffic level data)
    data_map_files = [os.path.join(hook_output_dir, file) for file in os.listdir(hook_output_dir) if file.endswith("data_map.json")]
    filtered_traffic_files = [
        os.path.join(traffic_filtered_output_dir, file) for file in os.listdir(traffic_filtered_output_dir) if file.endswith("simple.json")
    ]
    key_apis_files = [os.path.join(key_apis_output_dir, file) for file in os.listdir(key_apis_output_dir) if file.endswith("key-apis.json")]
    map_traffic_entry_with_api_instrumentation(filtered_traffic_files, key_apis_files, data_map_files)
    # default: output/hook/pkgname-apkname-traffic_entry_map.json

    # llm privacy analyze: infer transmitted private data
    privacy_analyze_logger = logger.bind(name="privacy_analyze")
    privacy_analyze_logger.add(
        f"{log_path}/privacy_analyze_{timestamp}.log", encoding="utf-8", enqueue=True, filter=lambda msg: msg["extra"].get("name") == "privacy_analyze"
    )
    privacy_analyzer(hook_output_dir, llm_privacy_extraction_output_dir, privacy_analyze_logger)
