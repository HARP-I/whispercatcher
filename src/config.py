import os
import adbutils

# for input & output paths
apk_dir = "apks"
log_path = "logs"
output_dir_name = "output"
traffic_blacklist_path = os.path.join("src", "system_traffic_blacklist.txt")  # refer to test/extract_system_traffic_domains.py
traffic_output_dir = os.path.join(output_dir_name, "traffic")
traffic_filtered_output_dir = os.path.join(output_dir_name, "traffic_filtered")
traffic_keywords_output_dir = os.path.join(output_dir_name, "traffic_keywords")
soot_analyze_output_dir = os.path.join(output_dir_name, "soot_analyze")
key_apis_output_dir = os.path.join(output_dir_name, "key_apis")
hook_output_dir = os.path.join(output_dir_name, "hook")
llm_privacy_extraction_output_dir = os.path.join(output_dir_name, "llm_privacy_extraction_output")
os.makedirs(log_path, exist_ok=True)
os.makedirs(traffic_output_dir, exist_ok=True)
os.makedirs(traffic_filtered_output_dir, exist_ok=True)
os.makedirs(traffic_keywords_output_dir, exist_ok=True)
os.makedirs(soot_analyze_output_dir, exist_ok=True)
os.makedirs(key_apis_output_dir, exist_ok=True)
os.makedirs(hook_output_dir, exist_ok=True)
os.makedirs(llm_privacy_extraction_output_dir, exist_ok=True)

# for environment variables
sdk_path = "D:\\AndroidSDK\\platforms"  # platform path
soot_analyzer_path = os.path.join(os.getcwd(), "src", "static_analyzer", "sootAnalyzer.jar")

# for adb device
adb_client = adbutils.AdbClient()
devices = adb_client.device_list()
device = None if len(devices) == 0 else devices[0]

# for testing parameters
WAIT_FOR_DATA_TRANSMISSION = 60  # seconds

# configure api key for llm
OPENROUTER_API_KEY = "your_openrouter_api_key"