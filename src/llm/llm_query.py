import os
import json
import re
import time
import base64
import urllib.parse
from openai import OpenAI, RateLimitError
from config import OPENROUTER_API_KEY

os.environ["OPENROUTER_API_KEY"] = OPENROUTER_API_KEY
client = OpenAI(
    api_key=os.getenv("OPENROUTER_API_KEY"),
    base_url="https://openrouter.ai/api/v1",
)

PRIVACY_CATEGORIES = [
    "IMEI",
    "IMSI",
    "UDID",
    "DeviceID",
    "Brand/OemName",
    "Device Model",
    "Device Resolution",
    "SIM Serial",
    "SD Card Serial",
    "OperatingSystem Version",
    "CPU Model",
    "Storage Info",
    "Operator",
    "Network type",
    "MAC Address",
    "IP Address",
    "SSID",
    "BSSID",
    "Bluetooth Info",
    "Position/Location",
    "Longitude/Latitude",
    "Misc.sensors",
    "List of all apps on the device",
    "AndroidID",
    "AdvertisingID(adid)",
    "OAID",
    "UUID",
    "Phone Number",
    "SMS",
    "Account Info",
    "Clipboard Data",
]
privacy_table_md = "\n".join([f"- {item}" for item in PRIVACY_CATEGORIES])


def is_url_encoded(data: str) -> bool:
    try:
        return urllib.parse.unquote(data) != data
    except:
        return False


def is_valid_json(data: str) -> bool:
    try:
        cleaned = data.replace("\\n", "").replace("\\t", "")

        def parse(s):
            try:
                return json.loads(s)
            except:
                if (s.startswith("{") and s.endswith("}")) or (s.startswith("[") and s.endswith("]")):
                    return parse(s)
                return None

        return parse(cleaned) is not None
    except:
        return False


def is_base64_encoded(data: str) -> bool:
    try:
        if isinstance(data, str):
            base64.b64decode(data, validate=True)
            return True
    except:
        pass
    return False


def is_object_reference(data: str) -> bool:
    return bool(re.match(r"^[\w.]+@[0-9a-fA-F]+$", data))


def is_binary_data(data: str) -> bool:
    if isinstance(data, str):
        if "[Binary][application/octet-stream]" in data:
            return True
        if is_base64_encoded(data) or is_url_encoded(data) or is_object_reference(data):
            return True
    return False


def is_meaningful(data: str) -> bool:
    if len(data) < 1000:
        return True
    if is_binary_data(data):
        return False
    if is_valid_json(data) and len(data) < 300000:
        return True
    return len(data) < 100000


def filter_instrumentation_args(instr: dict) -> dict:
    if not isinstance(instr, dict):
        return {}
    result = {}

    b64_json_re = re.compile(r"^ey[A-Za-z0-9+/=]{50,}$")
    for method, entries in instr.items():
        filtered = []
        for entry in entries:
            args = entry.get("args", [])
            if not isinstance(args, list):
                continue
            keep_args = []
            for a in args:
                if not isinstance(a, str):
                    continue
                if b64_json_re.match(a):
                    continue
                if is_binary_data(a):
                    continue
                if not is_meaningful(a):
                    continue
                keep_args.append(a)
            ret = entry.get("ret")
            if not isinstance(ret, str) or is_binary_data(ret) or not is_meaningful(ret):
                ret = None
            if keep_args or ret:
                filtered.append({"args": keep_args or None, "ret": ret})
        if filtered:
            result[method] = filtered
    return result


def build_prompt(records: list) -> dict:
    combined = {"plaintext_info_list": [], "instrumentation_result": []}
    IGNORE_KEYS = {"tm", "time", "timestamp", "oauth_timestamp"}
    seen_pairs = set()

    for rec in records:
        pi = rec.get("plaintext_info", {})
        if isinstance(pi, dict):
            cleaned = {k: v for k, v in pi.items() if k not in IGNORE_KEYS}
            unique = {}
            for k, v in cleaned.items():
                if (k, str(v)) not in seen_pairs:
                    seen_pairs.add((k, str(v)))
                    unique[k] = v
            if unique:
                combined["plaintext_info_list"].append(unique)

        inst = rec.get("instrumentation_result", {})
        if isinstance(inst, dict):
            inst = filter_instrumentation_args(inst)
            for entries in inst.values():
                for entry in entries:
                    args = entry.get("args") or []
                    ret = entry.get("ret")
                    key = (tuple(str(a) for a in args), str(ret) if ret is not None else None)
                    if key in seen_pairs:
                        continue
                    seen_pairs.add(key)
                    combined["instrumentation_result"].append(entry)

    combined_json = json.dumps(combined, ensure_ascii=False, indent=4)

    prompt = f"""
    ## Role
    You are an expert in mobile application data security.

    ## Task
    Your task is to analyze the private data instances from given {{app runtime record}}. The record will be provided in JSON format, where *traffic_info* represents target app's plaintext traffic record at runtime, *instrumentation_result* represents target app's function execution record at runtime. Please determine if the given record contains any of the data instances listed in the {{privacy data types table}}. Output the results in JSON format with *detected_categories* as key and an array of privacy instances as value, do not output extra text.

    ## Chain-of-Thought
    First, conduct a thorough review of all privacy data types and instances listed in given table to ensure a comprehensive understanding. Second, use only the specified privacy instances; refrain from creating new ones. Third, infer privacy instances based on contextual features across different scenarios:

    - For data with distinctive features such as IP addresses and MAC addresses, as well as tracking identifiers with unique features, please infer them directly.  
    - **Q:** `{{"traffic_info": {{"addr": "192.168.137.238"}}}}`  
    - **Reasoning:** This record is a plaintext traffic record, and it contains a key "addr", which does not match any predefined privacy instances in the table. However, the value "192.168.137.238" conforms to the IP address pattern and is also listed in the provided table. Therefore, this record contains an IP Address instance.  
    - **A:** `{{"detected_categories": ["IP Address"]}}`

    - In cases where the key or value cannot be definitively inferred, the presence of either one can be considered indicative of a privacy instance.  
    - **Q:** `{{"traffic_info": {{"mt": "android 12"}}}}`  
    - **Reasoning:** This record is a plaintext traffic record and contains a key denoting an entry string, making its meaning unclear. However, the corresponding value is "android 12", which can be interpreted as an OS Version. Since OS Version is listed in the provided table, this record is determined to contain OS Version instance.  
    - **A:** `{{"detected_categories": ["OS Version"]}}`

    - When privacy instance appears in abbreviated or obfuscated form, its original meaning should be inferred based on contextual information or value patterns.  
    - **Q:** `{{"instrumentation_result": {{"b.c.enc": {{"args": ["{{\\"device.sz\\": \\"1080x2340\\"}}"], "ret": "E20BA7D32..."}}}}}}`  
    - **Reasoning:** This record is a function execution record. The executed function is "b.c.enc", and its argument is `[{{\\"device.sz\\": \\"1080x2340\\"}}]`. The return value is "E20BA7D32...", which appears to be meaningless. The argument contains a JSON-formatted string in which the key "device.sz" is likely an abbreviation of "device.size", and its value is "1080x2340", which can also be interpreted as a screen resolution. Since the screen resolution is listed as Resolution in the provided table, based on the contextual information, this record contains a Resolution instance.  
    - **A:** `{{"detected_categories": ["Resolution"]}}`

    - Finally, collect all detected privacy instances in an array, then format the output as a JSON object with the key *detected_categories*.

    ## Input
    1. Privacy data types table (Markdown list format): {privacy_table_md}
    2. App runtime records (JSON format): {combined_json}

    ## Output Format
    `{{"detected_categories": ["Privacy Instance1", "Privacy Instance2", ...]}}`

    ## Example
    - **Example1**  
    - Input: `{{"traffic_info": {{"device.ov": "12", "mc": "00:01:6C:06:A7:29"}}}}`  
    - Output:  
        "`{{"detected_categories": ["OS Version", "MAC Address"]}}`"

    - **Example2**  
    - Input:  
        "`{{"instrumentation_result": {{"com.data.AES128Encode": {{"args": ["{{\\"md\\": \\"Redmi_M2007J22C\\", \\"conn_type\\": \\"[wifi]\\"}}"], "ret": "99b7257581..."}}}}}}`  
    - Output:  
        "`{{"detected_categories": ["Device Model", "Network Type"]}}`"
    """
    return prompt


def analyze(records: list, logger) -> dict:
    def normalize(name: str) -> str:
        return re.sub(r"[^0-9a-z]", "", name.lower())

    prompt = build_prompt(records)

    max_retries = 5
    retry_delay = 5

    for attempt in range(1, max_retries + 1):
        try:
            resp = client.chat.completions.create(
                model="google/gemini-2.5-flash",
                messages=[{"role": "system", "content": "You are an expert in mobile application data security."}, {"role": "user", "content": prompt}],
                extra_body={"enable_thinking": False},
            )
            raw = resp.choices[0].message.content.strip()

            if "I cannot fulfill this request" in raw or "I cannot proceed" in raw:
                raise RuntimeError("Model rejected the request, triggering retry")

            # Try to parse JSON
            try:
                result = json.loads(raw)
            except json.JSONDecodeError:
                snippet = raw[raw.find("{") : raw.rfind("}") + 1]
                result = json.loads(snippet)

            detected = result.get("detected_categories", [])
            norm_map = {normalize(cat): cat for cat in PRIVACY_CATEGORIES}

            final_detected = []
            for cat in detected:
                key = normalize(cat)
                std = norm_map.get(key)
                if std and std not in final_detected:
                    final_detected.append(std)

            result = {"detected_categories": final_detected}

            logger.info("[llm_privacy_extractor] [llm_query_analyze] Parsed result after cleanup: ")
            logger.info(json.dumps(result, ensure_ascii=False, indent=4))
            return result

        except (json.JSONDecodeError, RuntimeError) as e:
            logger.error(f"[llm_privacy_extractor] [llm_query_analyze] Model output exception, retry {attempt}/{max_retries}, waiting {retry_delay} seconds... | Error: {e}")
            if attempt == max_retries:
                raise RuntimeError("Maximum retry attempts reached, program terminated") from e
            time.sleep(retry_delay)

        except RateLimitError as e:
            logger.error(f"[llm_privacy_extractor] [llm_query_analyze] Rate limit exceeded (RateLimitError), retry {attempt}/{max_retries}, waiting {retry_delay} seconds...")
            if attempt == max_retries:
                raise RuntimeError("Maximum retry attempts reached, program terminated") from e
            time.sleep(retry_delay)

        except Exception as e:
            logger.error(f"[llm_privacy_extractor] [llm_query_analyze] Model call failed (non-quota issue), retry {attempt}/{max_retries}, waiting {retry_delay} seconds... Error: {e}")
            if attempt == max_retries:
                logger.warning(f"[llm_privacy_extractor] [llm_query_analyze] Maximum retry attempts reached, pausing for manual intervention... | From error: {e}")
                input("Press Enter to continue after resolving the issue...")
            else:
                time.sleep(retry_delay)
        

def merge_results(meta, plain_res, instr_res):
    plain_cats = set(plain_res.get("detected_categories", []))
    instr_cats = set(instr_res.get("detected_categories", []))

    return {
        "package_name": meta["package_name"],
        "traffic_id": meta["traffic_id"],
        "url": meta["url"],
        "detected_categories": sorted(list(plain_cats | instr_cats)),
        "from_plaintext": sorted(list(plain_cats)),
        "from_instrumentation": sorted(list(instr_cats)),
    }


def process_single_entry(entry_data: dict, logger) -> dict:
    metadata = entry_data["metadata"]
    plaintext_data = entry_data["plaintext"]
    instrumentation_data = entry_data["instrumentation"]

    logger.info(f"[llm_privacy_extractor] [process_single_entry] Processing traffic_id: {metadata["traffic_id"]}")

    result_plain = {"detected_categories": []}
    if plaintext_data.get("plaintext_info"):
        result_plain = analyze([{"plaintext_info": plaintext_data["plaintext_info"]}], logger)

    result_instr = {"detected_categories": []}
    if instrumentation_data.get("instrumentation_result"):
        result_instr = analyze([{"instrumentation_result": instrumentation_data["instrumentation_result"]}], logger)

    merged = merge_results(metadata, result_plain, result_instr)

    return merged
