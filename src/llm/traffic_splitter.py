import json
from typing import Dict, Tuple, Any, Generator
from pathlib import Path


def split_traffic_entry(traffic_entry: Dict[str, Any], package_name: str = "") -> Tuple[Dict[str, Any], Dict[str, Any]]:
    plaintext_data = {
        "package_name": package_name,
        "traffic_id": traffic_entry.get("traffic_id", ""),
        "url": traffic_entry.get("url", ""),
        "plaintext_info": traffic_entry.get("plaintext_info", {}),
    }

    instrumentation_data = {
        "package_name": package_name,
        "traffic_id": traffic_entry.get("traffic_id", ""),
        "url": traffic_entry.get("url", ""),
        "instrumentation_result": traffic_entry.get("instrumentation_result", {}),
    }

    return plaintext_data, instrumentation_data


def extract_package_name(filename: str) -> str:
    return filename.split("-")[0]


def process_traffic_entries(input_dir: str, logger) -> Generator[list, None, None]:
    input_path = Path(input_dir)
    if not input_path.exists():
        logger.warning(f"[llm_privacy_extractor] [process_traffic_entries] Input directory {input_dir} does not exist")
        return

    traffic_files = list(input_path.glob("*-traffic_entry_map.json"))
    if not traffic_files:
        logger.warning(f"[llm_privacy_extractor] [process_traffic_entries] No traffic_entry_map files found")
        return

    logger.info(f"[llm_privacy_extractor] [process_traffic_entries] Found {len(traffic_files)} files to process")

    for file_path in traffic_files:
        try:
            logger.info(f"[llm_privacy_extractor] [process_traffic_entries] Processing file: {file_path.name}")
            
            with open(file_path, "r", encoding="utf-8") as f:
                data = json.load(f)
                package_name = extract_package_name(file_path.stem)

                processed_data = []
                
                if isinstance(data, list):
                    for entry in data:
                        entry["package_name"] = package_name
                        plaintext_data, instrumentation_data = split_traffic_entry(entry, package_name)
                        processed_data.append({
                            "metadata": {
                                "package_name": package_name, 
                                "traffic_id": entry.get("traffic_id", ""), 
                                "url": entry.get("url", "")
                            },
                            "plaintext": plaintext_data,
                            "instrumentation": instrumentation_data,
                        })
                else:
                    data["package_name"] = package_name
                    plaintext_data, instrumentation_data = split_traffic_entry(data, package_name)
                    processed_data.append({
                        "metadata": {
                            "package_name": package_name, 
                            "traffic_id": data.get("traffic_id", ""), 
                            "url": data.get("url", "")
                        },
                        "plaintext": plaintext_data,
                        "instrumentation": instrumentation_data,
                    })

                logger.info(f"[llm_privacy_extractor] [process_traffic_entries] Processed {len(processed_data)} entries from {file_path.name}")
                yield processed_data

        except Exception as e:
            logger.error(f"[llm_privacy_extractor] [process_traffic_entries] Failed to process file {file_path.name}: {e}")
            continue
