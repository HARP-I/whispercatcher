import sys
import argparse
import json
from pathlib import Path
from .traffic_splitter import process_traffic_entries
from .category_name_mapping import map_categories
from .llm_query import process_single_entry


def check_input_files(runtime_record_dir, logger):
    input_path = Path(runtime_record_dir)
    if not input_path.exists():
        logger.error(f"[llm_privacy_extractor] Input directory does not exist: {runtime_record_dir}")
        return False
    traffic_files = list(input_path.glob("*-traffic_entry_map.json"))
    if not traffic_files:
        logger.warning(f"No traffic_entry_map files found")
        return False
    logger.info(f"Found {len(traffic_files)} files")
    return True


def save_single_result(result, output_path, logger):
    if result.get("error"):
        return

    package_name = result.get("package_name", "unknown")
    traffic_id = result.get("traffic_id", "unknown")
    filename = f"{package_name}-{traffic_id}-privacy_analysis.json"
    file_path = output_path / filename

    with open(file_path, "w", encoding="utf-8") as f:
        json.dump(result, f, ensure_ascii=False, indent=4)

    logger.info(f"[llm_privacy_extractor] [save_single_result] Saved: {filename}")


def privacy_analyzer(runtime_record_dir, llm_privacy_extraction_output_dir, logger):
    logger.info("[llm_privacy_extractor] Starting analysis...")
    if not check_input_files(runtime_record_dir, logger):
        return False

    output_path = Path(llm_privacy_extraction_output_dir)
    total_processed = 0

    for file_entries in process_traffic_entries(runtime_record_dir, logger):
        logger.info(f"[llm_privacy_extractor] Processing file with {len(file_entries)} entries")
        
        for i, entry_data in enumerate(file_entries, 1):
            total_processed += 1
            logger.info(f"[llm_privacy_extractor] Processing entry {i}/{len(file_entries)} (total: {total_processed})")
            
            try:
                result = process_single_entry(entry_data, logger)

                for key in ["detected_categories", "from_plaintext", "from_instrumentation"]:
                    if key in result:
                        result[key] = map_categories(result[key])

                save_single_result(result, output_path, logger)

            except Exception as e:
                logger.error(f"[llm_privacy_extractor] Processing failed: {e}")
                metadata = entry_data["metadata"]
                error_result = {
                    "package_name": metadata["package_name"],
                    "traffic_id": metadata["traffic_id"],
                    "url": metadata["url"],
                    "detected_categories": [],
                    "from_plaintext": [],
                    "from_instrumentation": [],
                    "error": str(e),
                }
                save_single_result(error_result, output_path, logger)

    logger.info(f"[llm_privacy_extractor] Analysis completed. Total entries processed: {total_processed}")
    return True
