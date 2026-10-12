import json
import logging
import os

logger = logging.getLogger("HostHardeningScanner")

def load_rule_engine(json_file_path: str) -> list:
    """
    Loads and parses rule definitions from a JSON file.
    Ensures safe read-only ingestion without modifying system state.
    """
    if not os.path.exists(json_file_path):
        logger.error(f"Rule file not found at: {json_file_path}")
        return []

    try:
        with open(json_file_path, 'r', encoding='utf-8') as f:
            rules = json.load(f)
            logger.info(f"Successfully loaded {len(rules)} rules from {json_file_path}")
            return rules
    except json.JSONDecodeError as e:
        logger.error(f"Invalid JSON format in rule file: {e}")
        return []
    except Exception as e:
        logger.error(f"Unexpected error loading rules: {e}")
        return []