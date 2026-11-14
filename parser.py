import json
import logging

logger = logging.getLogger("AHHCS-Parser")

def load_rule_engine(rules_path: str) -> list:
    """
    Safely loads and validates hardening rules from a target JSON configuration file.
    """
    try:
        with open(rules_path, 'r', encoding='utf-8') as f:
            rules = json.load(f)
            
        if not isinstance(rules, list):
            logger.error("Invalid rule format: Root element must be a JSON list.")
            return []
            
        valid_rules = []
        for rule in rules:
            if not isinstance(rule, dict) or "rule_id" not in rule or "category" not in rule:
                logger.warning(f"Skipping malformed rule entry: {rule}")
                continue
            valid_rules.append(rule)
            
        logger.info(f"HostHardeningScanner: Successfully loaded {len(valid_rules)} rules from {rules_path}")
        return valid_rules
        
    except FileNotFoundError:
        logger.error(f"Rule file not found at path: {rules_path}")
        return []
    except json.JSONDecodeError as e:
        logger.error(f"JSON decoding error in rules file: {e}")
        return []
    except Exception as e:
        logger.error(f"Unexpected error loading rules: {e}")
        return []