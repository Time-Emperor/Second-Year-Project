def evaluate_ssh_rule(config_path: str, rule: dict) -> dict:
    """
    Evaluates an SSH configuration rule against a target sshd_config file.
    Maintains strict read-only audit safety.
    """
    result = {
        "rule_id": rule.get("rule_id"),
        "description": rule.get("description"),
        "severity": rule.get("severity"),
        "parameter": rule.get("parameter"),
        "expected": rule.get("expected"),
        "actual": None,
        "passed": False,
        "error": None
    }
    
    target_param = rule.get("parameter", "").lower()
    expected_value = rule.get("expected", "").lower()
    
    try:
        if not os.path.exists(config_path):
            result["error"] = f"SSH config file not found at {config_path}"
            return result
            
        with open(config_path, 'r', encoding='utf-8') as f:
            for line in f:
                line = line.strip()
                # This skips comments and empty lines
                if not line or line.startswith('#'):
                    continue
                    
                parts = line.split()
                if len(parts) >= 2 and parts[0].lower() == target_param:
                    actual_value = parts[1].lower()
                    result["actual"] = actual_value
                    result["passed"] = (actual_value == expected_value)
                    break
            
            # If parameter wasn't explicitly found in the file
            if result["actual"] is None:
                result["actual"] = "not_configured"
                # Some defaults are implicitly 'no' or 'yes', but we flag as unconfigured/failed strict check
                result["passed"] = False
                
    except PermissionError:
        result["error"] = "Permission denied reading SSH configuration file."
    except Exception as e:
        result["error"] = str(e)
        
    return result