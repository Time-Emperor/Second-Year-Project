import os
import stat

def check_file_permissions(path: str, expected_octal: str, rule: dict = None) -> dict:
    """
    Checks if a file's octal permissions match the expected compliance standard.
    """
    rule = rule or {}
    result = {
        "rule_id": rule.get("rule_id", "FILE-01"),
        "category": rule.get("category", "file_permissions"),
        "severity": rule.get("severity", "High"),
        "description": rule.get("description", "Ensure correct file permissions"),
        "expected": expected_octal,
        "actual": None,
        "passed": False,
        "error": None
    }
    
    try:
        if not os.path.exists(path):
            result["error"] = "File not found"
            return result
            
        file_stat = os.stat(path)
        actual_octal = oct(file_stat.st_mode)[-4:]
        result["actual"] = actual_octal
        result["passed"] = (actual_octal == expected_octal)
        
    except PermissionError:
        result["error"] = "Permission denied"
    except Exception as e:
        result["error"] = str(e)
        
    return result

def check_suid_binary(path: str, rule: dict = None) -> dict:
    """
    Checks if a binary has SUID permissions set.
    """
    rule = rule or {}
    result = {
        "rule_id": rule.get("rule_id", "SUID-01"),
        "category": rule.get("category", "suid"),
        "severity": rule.get("severity", "Medium"),
        "description": rule.get("description", "Check SUID bit on binary"),
        "expected": "no_suid",
        "actual": None,
        "passed": False,
        "error": None
    }
    
    try:
        if not os.path.exists(path):
            result["error"] = "File not found"
            return result
            
        file_stat = os.stat(path)
        has_suid = bool(file_stat.st_mode & stat.S_ISUID)
        result["actual"] = "suid_set" if has_suid else "secure"
        result["passed"] = not has_suid
        
    except PermissionError:
        result["error"] = "Permission denied"
    except Exception as e:
        result["error"] = str(e)
        
    return result