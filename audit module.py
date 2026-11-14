import os
import logging

logger = logging.getLogger("HostHardeningScanner")

def check_sysctl_parameter(parameter_name: str, expected_value: str) -> dict:
    """
    Audits a live kernel sysctl parameter by reading from /proc/sys/.
    Converts dotted notation (e.g., net.ipv4.ip_forward) to filesystem paths.
    Maintains strict read-only audit safety.
    """
    result = {
        "parameter": parameter_name,
        "expected": str(expected_value),
        "actual": None,
        "passed": False,
        "error": None
    }
    
    # Convert dotted sysctl notation to /proc/sys path
    # e.g., net.ipv4.ip_forward -> /proc/sys/net/ipv4/ip_forward
    file_path = os.path.join("/proc/sys", *parameter_name.split('.'))
    
    try:
        if not os.path.exists(file_path):
            result["error"] = f"Sysctl parameter path not found: {file_path}"
            return result
            
        with open(file_path, 'r', encoding='utf-8') as f:
            actual_value = f.read().strip()
            result["actual"] = actual_value
            result["passed"] = (actual_value == str(expected_value))
            
    except PermissionError:
        result["error"] = "Permission denied reading sysctl parameter."
        logger.warning(f"Permission denied for sysctl parameter {parameter_name}")
    except Exception as e:
        result["error"] = str(e)
        logger.error(f"Error reading sysctl {parameter_name}: {e}")
        
    return result