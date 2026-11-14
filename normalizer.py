def format_audit_result(rule_id: str, category: str, severity: str, description: str, passed: bool, actual: str, expected: str, error: str = None) -> dict:
    """
    Standardizes output objects across disparate check categories (e.g., UFW vs nftables, SSH, files).
    """
    return {
        "rule_id": rule_id,
        "category": category,
        "severity": severity,
        "description": description,
        "passed": bool(passed),
        "actual": str(actual),
        "expected": str(expected),
        "error": error
    }