def calculate_compliance_score(audit_results: list) -> dict:
    """
    Calculates the aggregate compliance score percentage based on audit results.
    """
    total_checks = len(audit_results)
    if total_checks == 0:
        return {
            "total_checks": 0,
            "passed_checks": 0,
            "failed_checks": 0,
            "score_percentage": 0.0
        }
        
    passed_checks = sum(1 for r in audit_results if r.get("passed", False))
    failed_checks = total_checks - passed_checks
    
    score_percentage = round((passed_checks / total_checks) * 100, 2)
    
    return {
        "total_checks": total_checks,
        "passed_checks": passed_checks,
        "failed_checks": failed_checks,
        "score_percentage": score_percentage
    }