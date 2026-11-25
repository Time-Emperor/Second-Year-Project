import os
import logging
from normalizer import format_audit_result

logger = logging.getLogger("AHHCS-Sysctl")


def check_sysctl_parameter(parameter_name: str, expected_value: str, rule: dict = None) -> dict:
    """Reads a kernel sysctl parameter from /proc/sys/ in read-only mode."""
    rule = rule or {}
    rule_id = rule.get("rule_id", "SYSCTL-00")
    severity = rule.get("severity", "Medium")
    description = rule.get("description", f"Check sysctl parameter {parameter_name}")

    sysctl_path = os.path.join("/proc/sys", *parameter_name.split("."))

    try:
        if not os.path.exists(sysctl_path):
            return format_audit_result(
                rule_id=rule_id,
                category="sysctl",
                severity=severity,
                description=description,
                passed=False,
                actual="missing",
                expected=str(expected_value),
                error=f"Parameter path not found: {sysctl_path}"
            )

        with open(sysctl_path, "r", encoding="utf-8") as f:
            actual_value = f.read().strip()

        passed = actual_value == str(expected_value)
        return format_audit_result(
            rule_id=rule_id,
            category="sysctl",
            severity=severity,
            description=description,
            passed=passed,
            actual=actual_value,
            expected=str(expected_value)
        )
    except PermissionError:
        logger.warning("Permission denied reading sysctl %s", parameter_name)
        return format_audit_result(
            rule_id=rule_id,
            category="sysctl",
            severity=severity,
            description=description,
            passed=False,
            actual="permission_denied",
            expected=str(expected_value),
            error="Permission denied reading sysctl parameter."
        )
    except OSError as exc:
        logger.error("Failed reading sysctl %s: %s", parameter_name, exc)
        return format_audit_result(
            rule_id=rule_id,
            category="sysctl",
            severity=severity,
            description=description,
            passed=False,
            actual="error",
            expected=str(expected_value),
            error=str(exc)
        )