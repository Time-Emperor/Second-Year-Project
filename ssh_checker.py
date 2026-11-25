import os
from normalizer import format_audit_result


def evaluate_ssh_rule(config_path: str, rule: dict) -> dict:
    """Evaluates a single SSH directive against an sshd_config file."""
    rule = rule or {}
    rule_id = rule.get("rule_id", "SSH-00")
    severity = rule.get("severity", "Medium")
    description = rule.get("description", "Evaluate SSH configuration directive")
    target_param = (rule.get("parameter") or "").strip().lower()
    expected_value = (rule.get("expected") or "").strip().lower()

    if not config_path or not os.path.exists(config_path):
        return format_audit_result(
            rule_id=rule_id,
            category="ssh",
            severity=severity,
            description=description,
            passed=False,
            actual="missing_config",
            expected=expected_value,
            error=f"SSH config file not found at {config_path}"
        )

    try:
        found_value = None
        with open(config_path, "r", encoding="utf-8") as f:
            for raw_line in f:
                line = raw_line.strip()
                if not line or line.startswith("#"):
                    continue
                parts = line.split()
                if len(parts) >= 2 and parts[0].lower() == target_param:
                    found_value = parts[1].lower()
                    break

        if found_value is None:
            return format_audit_result(
                rule_id=rule_id,
                category="ssh",
                severity=severity,
                description=description,
                passed=False,
                actual="not_configured",
                expected=expected_value
            )

        return format_audit_result(
            rule_id=rule_id,
            category="ssh",
            severity=severity,
            description=description,
            passed=(found_value == expected_value),
            actual=found_value,
            expected=expected_value
        )
    except PermissionError:
        return format_audit_result(
            rule_id=rule_id,
            category="ssh",
            severity=severity,
            description=description,
            passed=False,
            actual="permission_denied",
            expected=expected_value,
            error="Permission denied reading SSH configuration file."
        )
    except OSError as exc:
        return format_audit_result(
            rule_id=rule_id,
            category="ssh",
            severity=severity,
            description=description,
            passed=False,
            actual="error",
            expected=expected_value,
            error=str(exc)
        )