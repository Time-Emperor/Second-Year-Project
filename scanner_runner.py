import os
import time
from parser import load_rule_engine
from ssh_checker import evaluate_ssh_rule
from file_checker import check_file_permissions, check_suid_binary
from audit_module import check_sysctl_parameter
from normalizer import format_audit_result


def resolve_sshd_config_path() -> str:
    if os.path.exists("/etc/ssh/sshd_config"):
        return "/etc/ssh/sshd_config"
    return "etc/ssh/sshd_config"


def execute_audit_rules(rules_path: str = "rules.json", category_filter: str = "all") -> tuple[list, float]:
    start_time = time.perf_counter()
    rules = load_rule_engine(rules_path)
    results = []
    sshd_path = resolve_sshd_config_path()

    for rule in rules:
        category = rule.get("category")
        if category_filter != "all" and category != category_filter:
            continue

        rule_id = rule.get("rule_id", "UNKNOWN")
        severity = rule.get("severity", "Medium")
        description = rule.get("description", rule_id)

        try:
            if category == "ssh":
                result = evaluate_ssh_rule(sshd_path, rule)
            elif category == "file_permissions":
                result = check_file_permissions(rule.get("path"), rule.get("expected_octal"), rule)
            elif category == "suid":
                result = check_suid_binary(rule.get("path"), rule)
            elif category == "sysctl":
                result = check_sysctl_parameter(rule.get("parameter"), rule.get("expected"), rule)
            else:
                continue

            results.append(result)
        except Exception as exc:
            results.append(
                format_audit_result(
                    rule_id=rule_id,
                    category=category or "unknown",
                    severity=severity,
                    description=description,
                    passed=False,
                    actual="error",
                    expected=str(rule.get("expected") or rule.get("expected_octal") or "no_suid"),
                    error=str(exc)
                )
            )

    elapsed = round(time.perf_counter() - start_time, 4)
    return results, elapsed