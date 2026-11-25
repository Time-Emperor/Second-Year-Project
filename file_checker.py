import os
import stat
from normalizer import format_audit_result


def check_file_permissions(path: str, expected_octal: str, rule: dict = None) -> dict:
    """Compares a file or directory's 4-digit octal mode against expected_octal."""
    rule = rule or {}
    rule_id = rule.get("rule_id", "FILE-00")
    severity = rule.get("severity", "High")
    description = rule.get("description", f"Check permissions on {path}")

    try:
        if not path or not os.path.exists(path):
            return format_audit_result(
                rule_id=rule_id,
                category="file_permissions",
                severity=severity,
                description=description,
                passed=False,
                actual="missing",
                expected=str(expected_octal),
                error="Target path does not exist."
            )

        mode = os.stat(path).st_mode
        actual_octal = oct(stat.S_IMODE(mode))[2:].zfill(4)
        expected_norm = str(expected_octal).zfill(4)
        passed = actual_octal == expected_norm

        return format_audit_result(
            rule_id=rule_id,
            category="file_permissions",
            severity=severity,
            description=description,
            passed=passed,
            actual=actual_octal,
            expected=expected_norm
        )
    except PermissionError:
        return format_audit_result(
            rule_id=rule_id,
            category="file_permissions",
            severity=severity,
            description=description,
            passed=False,
            actual="permission_denied",
            expected=str(expected_octal),
            error="Permission denied reading file metadata."
        )
    except OSError as exc:
        return format_audit_result(
            rule_id=rule_id,
            category="file_permissions",
            severity=severity,
            description=description,
            passed=False,
            actual="error",
            expected=str(expected_octal),
            error=str(exc)
        )


def check_suid_binary(path: str, rule: dict = None) -> dict:
    """Checks whether the SUID bit is set on a target binary."""
    rule = rule or {}
    rule_id = rule.get("rule_id", "SUID-00")
    severity = rule.get("severity", "Medium")
    description = rule.get("description", f"Check SUID bit on {path}")

    try:
        if not path or not os.path.exists(path):
            return format_audit_result(
                rule_id=rule_id,
                category="suid",
                severity=severity,
                description=description,
                passed=False,
                actual="missing",
                expected="no_suid",
                error="Target binary does not exist."
            )

        mode = os.stat(path).st_mode
        has_suid = bool(mode & stat.S_ISUID)
        return format_audit_result(
            rule_id=rule_id,
            category="suid",
            severity=severity,
            description=description,
            passed=not has_suid,
            actual="suid_set" if has_suid else "no_suid",
            expected="no_suid"
        )
    except PermissionError:
        return format_audit_result(
            rule_id=rule_id,
            category="suid",
            severity=severity,
            description=description,
            passed=False,
            actual="permission_denied",
            expected="no_suid",
            error="Permission denied inspecting binary."
        )
    except OSError as exc:
        return format_audit_result(
            rule_id=rule_id,
            category="suid",
            severity=severity,
            description=description,
            passed=False,
            actual="error",
            expected="no_suid",
            error=str(exc)
        )