import time
import logging
import os

# Import modules using their correct filenames
from cli import parse_cli_args
from parser import load_rule_engine
from ssh_checker import evaluate_ssh_rule
from file_checker import check_file_permissions, check_suid_binary

# If you have a separate sysctl module, import it here, or handle it inline
try:
    from audit_module import check_sysctl_parameter
except ImportError:
    # Fallback placeholder if sysctl check is defined elsewhere
    def check_sysctl_parameter(param, expected):
        return {"parameter": param, "passed": False, "error": "Not implemented"}

from scoring import calculate_compliance_score
from reporter import export_html_report, export_json_output

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(name)s: %(message)s")
logger = logging.getLogger("AHHCS-Main")

def run_audit(rules_path: str, category_filter: str) -> tuple:
    """
    Orchestrates the end-to-end execution of all enabled audit rules.
    Measures performance to ensure execution stays under the 5-second threshold.
    """
    start_time = time.time()
    
    # 1. Load rules via JSON ingestion engine
    rules = load_rule_engine(rules_path)
    audit_results = []
    
    if not rules:
        logger.error("No rules loaded. Aborting audit.")
        return audit_results, 0.0

    logger.info(f"Starting audit execution (Filter category: {category_filter})...")

    for rule in rules:
        category = rule.get("category")
        
        # Apply category filters if specified via CLI
        if category_filter != "all" and category != category_filter:
            continue
            
        rule_id = rule.get("rule_id", "UNKNOWN")
        
        try:
            # Route to respective check module based on category
            if category == "ssh":
                config_path = "etc/ssh/sshd_config" if os.path.exists("etc/ssh/sshd_config") else "/etc/ssh/sshd_config"
                result = evaluate_ssh_rule(config_path, rule)
            elif category == "file_permissions":
                result = check_file_permissions(rule.get("path"), rule.get("expected_octal"), rule)
            elif category == "suid":
                result = check_suid_binary(rule.get("path"), rule)
            elif category == "sysctl":
                result = check_sysctl_parameter(rule.get("parameter"), rule.get("expected"))
            else:
                logger.warning(f"Unknown rule category '{category}' for rule {rule_id}")
                continue
                
            audit_results.append(result)
            
        except FileNotFoundError as e:
            logger.warning(f"Missing file target for rule {rule_id}: {e}")
            audit_results.append({
                "rule_id": rule_id,
                "category": category,
                "severity": rule.get("severity", "Medium"),
                "description": rule.get("description"),
                "passed": False,
                "actual": "missing",
                "expected": rule.get("expected") or rule.get("expected_octal"),
                "error": "Target file or path does not exist."
            })
        except PermissionError:
            logger.warning(f"Permission denied while executing rule {rule_id}. Handled gracefully.")
            audit_results.append({
                "rule_id": rule_id,
                "category": category,
                "severity": rule.get("severity", "Medium"),
                "description": rule.get("description"),
                "passed": False,
                "actual": "permission_denied",
                "expected": rule.get("expected") or rule.get("expected_octal"),
                "error": "Insufficient privileges to read target."
            })
        except Exception as e:
            logger.error(f"Unexpected error executing rule {rule_id}: {e}")
            
    elapsed_time = time.time() - start_time
    logger.info(f"Audit completed in {elapsed_time:.4f} seconds.")
    
    return audit_results, elapsed_time

def main():
    args = parse_cli_args()
    
    # Run the audit engine
    results, duration = run_audit(args.rules, args.check)
    
    # Calculate compliance score
    score_data = calculate_compliance_score(results)
    score_data["execution_time_seconds"] = round(duration, 4)
    
    # Handle exports based on CLI flags
    if args.json:
        export_json_output(results, score_data)
    elif args.export:
        export_html_report(results, score_data, args.export)
    else:
        # Default terminal summary output
        print(f"\n--- AHHCS Audit Summary ---")
        print(f"Total Compliance Score: {score_data['score_percentage']}%")
        print(f"Execution Time: {duration:.4f}s")
        print(f"Passed/Checked: {sum(1 for r in results if r.get('passed'))}/{len(results)}")

if __name__ == "__main__":
    main()