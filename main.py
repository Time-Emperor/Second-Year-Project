import logging
from cli import parse_cli_args
from scanner_runner import execute_audit_rules
from scoring import calculate_compliance_score
from reporter import export_html_report, export_json_output

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(name)s: %(message)s")
logger = logging.getLogger("AHHCS-CLI")


def main():
    args = parse_cli_args()
    results, duration = execute_audit_rules(args.rules, args.check)

    if not results:
        logger.warning("No audit results generated for rules='%s' check='%s'.", args.rules, args.check)

    score_data = calculate_compliance_score(results)
    score_data["execution_time_seconds"] = duration

    if args.json:
        export_json_output(results, score_data)
    elif args.export:
        export_html_report(results, score_data, args.export)
    else:
        print("\n--- AHHCS Audit Summary ---")
        print(f"Compliance Score: {score_data['score_percentage']}%")
        print(f"Passed Checks:    {score_data['passed_checks']} / {score_data['total_checks']}")
        print(f"Execution Time:   {duration:.4f}s")


if __name__ == "__main__":
    main()