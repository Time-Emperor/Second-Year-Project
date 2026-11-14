import argparse

def parse_cli_args():
    """
    Parses command-line arguments for the AHHCS audit engine.
    """
    parser = argparse.ArgumentParser(description="Automated Host Hardening and Compliance Scanner (AHHCS)")
    
    parser.add_argument(
        "--rules", 
        type=str, 
        default="rules.json", 
        help="Path to the JSON rules configuration file (default: rules.json)"
    )
    
    parser.add_argument(
        "--check", 
        type=str, 
        default="all", 
        help="Filter audit execution by category (ssh, file_permissions, suid, sysctl, or all)"
    )
    
    parser.add_argument(
        "--export", 
        type=str, 
        default=None, 
        help="Export executive HTML compliance report to the specified file path"
    )
    
    parser.add_argument(
        "--json", 
        action="store_true", 
        help="Output raw structured audit results in JSON format to stdout"
    )
    
    return parser.parse_args()