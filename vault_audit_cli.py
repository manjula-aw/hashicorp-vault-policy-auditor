import argparse
import sys
import json
from vault_audit_core import VaultAuditEngine

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Vault Policy Auditor CLI")
    parser.add_argument("input_dir", help="Path to policy folder")
    parser.add_argument("--html", help="Path for HTML report")
    parser.add_argument("--excel", help="Path for Excel report")
    parser.add_argument("--json", action="store_true", help="Print JSON to stdout")
    parser.add_argument("--fail-on-critical", action="store_true", help="Exit code 1 if CRITICAL risks found")
    
    args = parser.parse_args()

    # Initialize and Run Engine
    engine = VaultAuditEngine()
    try:
        engine.scan_folder(args.input_dir, ignore_extensions=True)
        engine.analyze()
    except Exception as e:
        print(f"Error: {e}")
        sys.exit(1)

    # Outputs
    if args.json:
        print(json.dumps(engine.audit_issues, indent=2))
    
    if args.html:
        engine.export_html(args.html)
        print(f"HTML Report: {args.html}")
        
    if args.excel:
        engine.export_excel(args.excel)
        print(f"Excel Report: {args.excel}")

    # CI/CD Logic
    if args.fail_on_critical and engine.stats["CRITICAL"] > 0:
        print(f"\n[FAILURE] Found {engine.stats['CRITICAL']} CRITICAL issues.")
        sys.exit(1)
    
    print("\n[SUCCESS] Audit complete.")
