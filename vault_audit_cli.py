import argparse
import sys
import os
from vault_audit_core import VaultAuditEngine

def main():
    parser = argparse.ArgumentParser(description="HashiCorp Vault Policy Auditor (CLI)")
    parser.add_argument("folder", help="Path to the folder containing policy files")
    parser.add_argument("--html", help="Path to export HTML report", default=None)
    parser.add_argument("--excel", help="Path to export Excel report", default=None)
    
    # NEW ARGUMENT
    parser.add_argument("--scan-all", action="store_true", help="Scan ALL files (e.g. .hcl, .txt). Default behavior scans only files with NO extension.")
    
    parser.add_argument("--fail-on-critical", action="store_true", help="Exit with error code 1 if Critical risks found")
    
    args = parser.parse_args()
    
    # Path Normalization
    abs_folder_path = os.path.abspath(args.folder)
    
    print(f"[*] Scanning directory: {abs_folder_path}")
    if args.scan_all:
        print("[*] Mode: Scanning ALL files (including extensions)")
    else:
        print("[*] Mode: Scanning only files with NO extension (Default)")
    
    if not os.path.exists(abs_folder_path):
        print(f"[!] Error: Directory not found: {abs_folder_path}")
        sys.exit(1)

    # Initialize Engine
    engine = VaultAuditEngine()
    try:
        # Pass the logic: if scan_all is True, then ignore_extensions is False
        engine.scan_folder(abs_folder_path, ignore_extensions=not args.scan_all)
        engine.analyze()
        
        # Summary
        print(f"[*] Analysis Complete.")
        print(f"    - Policies Scanned: {len(engine.policies_data)}")
        print(f"    - Critical Risks:   {engine.stats['CRITICAL']}")
        print(f"    - High Risks:       {engine.stats['HIGH']}")
        print(f"    - Medium Risks:     {engine.stats['MEDIUM']}")
        
        # Exports
        if args.html:
            html_path = os.path.abspath(args.html)
            engine.export_html(html_path)
            print(f"[*] HTML Report saved to: {html_path}")
            
        if args.excel:
            excel_path = os.path.abspath(args.excel)
            engine.export_excel(excel_path)
            print(f"[*] Excel Report saved to: {excel_path}")
            
        # CI/CD Failure
        if args.fail_on_critical and engine.stats['CRITICAL'] > 0:
            print("[!] CRITICAL RISKS DETECTED - Failing Pipeline.")
            sys.exit(1)
            
    except Exception as e:
        print(f"[!] An unexpected error occurred: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
