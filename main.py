import argparse
import sys
import os
# v17.1: Suprimir warnings de urllib3 globalmente
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# v17.4: Load .env file if it exists (before importing Orchestrator)
try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    # dotenv not installed, try manual loading
    env_file = os.path.join(os.path.dirname(__file__), '.env')
    if os.path.exists(env_file):
        with open(env_file, 'r') as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith('#') and '=' in line:
                    key, value = line.split('=', 1)
                    key = key.strip()
                    value = value.strip().strip('"').strip("'")
                    os.environ[key] = value

from audit_system.core.orchestrator import Orchestrator
from audit_system.reporting.generator import Reporter
from audit_system.core.exceptions import AuditError

def main():
    parser = argparse.ArgumentParser(description="Meowware v1.0 'Tulipán' - Professional Security Audit Platform")
    parser.add_argument("target", help="IP or Domain to audit")
    parser.add_argument("--json", action="store_true", help="Output full JSON to stdout")
    parser.add_argument("--debug", action="store_true", help="Enable verbose debug mode (shows AI prompts, tool outputs, etc.)")
    
    args = parser.parse_args()

    # Set global debug flag
    os.environ['DEBUG_MODE'] = '1' if args.debug else '0'
    
    if args.debug:
        print("[DEBUG] Debug mode enabled - Verbose output active", file=sys.stderr)
        print("[DEBUG] All AI prompts and tool outputs will be shown", file=sys.stderr)
        print("-" * 60, file=sys.stderr)

    print(f"[*] Starting Meowware audit for: {args.target}...", file=sys.stderr)
    print(f"[*] Initializing Meowware v1.0 'Tulipán' [Professional Security Audit Platform]...", file=sys.stderr)
    
    try:
        orchestrator = Orchestrator()
        report_data = orchestrator.run(args.target)
        
        if args.json:
            print(Reporter.generate_json(report_data))
        else:
            summary = Reporter.generate_summary(report_data)
            html_report = Reporter.generate_html(report_data)
            
            # Print colorful summary to stdout
            print(summary)
            
            # Save files
            try:
                import re
                clean_summary = re.sub(r'\033\[[0-9;]*m', '', summary)
                with open("report_summary.txt", "w") as f: f.write(clean_summary)
                with open("meowware_report.html", "w") as f: f.write(html_report)
                print(f"\n[✔] Reports saved: report_summary.txt, meowware_report.html", file=sys.stderr)
            except Exception as e:
                print(f"\n[✖] Failed to save reports: {e}", file=sys.stderr)
            
    except AuditError as e:
        print(f"[!] Error: {e}", file=sys.stderr)
        sys.exit(1)
    except Exception as e:
        print(f"[!] Unexpected Error: {e}", file=sys.stderr)
        if args.debug:
            import traceback
            traceback.print_exc()
        sys.exit(1)

if __name__ == "__main__":
    main()

