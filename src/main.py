import argparse
import json
import sys

from engine import CADiffEngine

def generate_html_report(alerts, old_name, new_name):
    """Generates a standalone, CSS-styled HTML assessment report."""
    status_class = "pass" if not alerts else "fail"
    status_text = "PASSED (Secure)" if not alerts else "FAILED (Regressions Detected)"
    
    alert_rows = ""
    if alerts:
        for alert in alerts:
            severity = "HIGH" if "CRITICAL" in alert or "RETRACTION" in alert else "MED"
            alert_rows += f"""
            <tr>
                <td class="severity-{severity.lower()}">{severity}</td>
                <td>{alert}</td>
            </tr>
            """
    else:
        alert_rows = """
        <tr>
            <td colspan="2" style="text-align: center; color: #10b981; font-weight: bold; padding: 20px;">
                ✅ No security regressions or policy configuration drifts detected.
            </td>
        </tr>
        """

    html_content = f"""<!DOCTYPE html>
<html>
<head>
    <title>Entra CA Gatekeeper Report</title>
    <style>
        body {{ font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; background-color: #f3f4f6; color: #1f2937; margin: 40px; }}
        .container {{ max-width: 900px; background: white; padding: 30px; border-radius: 8px; box-shadow: 0 4px 6px rgba(0,0,0,0.05); }}
        h1 {{ margin-top: 0; color: #111827; border-bottom: 2px solid #e5e7eb; padding-bottom: 10px; }}
        .meta {{ display: flex; gap: 40px; margin-bottom: 20px; font-size: 14px; color: #4b5563; }}
        .status {{ padding: 10px 15px; border-radius: 4px; font-weight: bold; display: inline-block; margin-bottom: 20px; }}
        .status.pass {{ background-color: #d1fae5; color: #065f46; }}
        .status.fail {{ background-color: #fee2e2; color: #991b1b; }}
        table {{ width: 100%; border-collapse: collapse; margin-top: 10px; }}
        th, td {{ padding: 12px; text-align: left; border-bottom: 1px solid #e5e7eb; }}
        th {{ background-color: #f9fafb; color: #374151; font-weight: 600; }}
        .severity-high {{ color: #dc2626; font-weight: bold; }}
        .severity-med {{ color: #d97706; font-weight: bold; }}
    </style>
</head>
<body>
    <div class="container">
        <h1>🛡️ Entra ID Conditional Access Gatekeeper Report</h1>
        <div class="meta">
            <div><strong>Baseline File (Prod):</strong> {old_name}</div>
            <div><strong>Proposed File (Dev):</strong> {new_name}</div>
        </div>
        <div class="status {status_class}">
            Evaluation Status: {status_text}
        </div>
        <table>
            <thead>
                <tr>
                    <th style="width: 15%;">Severity</th>
                    <th>Technical Finding Summary</th>
                </tr>
            </thead>
            <tbody>
                {alert_rows}
            </tbody>
        </table>
    </div>
</body>
</html>
"""
    with open("ca_gatekeeper_report.html", "w") as f:
        f.write(html_content)

def main():
    parser = argparse.ArgumentParser(
        description="Entra ID Conditional Access Semantic Diff Gatekeeper"
    )
    parser.add_argument("--old", required=True, help="Path to baseline CA policy JSON")
    parser.add_argument("--new", required=True, help="Path to proposed CA policy JSON")
    
    args = parser.parse_args()
    
    try:
        with open(args.old, "r") as f:
            old_data = json.load(f)
        with open(args.new, "r") as f:
            new_data = json.load(f)
    except FileNotFoundError as e:
        print(f"Error: File not found - {e.filename}")
        sys.exit(1)
    except json.JSONDecodeError:
        print("Error: Invalid JSON format.")
        sys.exit(1)

    print("🛡️ Evaluating Entra ID Conditional Access Policy Changes...")
    alerts = CADiffEngine.evaluate(old_data, new_data)
    
    # Generate the physical HTML report file on disk
    generate_html_report(alerts, args.old, args.new)
    print("📋 HTML Report generated successfully: ca_gatekeeper_report.html")
    
    if not alerts:
        print("✅ SUCCESS: No regressions detected.")
        sys.exit(0)
        
    print(f"❌ RISK ALERT FAILURE: Found {len(alerts)} violations.")
    sys.exit(1)

if __name__ == "__main__":
    main()
