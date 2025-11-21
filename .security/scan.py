#!/usr/bin/env python
import time
import os
import sys
import yaml
import json
import re
import html
from datetime import datetime
from dotenv import load_dotenv
from zapv2 import ZAPv2

# Add .security directory to Python path so imports work when run from project root
script_dir = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, script_dir)

from alert_processor import sort_and_save_alerts, count_alerts, get_alert_summaries_and_final_summary, load_alerts
from github import post_pr_comment
from alert_diff import alert_diff
# Load environment variables
load_dotenv()

# Load scan config
CONFIG_PATH = ".security/config.yaml"
if os.path.exists(CONFIG_PATH):
    with open(CONFIG_PATH, "r") as config_file:
        config = yaml.safe_load(config_file)
else:
    raise FileNotFoundError("Missing .security/config.yaml file in project directory.")

scans_config = config.get("scans", {})
run_spider = scans_config.get("spider", True)
run_ajax_spider = scans_config.get("ajax_spider", False)
ajax_spider_timeout = scans_config.get("ajax_spider_timeout", 120)  # default 120 seconds
run_passive = scans_config.get("passive", True)
run_active = scans_config.get("active", False)

# Show selected scans
print(f"Selected scans: 🕷️ Spider: {run_spider} | ⚡ AJAX Spider: {run_ajax_spider} | 🧠 Passive: {run_passive} | 💥 Active: {run_active}")

# Basic validation: at least one scan must be selected
if not (run_spider or run_ajax_spider or run_passive or run_active):
    raise ValueError("❌ No scans selected! Please enable at least one scan type in .security/config.yaml.")


def format_risk_badge(risk):
    """Format risk level as a colored badge."""
    risk_lower = risk.lower() if risk else "unknown"
    colors = {
        "high": "#dc3545",
        "medium": "#ffc107",
        "low": "#28a745",
        "informational": "#17a2b8"
    }
    color = colors.get(risk_lower, "#6c757d")
    return f'<span style="background-color: {color}; color: white; padding: 4px 8px; border-radius: 4px; font-weight: bold; font-size: 0.85em;">{risk.upper() if risk else "UNKNOWN"}</span>'

def format_summary_text(text):
    """Convert markdown-like text to HTML with proper escaping."""
    if not text:
        return ""
    # Escape HTML first
    text = html.escape(text)
    # Convert markdown headers
    text = re.sub(r'^### (.*)$', r'<h3>\1</h3>', text, flags=re.MULTILINE)
    text = re.sub(r'^## (.*)$', r'<h2>\1</h2>', text, flags=re.MULTILINE)
    text = re.sub(r'\*\*(.*?)\*\*', r'<strong>\1</strong>', text)
    # Convert line breaks
    text = text.replace('\n', '<br>')
    return text

def generate_html_report(new_alerts_with_summaries, resolved_alerts_with_summaries, common_alerts_with_summaries,
                         new_summaries, resolved_summaries, common_summaries,
                         new_final_summary, resolved_final_summary, common_final_summary,
                         new_count, resolved_count, common_count):
    """Generate a visually appealing HTML security report."""
    
    # Use the alert data directly (summaries are already in the alert objects)
    new_alerts_parsed = new_alerts_with_summaries if new_alerts_with_summaries else []
    resolved_alerts_parsed = resolved_alerts_with_summaries if resolved_alerts_with_summaries else []
    common_alerts_parsed = common_alerts_with_summaries if common_alerts_with_summaries else []
    
    html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Security Scan Report</title>
    <style>
        * {{
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }}
        body {{
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, Cantarell, sans-serif;
            line-height: 1.6;
            color: #333;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            padding: 20px;
            min-height: 100vh;
        }}
        .container {{
            max-width: 1200px;
            margin: 0 auto;
            background: white;
            border-radius: 12px;
            box-shadow: 0 10px 40px rgba(0,0,0,0.2);
            overflow: hidden;
        }}
        .header {{
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 30px;
            text-align: center;
        }}
        .header h1 {{
            font-size: 2.5em;
            margin-bottom: 10px;
        }}
        .header .timestamp {{
            opacity: 0.9;
            font-size: 0.9em;
        }}
        .stats {{
            display: flex;
            justify-content: center;
            gap: 20px;
            padding: 30px;
            background: #f8f9fa;
            flex-wrap: wrap;
        }}
        .stat-card {{
            background: white;
            padding: 20px 30px;
            border-radius: 8px;
            box-shadow: 0 2px 8px rgba(0,0,0,0.1);
            text-align: center;
            min-width: 150px;
        }}
        .stat-card.new {{
            border-left: 4px solid #dc3545;
        }}
        .stat-card.resolved {{
            border-left: 4px solid #28a745;
        }}
        .stat-card.common {{
            border-left: 4px solid #ffc107;
        }}
        .stat-number {{
            font-size: 2.5em;
            font-weight: bold;
            margin-bottom: 5px;
        }}
        .stat-label {{
            color: #666;
            font-size: 0.9em;
        }}
        .section {{
            margin: 30px;
            padding: 25px;
            background: #f8f9fa;
            border-radius: 8px;
            border-left: 4px solid;
        }}
        .section.new {{
            border-left-color: #dc3545;
        }}
        .section.resolved {{
            border-left-color: #28a745;
        }}
        .section.common {{
            border-left-color: #ffc107;
        }}
        .section h2 {{
            margin-bottom: 20px;
            font-size: 1.8em;
            display: flex;
            align-items: center;
            gap: 10px;
        }}
        .alert-card {{
            background: white;
            margin: 15px 0;
            padding: 20px;
            border-radius: 8px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
            border-left: 4px solid #667eea;
        }}
        .alert-header {{
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 15px;
            flex-wrap: wrap;
            gap: 10px;
        }}
        .alert-title {{
            font-size: 1.3em;
            font-weight: bold;
            color: #333;
        }}
        .alert-details {{
            margin: 15px 0;
            padding: 15px;
            background: #f8f9fa;
            border-radius: 6px;
            font-family: 'Courier New', monospace;
            font-size: 0.9em;
            overflow-x: auto;
        }}
        .alert-details pre {{
            margin: 0;
            white-space: pre-wrap;
            word-wrap: break-word;
        }}
        .alert-summary {{
            margin-top: 15px;
            padding: 15px;
            background: #e7f3ff;
            border-radius: 6px;
            border-left: 3px solid #667eea;
        }}
        .summary-section {{
            margin: 30px;
            padding: 25px;
            background: white;
            border-radius: 8px;
            box-shadow: 0 2px 8px rgba(0,0,0,0.1);
        }}
        .summary-section h2 {{
            margin-bottom: 15px;
            color: #667eea;
        }}
        .summary-content {{
            line-height: 1.8;
            white-space: pre-wrap;
        }}
        .empty-state {{
            text-align: center;
            padding: 40px;
            color: #999;
            font-style: italic;
        }}
        .collapsible {{
            cursor: pointer;
            user-select: none;
        }}
        .collapsible:hover {{
            opacity: 0.8;
        }}
        .collapsible-content {{
            max-height: 0;
            overflow: hidden;
            transition: max-height 0.3s ease-out;
        }}
        .collapsible-content.expanded {{
            max-height: 5000px;
        }}
        @media (max-width: 768px) {{
            .stats {{
                flex-direction: column;
            }}
            .stat-card {{
                width: 100%;
            }}
        }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🔒 Security Scan Report</h1>
            <div class="timestamp">Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</div>
        </div>
        
        <div class="stats">
            <div class="stat-card new">
                <div class="stat-number">{new_count}</div>
                <div class="stat-label">🆕 New Alerts</div>
            </div>
            <div class="stat-card resolved">
                <div class="stat-number">{resolved_count}</div>
                <div class="stat-label">✅ Resolved Alerts</div>
            </div>
            <div class="stat-card common">
                <div class="stat-number">{common_count}</div>
                <div class="stat-label">⚙️ Existing Alerts</div>
            </div>
        </div>
"""
    
    # New Alerts Section
    html_content += f"""
        <div class="section new">
            <h2>🆕 New Alerts ({new_count})</h2>
"""
    if new_alerts_parsed:
        for i, alert in enumerate(new_alerts_parsed, 1):
            risk = alert.get('risk', 'Unknown')
            name = html.escape(str(alert.get('name', 'Unknown Alert')))
            summary = alert.get('summary', 'No summary available.')
            alert_json = html.escape(json.dumps(alert, indent=2))
            
            html_content += f"""
            <div class="alert-card">
                <div class="alert-header">
                    <div class="alert-title">Alert {i}: {name}</div>
                    {format_risk_badge(risk)}
                </div>
                <details>
                    <summary class="collapsible" style="cursor: pointer; color: #667eea; margin: 10px 0;">📋 View Alert Details</summary>
                    <div class="alert-details"><pre>{alert_json}</pre></div>
                </details>
                <div class="alert-summary">
                    <strong>Summary:</strong><br>
                    <div style="margin-top: 10px;">{format_summary_text(summary)}</div>
                </div>
            </div>
"""
    else:
        html_content += '<div class="empty-state">No new alerts.</div>'
    
    html_content += """
        </div>
"""
    
    # Resolved Alerts Section
    html_content += f"""
        <div class="section resolved">
            <h2>✅ Resolved Alerts ({resolved_count})</h2>
"""
    if resolved_alerts_parsed:
        for i, alert in enumerate(resolved_alerts_parsed, 1):
            risk = alert.get('risk', 'Unknown')
            name = html.escape(str(alert.get('name', 'Unknown Alert')))
            summary = alert.get('summary', 'No summary available.')
            alert_json = html.escape(json.dumps(alert, indent=2))
            
            html_content += f"""
            <div class="alert-card">
                <div class="alert-header">
                    <div class="alert-title">Alert {i}: {name}</div>
                    {format_risk_badge(risk)}
                </div>
                <details>
                    <summary class="collapsible" style="cursor: pointer; color: #667eea; margin: 10px 0;">📋 View Alert Details</summary>
                    <div class="alert-details"><pre>{alert_json}</pre></div>
                </details>
                <div class="alert-summary">
                    <strong>Summary:</strong><br>
                    <div style="margin-top: 10px;">{format_summary_text(summary)}</div>
                </div>
            </div>
"""
    else:
        html_content += '<div class="empty-state">No resolved alerts.</div>'
    
    html_content += """
        </div>
"""
    
    # Common/Older Alerts Section
    html_content += f"""
        <div class="section common">
            <h2>⚙️ Existing Alerts ({common_count})</h2>
"""
    if common_alerts_parsed:
        for i, alert in enumerate(common_alerts_parsed, 1):
            risk = alert.get('risk', 'Unknown')
            name = html.escape(str(alert.get('name', 'Unknown Alert')))
            summary = alert.get('summary', 'No summary available.')
            alert_json = html.escape(json.dumps(alert, indent=2))
            
            html_content += f"""
            <div class="alert-card">
                <div class="alert-header">
                    <div class="alert-title">Alert {i}: {name}</div>
                    {format_risk_badge(risk)}
                </div>
                <details>
                    <summary class="collapsible" style="cursor: pointer; color: #667eea; margin: 10px 0;">📋 View Alert Details</summary>
                    <div class="alert-details"><pre>{alert_json}</pre></div>
                </details>
                <div class="alert-summary">
                    <strong>Summary:</strong><br>
                    <div style="margin-top: 10px;">{format_summary_text(summary)}</div>
                </div>
            </div>
"""
    else:
        html_content += '<div class="empty-state">No existing alerts.</div>'
    
    html_content += """
        </div>
"""
    
    # Final Summary Section
    html_content += """
        <div class="summary-section">
            <h2>📊 Final Summary</h2>
"""
    
    if new_final_summary:
        html_content += f"""
            <div style="margin-bottom: 30px;">
                <h3 style="color: #dc3545; margin-bottom: 10px;">🆕 New Alerts Summary</h3>
                <div class="summary-content">{format_summary_text(new_final_summary)}</div>
            </div>
"""
    
    if common_final_summary:
        html_content += f"""
            <div style="margin-bottom: 30px;">
                <h3 style="color: #ffc107; margin-bottom: 10px;">⚙️ Existing Alerts Summary</h3>
                <div class="summary-content">{format_summary_text(common_final_summary)}</div>
            </div>
"""
    
    if resolved_final_summary:
        html_content += f"""
            <div style="margin-bottom: 30px;">
                <h3 style="color: #28a745; margin-bottom: 10px;">✅ Resolved Alerts Summary</h3>
                <div class="summary-content">{format_summary_text(resolved_final_summary)}</div>
            </div>
"""
    
    html_content += """
        </div>
    </div>
</body>
</html>
"""
    
    return html_content

# Get values
ZAP_PORT = int(os.getenv("ZAP_PORT", 8090))
ZAP_API_KEY = os.getenv("ZAP_API_KEY")
ZAP_HOST = os.getenv("ZAP_HOST", "http://localhost")
TARGET_URL = os.getenv("TARGET_URL")
GITHUB_REPO = os.getenv("GITHUB_REPO")  # Format: "owner/repo"

# Initialize ZAP API client
zap = ZAPv2(apikey=ZAP_API_KEY, proxies={'http': f"{ZAP_HOST}:{ZAP_PORT}", 'https': f"{ZAP_HOST}:{ZAP_PORT}"})

# Clear previous alerts and create a new session for this scan
print('🔄 Clearing previous ZAP session and alerts...')
try:
    zap.core.new_session()
    print('✅ New ZAP session created')
except Exception as e:
    print(f'⚠️ Warning: Could not create new session: {e}')
    # Try to delete all alerts as fallback
    try:
        # Delete all alerts
        zap.core.delete_all_alerts()
        print('✅ Previous alerts cleared')
    except Exception as e2:
        print(f'⚠️ Warning: Could not clear alerts: {e2}')

# Access the target URL first
print(f'Accessing target {TARGET_URL}')
zap.urlopen(TARGET_URL)
time.sleep(2)

# 🕷️ Spider Scan
if run_spider:
    print(f'🕷️ Spidering target {TARGET_URL}')
    scanid = zap.spider.scan(TARGET_URL)
    time.sleep(2)
    while int(zap.spider.status(scanid)) < 100:
        print(f'Spider progress %: {zap.spider.status(scanid)}')
        time.sleep(2)
    print('🕷️ Spider completed')
else:
    print('🚫 Skipping Spider scan as per config.')

# ⚡ AJAX Spider
if run_ajax_spider:
    print(f'⚡ AJAX Spidering target {TARGET_URL}')
    zap.ajaxSpider.scan(TARGET_URL)

    timeout = time.time() + ajax_spider_timeout
    while zap.ajaxSpider.status == 'running':
        if time.time() > timeout:
            print('⚠️ AJAX Spider timed out!')
            break
        print(f'AJAX Spider status: {zap.ajaxSpider.status}')
        time.sleep(2)

    print('⚡ AJAX Spider completed')
    ajax_results = zap.ajaxSpider.results(start=0, count=10)
    print(f'⚡ AJAX Spider results (first 10): {ajax_results}')
else:
    print('🚫 Skipping AJAX Spider as per config.')

# 🧠 Passive Scan
if run_passive:
    while int(zap.pscan.records_to_scan) > 0:
        print(f'Passive scan records left: {zap.pscan.records_to_scan}')
        time.sleep(2)
    print('🧠 Passive scan completed')
else:
    print('🚫 Skipping Passive scan as per config.')

# 💥 Active Scan
if run_active:
    print(f'💥 Active scanning target {TARGET_URL}')
    scanid = zap.ascan.scan(TARGET_URL)
    time.sleep(5)
    while int(zap.ascan.status(scanid)) < 100:
        print(f'Active scan progress %: {zap.ascan.status(scanid)}')
        time.sleep(5)
    print('💥 Active scan completed')
else:
    print('🚫 Skipping Active scan as per config.')

# ✅ Sort and save alerts in JSON file
suffix = os.getenv("REPORT_SUFFIX", "")   # main or pr or empty if not set
json_report_filename = f"security_report_{suffix}.json"
alerts = sort_and_save_alerts(zap.core.alerts(), json_report_filename)
print(f"📄 JSON report saved as: {json_report_filename}")

# ✅ Process and summarize alerts
# Note : PR scan should be done after the main scan is done
if suffix == "pr":
    alert_diff("security_report_main.json", "security_report_pr.json")
    
    # Process each alerts file to get summaries
    new_alerts_data = load_alerts("new_alerts.json")
    resolved_alerts_data = load_alerts("resolved_alerts.json")
    common_alerts_data = load_alerts("common_alerts.json")
    
    # Get summaries for each category
    new_summaries, new_final_summary, new_fail_count, new_alerts_with_summaries = get_alert_summaries_and_final_summary(
        new_alerts_data, 
        prompt_path=".security/prompts/prompt_alert.txt", 
        prompt_final_path=".security/prompts/prompt_final.txt", 
        include_pr_changes=True)

    resolved_summaries, resolved_final_summary, resolved_fail_count, resolved_alerts_with_summaries = get_alert_summaries_and_final_summary(
        resolved_alerts_data, 
        prompt_path=".security/prompts/prompt_solved_alert.txt", 
        prompt_final_path=".security/prompts/prompt_solved_final.txt")

    common_summaries, common_final_summary, common_fail_count, common_alerts_with_summaries = get_alert_summaries_and_final_summary(
        common_alerts_data, 
        prompt_path=".security/prompts/prompt_alert.txt", 
        prompt_final_path=".security/prompts/prompt_final.txt", 
        include_pr_changes=False)
    
    # Check for pipeline-failing alerts
    total_fail_count = new_fail_count + common_fail_count
    if total_fail_count > 0:
        fail_levels = config.get('fail_on_levels', [])
        fail_levels_str = ', '.join(fail_levels) if fail_levels else 'configured risk levels'
        print(f"❌ Found {total_fail_count} alert(s) at level(s) [{fail_levels_str}] configured to fail the pipeline.")
        sys.exit(1)
    
    # Build structured report
    resolved_alerts_count = count_alerts("resolved_alerts.json")
    new_alerts_count = count_alerts("new_alerts.json")
    
    # Generate HTML report
    html_content = generate_html_report(
        new_alerts_with_summaries if new_alerts_count > 0 else [],
        resolved_alerts_with_summaries if resolved_alerts_count > 0 else [],
        common_alerts_with_summaries if len(common_alerts_data) > 0 else [],
        new_summaries,
        resolved_summaries,
        common_summaries,
        new_final_summary,
        resolved_final_summary,
        common_final_summary,
        new_alerts_count,
        resolved_alerts_count,
        len(common_alerts_data)
    )
    
    # Write the HTML report
    with open("security_report.html", "w", encoding="utf-8") as f:
        f.write(html_content)
    
    print(f"📄 Security report saved as: security_report.html")

    # ✅ Post interactive summary as PR comment with collapsible sections
    artifact_link = f"https://github.com/{GITHUB_REPO}/actions/runs/{os.getenv('GITHUB_RUN_ID')}"
    
    # Build interactive comment with collapsible sections
    comment_body = "### 🔒 Security Scan Summary 🚨\n\n"
    
    # Add quick stats at the top
    total_new = new_alerts_count
    total_resolved = resolved_alerts_count
    total_common = len(common_alerts_data)
    
    comment_body += f"**Quick Stats:** "
    stats_parts = []
    if total_new > 0:
        stats_parts.append(f"🆕 {total_new} new")
    if total_resolved > 0:
        stats_parts.append(f"✅ {total_resolved} resolved")
    if total_common > 0:
        stats_parts.append(f"⚙️ {total_common} existing")
    comment_body += " | ".join(stats_parts) if stats_parts else "No alerts"
    comment_body += "\n\n---\n\n"
    
    # If no alerts at all, show a success message
    if not stats_parts:
        comment_body += "✅ **No security alerts found!** Great job keeping the codebase secure.\n\n"
    
    # New Alerts Section (collapsible)
    if new_alerts_count > 0:
        comment_body += "<details>\n<summary><b>🆕 New Alerts Summary</b> (" + str(new_alerts_count) + " alert" + ("s" if new_alerts_count > 1 else "") + ")</summary>\n\n"
        comment_body += "```\n" + new_final_summary + "\n```\n\n"
        comment_body += "</details>\n\n"
    
    # Resolved Alerts Section (collapsible)
    if resolved_alerts_count > 0:
        comment_body += "<details>\n<summary><b>✅ Resolved Alerts Summary</b> (" + str(resolved_alerts_count) + " alert" + ("s" if resolved_alerts_count > 1 else "") + ")</summary>\n\n"
        comment_body += "```\n" + resolved_final_summary + "\n```\n\n"
        comment_body += "</details>\n\n"
    
    # Older/Common Alerts Section (collapsible)
    if len(common_alerts_data) > 0:
        comment_body += "<details>\n<summary><b>⚙️ Existing Alerts Summary</b> (" + str(len(common_alerts_data)) + " alert" + ("s" if len(common_alerts_data) > 1 else "") + ")</summary>\n\n"
        comment_body += "```\n" + common_final_summary + "\n```\n\n"
        comment_body += "</details>\n\n"
    
    # Add download link at the bottom
    comment_body += f"---\n\n📂 **[Download Full Report]({artifact_link})**"
    
    post_pr_comment(comment_body)