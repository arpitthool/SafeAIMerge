import openai
import os
import json
import yaml
import sys
from datetime import datetime
from dotenv import load_dotenv
from collections import Counter

# Load environment variables
load_dotenv()

# Initialize OpenAI client
OPENAI_API_KEY = os.getenv("OPENAI_API_KEY")
client = openai.OpenAI(api_key=OPENAI_API_KEY)

# Load filtering preferences from YAML config
CONFIG_PATH = ".security/config.yaml"
if os.path.exists(CONFIG_PATH):
    with open(CONFIG_PATH, "r") as config_file:
        config = yaml.safe_load(config_file)
else:
    raise FileNotFoundError("Missing .security/config.yaml file in project directory.")

# Get the max number of alerts to include in the report
alerts_limit = config.get("alerts_limit", 5)

def normalize_levels(config: dict, key: str) -> set:
    """Safely load and normalize risk levels from config into a lowercase set."""
    return set(level.lower() for level in (config.get(key) or []))

# Normalize risk levels from config
summarize_levels = normalize_levels(config, "summarize_levels")
ignore_levels = normalize_levels(config, "ignore_levels") # For ignoring the alert levels
fail_on_levels = normalize_levels(config, "fail_on_levels") # For pipeline gating

def load_prompt(path: str, default: str) -> str:
    """Load a prompt from a file or fallback to a default string."""
    if os.path.exists(path):
        with open(path, "r", encoding="utf-8") as f:
            return f.read().strip()
    return default

def get_summary(alert, include_pr_changes: bool = False):
    """Summarize an individual alert using ChatGPT and a user-defined prompt.
    If pr_changes.txt exists, includes PR code changes for better context-aware suggestions."""
    system_prompt = load_prompt(
        ".security/prompt_alert.txt",
        "You are a cybersecurity expert. Summarize the following security alert."
    )

    # Build user message with alert
    user_content = json.dumps(alert, indent=2)
    
    # Load PR code changes if available (created by GitHub Actions workflow)
    pr_changes_path = "pr_changes.txt"
    if include_pr_changes and os.path.exists(pr_changes_path):
        try:
            with open(pr_changes_path, "r", encoding="utf-8") as f:
                pr_changes = f.read().strip()
            
            if pr_changes:
                # Limit PR changes size to avoid token limits (keep first 8000 chars)
                if len(pr_changes) > 8000:
                    pr_changes = pr_changes[:8000] + "\n\n... (truncated for length)"
                
                user_content += "\n\n--- PR Code Changes (for context) ---\n"
                user_content += pr_changes
                user_content += "\n\n--- End of PR Code Changes ---"
                user_content += "\n\nPlease provide suggestions for fixing this security issue considering the code changes shown above. If the vulnerability is related to the changed code, suggest specific fixes that account for the PR changes."
        except Exception as e:
            print(f"⚠️ Warning: Could not read PR changes from {pr_changes_path}: {e}")

    response = client.chat.completions.create(
        model="gpt-4",
        messages=[
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": user_content}
        ],
        temperature=0.5
    )
    return response.choices[0].message.content

def generate_final_summary(alert_summaries, all_alerts, summarized_alerts, alerts_count):
    """Generate final report from summarized alerts and append ChatGPT's high-level summary."""
    total_alerts = len(all_alerts)
    risk_counts = Counter(alert.get("risk", "Unknown").capitalize() for alert in all_alerts)
    summarized_levels = sorted(set(alert.get("risk", "Unknown").capitalize() for alert in summarized_alerts))

    # Contextual summary
    stats_intro = (
        f"Security scan detected **{total_alerts}** total alerts.\n\n" +
        f"📊 **Risk Level Breakdown:**\n" +
        "".join(f"- {level}: {count}\n" for level, count in risk_counts.items()) + "\n" +
        f"✅ **Alerts summarized in this report**: {', '.join(summarized_levels) or 'None'}.\n" +
        f"🔒 This report includes total **{alerts_count} alert(s)**.\n\n"
    )

    summaries_text = "\n\n".join(item["summary"] for item in alert_summaries)

    system_prompt = load_prompt(
        ".security/prompt_final.txt",
        "You are a security engineer. Analyze the provided summaries and generate a high-level report with urgent issues and recommendations."
    )

    response = client.chat.completions.create(
        model="gpt-4",
        messages=[
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": summaries_text}
        ],
        temperature=0.5
    )

    return stats_intro + response.choices[0].message.content

def sort_alerts_by_risk(alerts):
    """Sort alerts by risk"""
    # Define the desired order of risk levels for sorting
    risk_order = {"high": 0, "medium": 1, "low": 2, "informational": 3}

    # Sort alerts by risk before further processing or saving
    def alert_risk_key(alert):
        # Normalize risk string to lowercase and fall back to a large value if missing or unexpected risk
        return risk_order.get(str(alert.get("risk", "")).lower(), 99)

    sorted_alerts = sorted(alerts, key=alert_risk_key)

    return sorted_alerts

def sort_and_save_alerts(alerts, filename: str):
    sorted_alerts = sort_alerts_by_risk(alerts)

    with open(filename, "w", encoding="utf-8") as f:
        json.dump(sorted_alerts, f, indent=2)
    print(f"📄 JSON report saved as: {filename}")
    return sorted_alerts


def create_alert_summaries(alerts):
    """Create alert summaries and count the number of total processed alerts and pipeline-failing alerts."""
    alert_summaries = []
    fail_risk_alerts = 0  # Counter for pipeline-failing alerts
    total_processed_alerts = 0  # To respect alerts_limit

    print(f"✅ Starting to process {len(alerts)} alert(s).")

    for alert in alerts:
        risk_level = alert.get("risk", "").lower()

        # Ignore alerts in ignore_levels
        if risk_level in ignore_levels:
            continue

        if total_processed_alerts == alerts_limit:
            break  # Respect alert processing limit
        else:
            total_processed_alerts += 1
            
        print(f"→ Processing alert {total_processed_alerts}/{alerts_limit} ({alert.get('risk')}): {alert.get('name')}")

        # Count alerts matching fail_on_levels
        if risk_level in fail_on_levels:
            fail_risk_alerts += 1

        # Summarize only if risk is in summarize_levels
        if risk_level in summarize_levels:
            summary = get_summary(alert)
        else:
            summary = "*No summary generated for this alert based on configuration.*"

        alert_summaries.append({
            "alert": alert,
            "summary": summary
        })

    return alert_summaries, total_processed_alerts, fail_risk_alerts

def process_alerts(alerts):
    """Main entry to filter alerts, selectively summarize, and generate the final report."""
    # Create alert summaries
    alert_summaries, total_processed_alerts, fail_risk_alerts = create_alert_summaries(alerts)

    if not alert_summaries:
        print("⚠️ No alerts to include based on config.")
        return "No alerts to include based on the configured risk levels."

    final_summary = generate_final_summary(
        alert_summaries=alert_summaries,
        all_alerts=alerts,
        summarized_alerts=[item["alert"] for item in alert_summaries if not item["summary"].startswith("*No summary")],
        alerts_count = total_processed_alerts
    )

    # Save results
    filename = "security_report.txt"
    with open(filename, "w", encoding="utf-8") as f:
        f.write("=== Individual Alert Summaries ===\n")
        for i, item in enumerate(alert_summaries, 1):
            f.write(f"\nAlert {i}:\n{json.dumps(item['alert'], indent=2)}\n")
            f.write(f"Summary:\n{item['summary']}\n")
        f.write("\n=== Final Security Report ===\n")
        f.write(final_summary)

    print(f"📄 Security report saved as: {filename}")

    # 🚨 Fail the pipeline if needed
    if fail_risk_alerts > 0:
        print(f"❌ Found {fail_risk_alerts} alert(s) at level(s) [{', '.join(config.get('fail_on_levels', []))}] configured to fail the pipeline.")
        sys.exit(1)
    else:
        print("✅ No blocking alerts found. Proceeding normally.")

    return final_summary
