import openai
import os
import json
import yaml
import sys
from dotenv import load_dotenv
from collections import Counter

# Load environment variables
load_dotenv()

# Initialize OpenAI client
OPENAI_API_KEY = os.getenv("OPENAI_API_KEY")
client = openai.OpenAI(api_key=OPENAI_API_KEY)

# Load filtering preferences from YAML config
CONFIG_PATH = "config.yaml"
if os.path.exists(CONFIG_PATH):
    with open(CONFIG_PATH, "r") as config_file:
        config = yaml.safe_load(config_file)
else:
    raise FileNotFoundError("Missing config.yaml file in project directory.")

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

def get_summary(alert):
    """Summarize an individual alert using ChatGPT and a user-defined prompt."""
    system_prompt = load_prompt(
        ".security/prompt_alert.txt",
        "You are a cybersecurity expert. Summarize the following security alert."
    )

    response = client.chat.completions.create(
        model="gpt-4",
        messages=[
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": json.dumps(alert, indent=2)}
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

def process_alerts(alerts):
    """Main entry to filter alerts, selectively summarize, and generate the final report."""
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
    with open("security_report.txt", "w", encoding="utf-8") as f:
        f.write("=== Individual Alert Summaries ===\n")
        for i, item in enumerate(alert_summaries, 1):
            f.write(f"\nAlert {i}:\n{json.dumps(item['alert'], indent=2)}\n")
            f.write(f"Summary:\n{item['summary']}\n")
        f.write("\n=== Final Security Report ===\n")
        f.write(final_summary)

    print("📄 Security report saved as: security_report.txt")

    # 🚨 Fail the pipeline if needed
    if fail_risk_alerts > 0:
        print(f"❌ Found {fail_risk_alerts} alert(s) at level(s) [{', '.join(config.get('fail_on_levels', []))}] configured to fail the pipeline.")
        sys.exit(1)
    else:
        print("✅ No blocking alerts found. Proceeding normally.")

    return final_summary
