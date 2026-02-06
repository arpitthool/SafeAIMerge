# 🔐 Automated Security Scanner for CI/CD (ZAP + GPT + GitHub Actions)

![ZAP-LLM-tool - block-diagram](https://github.com/user-attachments/assets/855aad2c-0c76-4609-b951-447f8e5427b8)

demo

Welcome to the **CI/CD-integrated Security Scanner** — an automated system that:

- 🕷️ Scans your web app using [ZAP](https://www.zaproxy.org/)
- 🤖 Summarizes security findings using OpenAI's GPT model
- 💬 Posts those summaries as comments on your GitHub Pull Requests
- 🚨 Can fail the CI pipeline based on configurable risk levels

All of this is packaged into a **configurable, developer-friendly GitHub Action** — requiring minimal setup!

---

## 🚀 Features

- ✅ Works with any web app (static or dynamic) that runs in Docker
- ✅ Supports ZAP Spider, AJAX Spider, Passive Scan, Active Scan
- ✅ Auto-summarizes alerts with GPT for human-readable feedback
- ✅ Context-aware suggestions: LLM analyzes PR code changes to provide targeted security fix recommendations
- ✅ Adds comments directly on PRs
- ✅ Generates visually appealing HTML reports with categorized alerts (new, resolved, common)
- ✅ Pipeline gating: fail PRs with critical risks
- ✅ Customizable via `.security/config.yaml`

---

## 🧩 How It Works

    A[Pull Request Created] --> B[GitHub Action Triggers];
    B --> C[Capture PR Code Changes];
    C --> D[Dockerized Web App Starts];
    D --> E[ZAP Runs Scans];
    E --> F[ZAP Generates Alerts];
    F --> G[Python summarizes alerts using GPT with PR context];
    G --> H[Posts Summary as PR Comment];
    G --> I[Creates security_report.html];
    I --> J[Uploads as GitHub Artifact];
    G --> K[Optional: Fails pipeline on high-risk alert];

## 📁 Project Structure

The project is organized to be easily copied into your existing web app repository. All security scanning code is contained in the `.security/` directory (hidden directory, won't clutter your project root).

```
your-web-app/
├── .security/                          # Security scanning module (copy this entire directory)
│   ├── __init__.py                     # Makes .security/ a Python package
│   ├── scan.py                         # Main scanning script (runs ZAP scans)
│   ├── alert_processor.py              # Processes and summarizes alerts using GPT
│   ├── alert_diff.py                   # Compares alerts between main and PR branches
│   ├── github.py                       # Handles GitHub API interactions (PR comments)
│   ├── config.yaml                     # Configuration file (scan settings, risk levels)
│   ├── prompts/                        # GPT prompt templates directory
│   │   ├── prompt_alert.txt            # GPT prompt template for individual alerts
│   │   ├── prompt_final.txt            # GPT prompt template for final summary
│   │   ├── prompt_solved_alert.txt     # GPT prompt template for resolved alerts
│   │   └── prompt_solved_final.txt     # GPT prompt template for resolved alerts summary
│   └── requirements.txt                # Python dependencies
├── .github/
│   └── workflows/
│       └── zap.yaml                    # GitHub Actions workflow (copy this)
├── README.md                            # This file
└── LICENSE                              # License file
```

### File Descriptions

**`.security/` directory:**
- **`__init__.py`**: Makes `.security/` a Python package, enabling clean imports
- **`scan.py`**: Main entry point that orchestrates ZAP scans (spider, AJAX spider, passive, active scans) and processes results
- **`alert_processor.py`**: Core logic for filtering alerts, calling GPT API for summarization, and generating the security report
- **`alert_diff.py`**: Compares security alerts between main and PR branches to identify new, resolved, and common alerts
- **`github.py`**: Utilities for posting PR comments via GitHub API
- **`config.yaml`**: User-configurable settings for scan types, risk level filtering, and pipeline gating
- **`prompts/prompt_alert.txt`**: Customizable prompt template for GPT to summarize individual security alerts
- **`prompts/prompt_final.txt`**: Customizable prompt template for GPT to generate high-level security summary
- **`prompts/prompt_solved_alert.txt`**: Customizable prompt template for GPT to summarize resolved alerts
- **`prompts/prompt_solved_final.txt`**: Customizable prompt template for GPT to generate summary for resolved alerts
- **`requirements.txt`**: Python package dependencies (openai, dotenv, zaproxy, pyyaml)

**`.github/workflows/zap.yaml`**: GitHub Actions workflow that runs the security scan on PRs, schedules, or manual triggers

**Generated files** (not in repo):
- **`security_report.html`**: Generated during each scan run, contains detailed alert summaries and final report in HTML format (uploaded as artifact)
- **`pr_changes.txt`**: Automatically created by the workflow for PR events, contains the code diff for context-aware security suggestions

### Copying to Your Project

Simply copy the `.security/` directory and `.github/workflows/zap.yaml` into your existing web app repository. The hidden `.security/` directory keeps your project root clean while containing all security scanning functionality.

## ⚙️ Setup

### 1. 🍴 Copy files to your repository

Copy the following into your web app repository:
- **`.security/`** directory (all files within)
- **`.github/workflows/zap.yaml`** (create `.github/workflows/` if it doesn't exist)

This keeps your project organized with all security scanning code in a hidden directory.

---

### 2. 🔑 Set up required secrets in GitHub

Go to your repo → **Settings → Secrets and variables → Actions** → Add these:

| Secret Name       | Description                                                        |
|-------------------|--------------------------------------------------------------------|
| `ZAP_API_KEY`     | Random key used to authenticate with ZAP                           |
| `OPENAI_API_KEY`  | Your OpenAI GPT API key                                            |
| `GH_BOT_TOKEN`    | GitHub token (e.g., `${{ secrets.GITHUB_TOKEN }}` or bot token)    |


### 3. 🛠️ Configure your scan settings

Edit `.security/config.yaml` in your repo:

```yaml
summarize_levels:
  - High
  - Medium

alerts_limit: 5

ignore_levels:
  - Informational

fail_on_levels:
  - High

scans:
  spider: true
  ajax_spider: true
  ajax_spider_timeout: 180  # in seconds
  passive: true
  active: false
```

- Only `summarize_levels` are processed by the LLM  
- `ignore_levels` are completely skipped  
- `fail_on_levels` will cause the pipeline to fail if triggered
- `alerts_limit` defines the total number of alerts that the report will contain

---

### 4. 🐳 Ensure your web app can run in Docker

The scanner expects your web app to be runnable like this:

```bash
docker run -d --name my-web-app --network zapnet -p 127.0.0.1:3000:3000 your-web-app-image
```

By default, we use:
```bash
bkimminich/juice-shop
```
Replace it with your own app image in .github/workflows/zap.yaml.

### 5. ✅ Supported Triggers

Your scan runs automatically on:

- `pull_request` to `main`
- Manual trigger via "Run workflow"
- Scheduled cron job (weekly on Sunday at 2 AM EST by default)

---

## 📄 Output

- 📝 `security_report.html` uploaded as a GitHub artifact (visually appealing HTML report with categorized alerts)  
- 🧠 LLM-generated summary posted as a **comment** on the PR  
- 🎯 Context-aware suggestions: For PR events, the LLM analyzes your code changes and provides targeted security fix recommendations
- ❌ Optional CI failure if critical risk alerts are found

🧪 Example Report Content

The HTML report includes categorized sections for:
- **New Alerts**: Security issues introduced in the PR
- **Resolved Alerts**: Security issues fixed in the PR
- **Common Alerts**: Existing security issues present in both branches

Each section contains detailed alert information with LLM-generated summaries. Example content structure:

```
Security scan detected 9 total alerts.

📊 Risk Level Breakdown:
- High: 2
- Medium: 3
- Informational: 4

✅ Alerts summarized in this report: High, Medium.

🔐 Summary:
- One XSS vulnerability found on /search endpoint.
- Content-Security-Policy header missing on homepage.
...
```
## 🙋 FAQ

### Can I use this outside GitHub Actions?

Yes — the scripts can also be run locally or inside any CI tool that supports Docker + Python.

### What if I don't want the pipeline to fail?

Just leave `fail_on_levels:` empty in `.security/config.yaml`.

### What GPT model is used?

By default, it uses `gpt-4`, but you can customize this in `.security/alert_processor.py`.

### How does the PR code context feature work?

When scanning a Pull Request, the workflow automatically captures the code changes (diff) between the base and head branches. This diff is included in the LLM prompts when summarizing security alerts, allowing the AI to:
- Understand what code was changed in the PR
- Provide specific, targeted fix suggestions that account for your changes
- Identify if new vulnerabilities were introduced by the PR changes

The PR code changes are stored in `pr_changes.txt` during the workflow run and automatically loaded by `alert_processor.py` when available. Large diffs are automatically truncated to stay within token limits.


