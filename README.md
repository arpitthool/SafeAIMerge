# 🔐 Automated Security Scanner for CI/CD (ZAP + GPT + GitHub Actions)
# some code change
Welcome to the **CI/CD-integrated Security Scanner** — an automated system that:

- 🕷️ Scans your web app using [ZAP](https://www.zaproxy.org/)
- 🤖 Summarizes security findings using OpenAI's GPT model
- 💬 Posts those summaries as comments on your GitHub Pull Requests
- 🚨 Can fail the CI pipeline based on configurable risk levels

All of this is packaged into a **configurable, developer-friendly GitHub Action** — requiring minimal setup!

---
## Tool Demo

   https://drive.google.com/file/d/1KsJMFevws7GOrctwwYCsf6BeieYnWCf7/view?usp=sharing

---

## 🚀 Features

- ✅ Works with any web app (static or dynamic) that runs in Docker
- ✅ Supports ZAP Spider, AJAX Spider, Passive Scan, Active Scan
- ✅ Auto-summarizes alerts with GPT for human-readable feedback
- ✅ Adds comments directly on PRs
- ✅ Pipeline gating: fail PRs with critical risks
- ✅ Customizable via `config.yaml`

---

## 🧩 How It Works

    A[Pull Request Created] --> B[GitHub Action Triggers];
    B --> C[Dockerized Web App Starts];
    C --> D[ZAP Runs Scans];
    D --> E[ZAP Generates Alerts];
    E --> F[Python summarizes alerts using GPT];
    F --> G[Posts Summary as PR Comment];
    F --> H[Creates security_report.txt];
    H --> I[Uploads as GitHub Artifact];
    F --> J[Optional: Fails pipeline on high-risk alert];

## ⚙️ Setup

### 1. 🍴 Fork or clone this repo

You can also copy the `.github/workflows/zap.yaml`, `basic_scan.py`, and related files into your own repo.

---

### 2. 🔑 Set up required secrets in GitHub

Go to your repo → **Settings → Secrets and variables → Actions** → Add these:

| Secret Name       | Description                                                        |
|-------------------|--------------------------------------------------------------------|
| `ZAP_API_KEY`     | Random key used to authenticate with ZAP                           |
| `OPENAI_API_KEY`  | Your OpenAI GPT API key                                            |
| `GH_BOT_TOKEN`    | GitHub token (e.g., `${{ secrets.GITHUB_TOKEN }}` or bot token)    |


### 3. 🛠️ Configure your scan settings

Edit `config.yaml` in your repo:

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
- Scheduled cron job (every 5 mins by default)

---

## 📄 Output

- 📝 `security_report.txt` uploaded as a GitHub artifact  
- 🧠 LLM-generated summary posted as a **comment** on the PR  
- ❌ Optional CI failure if critical risk alerts are found

🧪 Example Report Snippet

```yaml
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

### What if I don’t want the pipeline to fail?

Just leave `fail_on_levels:` empty in `config.yaml`.

### What GPT model is used?

By default, it uses `gpt-4`, but you can customize this in `alert_processor.py`.


