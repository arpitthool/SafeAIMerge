import requests
import os

# Load GitHub API token from environment variable
GITHUB_TOKEN = os.getenv("GITHUB_TOKEN")
GITHUB_REPO = os.getenv("GITHUB_REPO")  # Format: "owner/repo"
PR_NUMBER = os.getenv("GITHUB_PR_NUMBER")  # PR number

def post_pr_comment(comment_body):
    """Post a comment on a GitHub PR."""
    url = f"https://api.github.com/repos/{GITHUB_REPO}/issues/{PR_NUMBER}/comments"
    headers = {
        "Authorization": f"Bearer {GITHUB_TOKEN}",
        "Accept": "application/vnd.github.v3+json"
    }
    payload = {"body": comment_body}

    response = requests.post(url, headers=headers, json=payload)

    if response.status_code == 201:
        print("Comment posted successfully!")
    else:
        print(f"Failed to post comment: {response.json()}")

# Read the final security report
with open("security_report.txt", "r") as f:
    final_summary = f.read()

