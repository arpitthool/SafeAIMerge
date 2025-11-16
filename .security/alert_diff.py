#!/usr/bin/env python3


import json
from urllib.parse import urlparse
from pathlib import Path


# ------------------------------------------------------------
# Helper Functions
# ------------------------------------------------------------

def read_json(path: Path):
    """Read and parse JSON safely."""
    if not path.exists():
        print(f"[WARN] File does not exist: {path}")
        return []
    
    if path.stat().st_size == 0:
        print(f"[WARN] File is empty: {path}")
        return []
    
    try:
        with path.open("r", encoding="utf-8") as f:
            content = f.read().strip()
            if not content:
                print(f"[WARN] File contains only whitespace: {path}")
                return []
            return json.loads(content)
    except json.JSONDecodeError as e:
        print(f"[ERROR] Invalid JSON in {path}: {e}")
        return []
    except Exception as e:
        print(f"[ERROR] Error reading {path}: {e}")
        return []


def iter_alert_objects(data):
    """Yield all alert objects regardless of ZAP export structure."""
    if isinstance(data, list):
        for a in data:
            if isinstance(a, dict) and "alert" in a:
                yield a
        return
    if isinstance(data, dict):
        sites = data.get("site") or []
        if isinstance(sites, list):
            for site in sites:
                alerts = site.get("alerts") or site.get("alert") or []
                if isinstance(alerts, list):
                    for a in alerts:
                        if isinstance(a, dict) and "alert" in a:
                            yield a


def normalize_url(url: str) -> str:
    """Normalize URL by removing host, query, and trailing slash."""
    if not url:
        return ""
    try:
        parsed = urlparse(url)
        path = parsed.path or "/"
        if path != "/" and path.endswith("/"):
            path = path[:-1]
        return path.lower()
    except Exception:
        return url.strip().lower().rstrip("/")


def safe_str(v):
    return str(v or "").strip()


def alert_signature(a):
    """Create a normalized tuple key for comparison."""
    return (
        safe_str(a.get("pluginId")),
        safe_str(a.get("alert")).lower(),
        safe_str(a.get("risk")).lower(),
        safe_str(a.get("cweid")),
        normalize_url(a.get("url", "")),
        safe_str(a.get("param")),
    )


def normalize_alerts(path: Path):
    """Return (set of signatures, map of signature→alert) for a given ZAP file."""
    data = read_json(path)
    if not data:
        print(f"[INFO] No alerts found in {path}, returning empty set and map")
        return set(), {}
    
    alerts = list(iter_alert_objects(data))
    norm_set = set()
    norm_map = {}
    for a in alerts:
        sig = alert_signature(a)
        norm_set.add(sig)
        norm_map[sig] = a
    return norm_set, norm_map

def alert_diff (main_report_filename: str = "security_report_main.json", pr_report_filename: str = "security_report_pr.json"):
    """
    ZAP JSON Diff (Main vs PR) - JSON Output Only

    Compares two ZAP reports (main vs PR) and outputs:
        - new_alerts.json
        - resolved_alerts.json
        - common_alerts.json

    Normalization:
    - Ignores differences in hostname, querystring, trailing slashes
    - Drops noisy fields like confidence, evidence, IDs
    - Compares by (pluginId, alert, risk, cweid, normalized path, param)

    Usage:
        python zap_diff_json.py --main security_report_main.json --pr security_report_pr.json
    """
    print(f"[INFO] Loading main report: {main_report_filename}")
    main_set, main_map = normalize_alerts(Path(main_report_filename))

    print(f"[INFO] Loading PR report: {pr_report_filename}")
    pr_set, pr_map = normalize_alerts(Path(pr_report_filename))

    new_signatures = pr_set - main_set
    resolved_signatures = main_set - pr_set
    common_signatures = pr_set & main_set

    new_alerts = [pr_map[s] for s in new_signatures if s in pr_map]
    resolved_alerts = [main_map[s] for s in resolved_signatures if s in main_map]
    common_alerts = [pr_map[s] for s in common_signatures if s in pr_map]

    print("\n=== ZAP DIFF SUMMARY ===")
    print(f"🆕 New alerts: {len(new_alerts)}")
    print(f"✅ Resolved alerts: {len(resolved_alerts)}")
    print(f"⚙️ Common alerts: {len(common_alerts)}")

    # Write results
    with open("new_alerts.json", "w", encoding="utf-8") as f:
        json.dump(new_alerts, f, indent=2)

    with open("resolved_alerts.json", "w", encoding="utf-8") as f:
        json.dump(resolved_alerts, f, indent=2)

    with open("common_alerts.json", "w", encoding="utf-8") as f:
        json.dump(common_alerts, f, indent=2)

    print("\n[OK] Wrote new_alerts.json")
    print("[OK] Wrote resolved_alerts.json")
    print("[OK] Wrote common_alerts.json")

    # Optional quick summary of top new alerts
    if new_alerts:
        print("\nTop NEW alerts (up to 10):")
        for i, alert in enumerate(new_alerts[:10]):
            print(f"- [{alert.get('risk')}] {alert.get('alert')} @ {normalize_url(alert.get('url',''))}")
