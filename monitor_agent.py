"""Consent-based SecureMonitor AI agent for Windows/Linux/macOS.

Set SECUREMONITOR_SERVER_URL and SECUREMONITOR_DEVICE_TOKEN in environment variables.
Set SECUREMONITOR_DEVICE_ID only as a friendly local label; server identity comes from token.
This agent reports basic system-usage metrics only. It does not inspect files, processes,
keystrokes, browsing history, or claim to detect malware.
"""
import json
import os
import platform
import time
from datetime import datetime, timezone
from urllib.parse import urlparse

import psutil
import requests

SERVER_URL = os.environ.get("SECUREMONITOR_SERVER_URL", "").strip().rstrip("/")
DEVICE_TOKEN = os.environ.get("SECUREMONITOR_DEVICE_TOKEN", "").strip()
DEVICE_ID = os.environ.get("SECUREMONITOR_DEVICE_ID", platform.node() or "my-device").strip()[:64]
INTERVAL = max(10, min(300, int(os.environ.get("SECUREMONITOR_INTERVAL_SECONDS", "15"))))


def validate_config():
    if not SERVER_URL or not DEVICE_TOKEN:
        raise SystemExit("Set SECUREMONITOR_SERVER_URL and SECUREMONITOR_DEVICE_TOKEN before starting the agent.")
    parsed = urlparse(SERVER_URL)
    if parsed.scheme != "https" and parsed.hostname not in {"127.0.0.1", "localhost"}:
        raise SystemExit("For remote monitoring, SERVER_URL must use HTTPS. HTTP is allowed only for localhost testing.")
    if not parsed.scheme or not parsed.netloc:
        raise SystemExit("SECUREMONITOR_SERVER_URL must be a full URL, e.g. https://your-site.example")


def collect():
    cpu = psutil.cpu_percent(interval=1)
    memory = psutil.virtual_memory()
    disk = psutil.disk_usage(os.path.abspath(os.sep))
    counters = psutil.net_io_counters()
    now = time.monotonic()
    # A single first sample establishes the baseline; speed is reported as zero initially.
    previous = getattr(collect, "previous", None)
    collect.previous = (counters.bytes_sent, counters.bytes_recv, now)
    if previous:
        elapsed = max(now - previous[2], 0.001)
        up = max(0, counters.bytes_sent - previous[0]) / elapsed / (1024 * 1024)
        down = max(0, counters.bytes_recv - previous[1]) / elapsed / (1024 * 1024)
    else:
        up = down = 0.0
    battery = psutil.sensors_battery() if hasattr(psutil, "sensors_battery") else None
    payload = {
        "cpu_percent": round(float(cpu), 1),
        "ram_percent": round(float(memory.percent), 1),
        "disk_percent": round(float(disk.percent), 1),
        "upload_mbps": round(float(up), 3),
        "download_mbps": round(float(down), 3),
        "battery_percent": round(float(battery.percent), 1) if battery else None,
        "battery_plugged": bool(battery.power_plugged) if battery else None,
        "timestamp": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "risk": "NORMAL",
        "reasons": [],
    }
    reasons = []
    risk = "NORMAL"
    if cpu >= 90:
        risk = "HIGH"; reasons.append(f"CPU usage is very high ({cpu:.0f}%).")
    elif cpu >= 75:
        risk = "MEDIUM"; reasons.append(f"CPU usage is elevated ({cpu:.0f}%).")
    if memory.percent >= 90:
        risk = "HIGH"; reasons.append(f"RAM usage is very high ({memory.percent:.0f}%).")
    elif memory.percent >= 80:
        if risk != "HIGH": risk = "MEDIUM"
        reasons.append(f"RAM usage is elevated ({memory.percent:.0f}%).")
    if disk.percent >= 95:
        risk = "HIGH"; reasons.append(f"Disk usage is critically high ({disk.percent:.0f}%).")
    elif disk.percent >= 90:
        if risk != "HIGH": risk = "MEDIUM"
        reasons.append(f"Disk usage is high ({disk.percent:.0f}%).")
    if not reasons:
        reasons = ["System usage is within configured demo thresholds."]
    payload["risk"] = risk
    payload["reasons"] = reasons
    return payload


def main():
    validate_config()
    endpoint = SERVER_URL + "/api/remote/ingest"
    print(f"SecureMonitor AI agent started for device label: {DEVICE_ID}")
    print(f"Sending basic system metrics every {INTERVAL} seconds to {SERVER_URL}")
    print("Press Ctrl+C to stop. This agent reports system usage, not proof of cyberattacks.")
    session = requests.Session()
    while True:
        try:
            payload = collect()
            response = session.post(endpoint, json=payload,
                headers={"Authorization": f"Bearer {DEVICE_TOKEN}"}, timeout=10)
            if response.ok:
                print(f"[{payload['timestamp']}] {payload['risk']} | CPU {payload['cpu_percent']}% | RAM {payload['ram_percent']}% | disk {payload['disk_percent']}% | sent")
            else:
                print(f"Server rejected update ({response.status_code}): {response.text[:200]}")
        except KeyboardInterrupt:
            print("Agent stopped.")
            break
        except requests.RequestException as exc:
            print(f"Network error; will retry next cycle: {exc}")
        except Exception as exc:
            print(f"Could not collect/send metrics: {exc}")
        time.sleep(INTERVAL)

if __name__ == "__main__":
    main()
