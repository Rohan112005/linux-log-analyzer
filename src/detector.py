from collections import defaultdict
from datetime import timedelta

def detect_suspicious_activity(events, threshold=5, window_minutes=5):
    grouped = defaultdict(list)
    for event in events:
        grouped[event["source_ip"]].append(event)
    alerts = []
    window = timedelta(minutes=window_minutes)
    for ip, rows in grouped.items():
        rows.sort(key=lambda x: x["timestamp"])
        failed = [x for x in rows if x["status"] == "failed"]
        for i, first in enumerate(failed):
            matches = [x for x in failed[i:] if x["timestamp"] <= first["timestamp"] + window]
            if len(matches) >= threshold:
                later_success = any(x["status"] == "success" and x["timestamp"] >= first["timestamp"] for x in rows)
                alerts.append({
                    "source_ip": ip, "failed_attempts": len(matches),
                    "window_minutes": window_minutes,
                    "first_seen": first["timestamp"], "last_seen": matches[-1]["timestamp"],
                    "severity": "High" if later_success else "Medium",
                    "alert": "Repeated failures followed by a success" if later_success else "Possible brute-force activity"
                })
                break
    return alerts
