import argparse
from src.log_reader import read_log_lines
from src.log_parser import parse_lines
from src.detector import detect_suspicious_activity
from src.report_generator import save_reports

def main():
    p = argparse.ArgumentParser(description="Analyze Linux SSH authentication logs")
    p.add_argument("--log-file", default="logs/sample_auth.log")
    p.add_argument("--threshold", type=int, default=5)
    p.add_argument("--window-minutes", type=int, default=5)
    args = p.parse_args()
    lines = read_log_lines(args.log_file)
    events = parse_lines(lines)
    alerts = detect_suspicious_activity(events, args.threshold, args.window_minutes)
    save_reports(events, alerts)
    print(f"Lines read: {len(lines)} | Events parsed: {len(events)} | Alerts: {len(alerts)}")
    for a in alerts:
        print(f"[{a['severity']}] {a['source_ip']} - {a['alert']} ({a['failed_attempts']} failures)")
    print("Reports saved in reports/")

if __name__ == "__main__":
    main()
