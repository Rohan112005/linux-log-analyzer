import re
from datetime import datetime

SYSLOG = re.compile(r"^(?P<month>[A-Z][a-z]{2})\s+(?P<day>\d{1,2})\s+(?P<time>\d{2}:\d{2}:\d{2})\s+(?P<host>\S+)\s+sshd(?:\[\d+\])?:\s+(?P<message>.*)$")
IP = re.compile(r"\bfrom\s+(?P<ip>(?:\d{1,3}\.){3}\d{1,3}|[0-9a-fA-F:]+)\s+port\b")

def parse_line(line, year=None):
    m = SYSLOG.match(line.strip())
    if not m:
        return None
    msg = m.group("message")
    ip = IP.search(msg)
    if not ip:
        return None
    if msg.startswith(("Failed password", "Invalid user")):
        status = "failed"
    elif msg.startswith(("Accepted password", "Accepted publickey")):
        status = "success"
    else:
        return None
    user = re.search(r"(?:Failed password for|Accepted (?:password|publickey) for|Invalid user)\s+(?:invalid user\s+)?(\S+)", msg)
    timestamp = datetime.strptime(f"{year or datetime.now().year} {m.group('month')} {m.group('day')} {m.group('time')}", "%Y %b %d %H:%M:%S")
    return {"timestamp": timestamp, "host": m.group("host"), "username": user.group(1) if user else "unknown", "source_ip": ip.group("ip"), "status": status, "message": msg}

def parse_lines(lines):
    return [event for line in lines if (event := parse_line(line)) is not None]
