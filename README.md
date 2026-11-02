# Linux Log Analyzer – Suspicious Login Detection

A beginner-friendly blue-team project. It reads Linux SSH authentication logs, detects repeated failed logins, and creates CSV/JSON reports with a Streamlit dashboard.

## Setup (Kali Linux)
```bash
cd linux-log-analyzer
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

## Test using sample logs
```bash
python3 main.py --log-file logs/sample_auth.log
```

## Run the dashboard
```bash
streamlit run dashboard/app.py
```

## Analyze your own log
On Kali/Debian, authentication logs may be at `/var/log/auth.log`:
```bash
sudo .venv/bin/python main.py --log-file /var/log/auth.log
```
If that file is missing, use the sample log first. Some systems store authentication records in the systemd journal instead.

Default detection rule: 5 or more failed SSH logins from one IP within 5 minutes. Adjust with `--threshold` and `--window-minutes`.

Supported starter patterns include SSH failed password, invalid user, accepted password, and accepted public key messages. Linux log formats vary, so this parser will not detect every possible event.

An alert is a lead for investigation, not proof of an attack. Only analyze systems and logs you are authorized to access.
