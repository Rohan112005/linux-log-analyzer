from pathlib import Path
import sys
import streamlit as st
import pandas as pd

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from src.log_reader import read_log_lines
from src.log_parser import parse_lines
from src.detector import detect_suspicious_activity

st.set_page_config(page_title="Linux Log Analyzer", page_icon="🛡️", layout="wide")
st.title("Linux Log Analyzer")
st.caption("Suspicious login detection | Blue-team learning project")
log_path = st.text_input("Log file path", str(ROOT / "logs" / "sample_auth.log"))
threshold = st.number_input("Failed attempts threshold", 2, 100, 5)
window = st.number_input("Time window (minutes)", 1, 120, 5)
if st.button("Analyze logs", type="primary"):
    try:
        events = parse_lines(read_log_lines(log_path))
        alerts = detect_suspicious_activity(events, int(threshold), int(window))
        df, adf = pd.DataFrame(events), pd.DataFrame(alerts)
        a, b, c = st.columns(3)
        a.metric("Events parsed", len(events))
        b.metric("Failed logins", sum(e["status"] == "failed" for e in events))
        c.metric("Alerts", len(alerts))
        st.subheader("Authentication events")
        if not df.empty:
            st.dataframe(df, use_container_width=True)
            st.bar_chart(df["status"].value_counts())
        else:
            st.info("No supported SSH authentication events found.")
        st.subheader("Suspicious activity")
        st.dataframe(adf, use_container_width=True) if not adf.empty else st.success("No activity matched this rule.")
        st.download_button("Download events CSV", df.to_csv(index=False), "events.csv", "text/csv")
        st.download_button("Download alerts CSV", adf.to_csv(index=False), "alerts.csv", "text/csv")
        st.warning("An alert is a reason to investigate, not proof of an attack.")
    except Exception as e:
        st.error(f"Could not analyze file: {e}")
