import json
from pathlib import Path
import pandas as pd

def save_reports(events, alerts, output_dir="reports"):
    out = Path(output_dir)
    out.mkdir(parents=True, exist_ok=True)
    pd.DataFrame(events).to_csv(out / "events.csv", index=False)
    pd.DataFrame(alerts).to_csv(out / "alerts.csv", index=False)
    def clean(rows):
        return [{k: (v.isoformat() if hasattr(v, "isoformat") else v) for k, v in row.items()} for row in rows]
    (out / "events.json").write_text(json.dumps(clean(events), indent=2))
    (out / "alerts.json").write_text(json.dumps(clean(alerts), indent=2))
