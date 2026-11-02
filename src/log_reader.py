from pathlib import Path

def read_log_lines(file_path):
    path = Path(file_path)
    if not path.is_file():
        raise FileNotFoundError(f"Log file not found: {file_path}")
    return path.read_text(errors="replace").splitlines()
