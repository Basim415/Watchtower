# siem/log_ingestor.py
import os
from pathlib import Path
from typing import Iterator, Tuple, List, Dict

# Folder where logs live: Watchtower/data/logs
LOG_DIR = Path(os.path.dirname(os.path.dirname(__file__))) / "data" / "logs"

# Map filenames to a logical source key
SUPPORTED_SOURCES: Dict[str, str] = {
    "auth.log": "auth",
    "web.log": "web",
}


def get_log_files() -> List[Path]:
    """Return a list of existing log files in LOG_DIR."""
    LOG_DIR.mkdir(parents=True, exist_ok=True)

    files: List[Path] = []
    for name in SUPPORTED_SOURCES.keys():
        path = LOG_DIR / name
        if path.exists():
            files.append(path)
    return files


def iter_log_lines() -> Iterator[Tuple[str, str]]:
    """
    Yield (source, raw_line) pairs for all supported log files.

    source is a short string like "auth" or "web".
    raw_line is the full text of the line.
    """
    for path in get_log_files():
        source_key = SUPPORTED_SOURCES[path.name]
        with path.open("r", encoding="utf-8") as f:
            for line in f:
                line = line.rstrip("\n")
                if not line.strip():
                    continue
                yield source_key, line


def ingest_all_logs() -> Iterator[Tuple[str, str]]:
    """
    Main generator that other code will use.

    Later, run_full_ingest in siem.cli will loop over this.
    """
    yield from iter_log_lines()


if __name__ == "__main__":
    # Tiny manual test
    print(f"LOG_DIR is: {LOG_DIR}")
    print("Existing files:", [p.name for p in get_log_files()])
    for source, raw in ingest_all_logs():
        print(f"[{source}] {raw}")
