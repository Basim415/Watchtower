# siem/log_ingestor.py
import os
from pathlib import Path
from typing import Iterator, Tuple, List, Dict

from .rule_engine import RuleEngine

# Folder where logs live: Watchtower/data/logs
LOG_DIR = Path(os.path.dirname(os.path.dirname(__file__))) / "data" / "logs"

# Folder where YAML rules live: Watchtower/rules
BASE_DIR = Path(os.path.dirname(os.path.dirname(__file__)))
RULE_DIR = BASE_DIR / "rules"

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
    # Manual test with rule engine
    print(f"LOG_DIR is: {LOG_DIR}")
    print("Existing files:", [p.name for p in get_log_files()])
    print(f"RULE_DIR is: {RULE_DIR}")

    # Create and load rules
    rule_engine = RuleEngine(rule_dir=RULE_DIR)
    rule_engine.load_rules()
    print(f"Loaded {len(rule_engine.rules)} rules")

    seen_sources = set()

    # Walk through all logs, print lines, and check for alerts
    for source, raw in ingest_all_logs():
        if source not in seen_sources:
            print(f"[{source}] # sample log")
            seen_sources.add(source)

        print(f"[{source}] {raw}")

        # Minimal event dict for the rule engine
        event = {
            "log_type": source,
            "raw": raw,
        }

        alerts = rule_engine.match_event(event)
        for alert in alerts:
            print("\n=== ALERT DETECTED ===")
            print(f"Rule: {alert['rule_id']}")
            print(f"Description: {alert['description']}")
            print(f"Severity: {alert['severity']}")
            print(f"Event: {alert['event']['raw']}")
