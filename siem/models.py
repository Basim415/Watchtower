# models
from dataclasses import dataclass
from typing import Optional


@dataclass
class Event:
    id: Optional[int] = None
    timestamp: str = ""      # store as ISO string, easier with SQLite
    source: str = ""         # which log file, for example "auth.log"
    raw: str = ""            # full raw log line
    action: str = ""         # example "login_failed"
    user: str = ""
    src_ip: str = ""


@dataclass
class Rules:
    name: str
    description: str
    severity: str = "low"
    # later will load conditions and thresholds from YAML
    condition: dict | None = None
    threshold: dict | None = None


@dataclass
class Alert:
    id: Optional[int] = None
    timestamp: str = ""
    rule_name: str = ""
    severity: str = "low"
    src_ip: str = ""
    user: str = ""
    message: str = ""
