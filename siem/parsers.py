# siem/parsers.py
import re
from datetime import datetime
from typing import Optional

from .models import Event

# Regexes for auth.log lines
AUTH_FAILED_RE = re.compile(
    r"Failed password for (invalid user )?(?P<user>\S+) from (?P<src_ip>\d+\.\d+\.\d+\.\d+)"
)

AUTH_ACCEPTED_RE = re.compile(
    r"Accepted password for (?P<user>\S+) from (?P<src_ip>\d+\.\d+\.\d+\.\d+)"
)


def parse_auth_log(raw: str) -> Optional[Event]:
    """
    Parse a single sshd auth.log line into an Event.
    Focus: action = login_failed or login_success and src_ip.
    """
    raw = raw.strip()
    if not raw or raw.startswith("#"):
        return None

    ts = datetime.now().isoformat()

    m = AUTH_FAILED_RE.search(raw)
    if m:
        return Event(
            timestamp=ts,
            source="auth",
            raw=raw,
            action="login_failed",
            user=m.group("user"),
            src_ip=m.group("src_ip"),
        )

    m = AUTH_ACCEPTED_RE.search(raw)
    if m:
        return Event(
            timestamp=ts,
            source="auth",
            raw=raw,
            action="login_success",
            user=m.group("user"),
            src_ip=m.group("src_ip"),
        )

    # unknown auth line, still store it if we want
    return Event(
        timestamp=ts,
        source="auth",
        raw=raw,
        action="",
        user="",
        src_ip="",
    )


# Very basic web log parser stub
WEB_IP_RE = re.compile(r"(?P<src_ip>\d+\.\d+\.\d+\.\d+)")


def parse_web_log(raw: str) -> Optional[Event]:
    raw = raw.strip()
    if not raw or raw.startswith("#"):
        return None

    ts = datetime.now().isoformat()

    m = WEB_IP_RE.search(raw)
    src_ip = m.group("src_ip") if m else ""

    # you can make this smarter later
    return Event(
        timestamp=ts,
        source="web",
        raw=raw,
        action="web_event",
        user="",
        src_ip=src_ip,
    )


def parse_event(source: str, raw: str) -> Optional[Event]:
    """
    Main entry point: choose the right parser based on source key.
    """
    if source == "auth":
        return parse_auth_log(raw)
    if source == "web":
        return parse_web_log(raw)

    # unknown source for now
    ts = datetime.now().isoformat()
    return Event(timestamp=ts, source=source, raw=raw)


if __name__ == "__main__":
    # manual test: run the ingestor and parse each line
    from .log_ingestor import ingest_all_logs

    for source, raw in ingest_all_logs():
        ev = parse_event(source, raw)
        if ev is None:
            continue
        print(
            f"{ev.timestamp} [{ev.source}] action={ev.action} "
            f"user={ev.user} src_ip={ev.src_ip}"
        )
