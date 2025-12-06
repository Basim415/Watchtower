# tests/test_parsers.py
from siem.parsers import parse_auth_log


def test_failed_login_parsing():
    line = (
        "Jan  1 10:15:32 server1 sshd[12345]: Failed password for "
        "invalid user admin from 192.168.1.10 port 54321 ssh2"
    )
    ev = parse_auth_log(line)
    assert ev is not None
    assert ev.action == "login_failed"
    assert ev.user == "admin"
    assert ev.src_ip == "192.168.1.10"
