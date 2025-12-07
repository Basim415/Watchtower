# siem/rule_engine.py

import os
import yaml
import re
from pathlib import Path
from typing import List, Dict, Any


class RuleEngine:
    def __init__(self, rule_dir):
        self.rule_dir = Path(rule_dir)
        self.rules: List[Dict[str, Any]] = []

    def load_rules(self):
        """Load all YAML rules from the rules directory."""
        self.rules.clear()

        if not self.rule_dir.exists():
            print(f"Rule directory does not exist: {self.rule_dir}")
            return

        for file in os.listdir(self.rule_dir):
            if not file.endswith(".yaml"):
                continue

            path = self.rule_dir / file
            try:
                with path.open("r", encoding="utf-8") as f:
                    data = yaml.safe_load(f)

                # Skip empty or invalid YAML
                if not data:
                    print(f"Skipping empty rule file: {file}")
                    continue
                if not isinstance(data, dict):
                    print(f"Skipping non dict rule file: {file}")
                    continue

                # Optional: basic validation
                if "id" not in data or "log_type" not in data or "match_type" not in data:
                    print(
                        f"Skipping rule file missing required fields: {file}")
                    continue

                self.rules.append(data)
                print(f"Loaded rule from {file}: {data.get('id')}")

            except Exception as e:
                print(f"Error loading rule file {file}: {e}")

    def match_event(self, event: Dict[str, Any]):
        """Return a list of alerts for a given event dict."""
        alerts = []
        event_log_type = event.get("log_type")
        message = event.get("raw", "")

        for rule in self.rules:
            # Extra guard in case something weird slipped in
            if not isinstance(rule, dict):
                continue

            log_type = rule.get("log_type")
            if event_log_type != log_type:
                continue

            match_type = rule.get("match_type")
            pattern = rule.get("pattern")

            if not pattern or not match_type:
                continue

            if match_type == "contains":
                if pattern in message:
                    alerts.append(self._build_alert(rule, event))

            elif match_type == "equals":
                if message.strip() == str(pattern).strip():
                    alerts.append(self._build_alert(rule, event))

            elif match_type == "regex":
                try:
                    if re.search(pattern, message):
                        alerts.append(self._build_alert(rule, event))
                except re.error as e:
                    print(f"Invalid regex in rule {rule.get('id')}: {e}")
                    continue

        return alerts

    def _build_alert(self, rule: Dict[str, Any], event: Dict[str, Any]):
        return {
            "rule_id": rule.get("id"),
            "description": rule.get("description"),
            "severity": rule.get("severity"),
            "event": event,
        }
