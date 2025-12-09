# ui/app.py

import tkinter as tk
from tkinter import ttk
import threading
import time
from datetime import datetime, timezone

from siem.log_ingestor import ingest_all_logs, LOG_DIR, RULE_DIR
from siem.rule_engine import RuleEngine
from siem.storage import SQLiteStorage
from siem.models import Alert
from siem.parsers import parse_event


class WatchtowerApp(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Watchtower SIEM")
        self.geometry("950x580")

        # Monitoring state
        self.monitoring = False
        self.monitor_thread = None

        # Dark style for Treeview
        style = ttk.Style(self)
        try:
            style.theme_use("clam")
        except tk.TclError:
            pass

        style.configure(
            "Treeview",
            background="#1e1e1e",
            foreground="#f5f5f5",
            fieldbackground="#1e1e1e",
            bordercolor="#3c3c3c",
            rowheight=24,
        )
        style.configure(
            "Treeview.Heading",
            background="#2d2d2d",
            foreground="#f5f5f5",
            bordercolor="#3c3c3c",
        )
        style.map(
            "Treeview",
            background=[("selected", "#264f78")],
            foreground=[("selected", "#ffffff")],
        )

        # Rule engine
        self.rule_engine = RuleEngine(rule_dir=RULE_DIR)
        self.rule_engine.load_rules()

        # SQLite storage
        self.storage = SQLiteStorage()
        self.storage.connect()
        self.storage.init_db()

        # Top section - info and refresh slider
        top = ttk.Frame(self, padding=10)
        top.pack(side=tk.TOP, fill=tk.X)

        self.info_label = ttk.Label(
            top,
            text=f"Log dir: {LOG_DIR}    Rules loaded: {len(self.rule_engine.rules)}"
        )
        self.info_label.pack(side=tk.LEFT)

        slider_frame = ttk.Frame(top)
        slider_frame.pack(side=tk.RIGHT, padx=10)

        ttk.Label(slider_frame, text="Refresh (sec)").pack()
        self.refresh_slider = ttk.Scale(
            slider_frame,
            from_=1,
            to=10,
            orient=tk.HORIZONTAL,
        )
        self.refresh_slider.set(3)
        self.refresh_slider.pack()

        # Button row
        btn_frame = ttk.Frame(self, padding=10)
        btn_frame.pack(side=tk.TOP, fill=tk.X)

        self.run_btn = ttk.Button(
            btn_frame, text="Run Analysis Once", command=self.run_analysis)
        self.run_btn.pack(side=tk.LEFT, padx=5)

        self.start_btn = ttk.Button(
            btn_frame, text="Start Monitoring", command=self.start_monitoring)
        self.start_btn.pack(side=tk.LEFT, padx=5)

        self.stop_btn = ttk.Button(
            btn_frame, text="Stop Monitoring", command=self.stop_monitoring)
        self.stop_btn.pack(side=tk.LEFT, padx=5)

        self.clear_btn = ttk.Button(
            btn_frame, text="Clear Alerts", command=self.clear_table)
        self.clear_btn.pack(side=tk.LEFT, padx=5)

        # Filter controls that read from SQLite
        filter_frame = ttk.Frame(self, padding=(10, 0))
        filter_frame.pack(side=tk.TOP, fill=tk.X)

        ttk.Label(filter_frame, text="Severity (from DB):").pack(side=tk.LEFT)
        self.severity_filter = ttk.Combobox(
            filter_frame,
            values=["", "low", "medium", "high"],
            width=10,
            state="readonly",
        )
        self.severity_filter.set("")
        self.severity_filter.pack(side=tk.LEFT, padx=(0, 10))

        load_btn = ttk.Button(
            filter_frame, text="Load Stored Alerts", command=self.load_alerts_from_db)
        load_btn.pack(side=tk.LEFT)

        # Table section
        table_frame = ttk.Frame(self, padding=10)
        table_frame.pack(fill=tk.BOTH, expand=True)

        cols = ("source", "rule_id", "severity", "description", "event")
        self.tree = ttk.Treeview(table_frame, columns=cols, show="headings")

        for col in cols:
            self.tree.heading(col, text=col.capitalize())

        self.tree.column("source", width=80)
        self.tree.column("rule_id", width=150)
        self.tree.column("severity", width=90)
        self.tree.column("description", width=250)
        self.tree.column("event", width=400)

        self.tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

        scroll = ttk.Scrollbar(
            table_frame, orient=tk.VERTICAL, command=self.tree.yview)
        scroll.pack(side=tk.RIGHT, fill=tk.Y)
        self.tree.configure(yscrollcommand=scroll.set)

        # Severity tag styles for dark mode (subtle)
        self.tree.tag_configure(
            "high",
            background="#3a2020",
            foreground="#ffb3b3",
        )
        self.tree.tag_configure(
            "medium",
            background="#3a321f",
            foreground="#ffe9a6",
        )
        self.tree.tag_configure(
            "low",
            background="#1f3a29",
            foreground="#b3ffd9",
        )

        # Status bar
        bottom = ttk.Frame(self, padding=10)
        bottom.pack(side=tk.BOTTOM, fill=tk.X)

        self.status_label = ttk.Label(bottom, text="Ready")
        self.status_label.pack(side=tk.LEFT)

    # -------------- helper methods --------------

    def clear_table(self):
        for row in self.tree.get_children():
            self.tree.delete(row)
        self.status_label.config(text="Alerts cleared.")

    def run_analysis(self):
        """Single run based on current logs."""
        self.status_label.config(text="Running analysis once...")
        self.update_idletasks()

        self.rule_engine.load_rules()
        self.info_label.config(
            text=f"Log dir: {LOG_DIR}    Rules loaded: {len(self.rule_engine.rules)}"
        )

        self.clear_table()
        alert_count = self.process_logs_once()
        self.status_label.config(
            text=f"Analysis complete, {alert_count} alert(s) found.")

    def process_logs_once(self) -> int:
        count = 0

        for source, raw in ingest_all_logs():
            # Use your existing parser to build an Event
            ev = parse_event(source, raw)
            if ev is None:
                continue

            # Optionally store the raw event in the events table
            self.storage.insert_event(ev)

            # Build the event dict that RuleEngine expects, plus extra fields
            event = {
                "log_type": ev.source,
                "raw": ev.raw,
                "user": getattr(ev, "user", ""),
                "src_ip": getattr(ev, "src_ip", ""),
                "action": getattr(ev, "action", ""),
                "timestamp": ev.timestamp,
            }

            alerts = self.rule_engine.match_event(event)

            for alert in alerts:
                count += 1

                sev_value = str(alert.get("severity", "")).lower()
                if sev_value == "high":
                    tags = ("high",)
                elif sev_value == "medium":
                    tags = ("medium",)
                else:
                    tags = ("low",)

                # Show enriched info in the table (source and raw message for now)
                self.tree.insert(
                    "",
                    tk.END,
                    values=(
                        ev.source,
                        alert.get("rule_id"),
                        alert.get("severity"),
                        alert.get("description"),
                        ev.raw,
                    ),
                    tags=tags,
                )

                # Save alert to SQLite using your Alert model and enriched fields
                alert_obj = Alert(
                    timestamp=ev.timestamp,
                    rule_name=alert.get("rule_id") or "",
                    severity=alert.get("severity") or "",
                    src_ip=ev.src_ip or "",
                    user=ev.user or "",
                    message=ev.raw,
                )
                self.storage.insert_alert(alert_obj)

        return count

    def load_alerts_from_db(self):
        """Load stored alerts from SQLite based on severity filter."""
        sev = self.severity_filter.get().strip() or None
        alerts = self.storage.fetch_alerts(severity=sev, limit=500)

        self.clear_table()
        count = 0

        for a in alerts:
            count += 1
            sev_value = str(a["severity"]).lower()
            if sev_value == "high":
                tags = ("high",)
            elif sev_value == "medium":
                tags = ("medium",)
            else:
                tags = ("low",)

            # We do not have source stored, so show n/a for now
            self.tree.insert(
                "",
                tk.END,
                values=(
                    "n/a",
                    a["rule_name"],
                    a["severity"],
                    a["message"],
                    a["message"],
                ),
                tags=tags,
            )

        if sev:
            self.status_label.config(
                text=f"Loaded {count} stored alert(s) from DB with severity = {sev}."
            )
        else:
            self.status_label.config(
                text=f"Loaded {count} stored alert(s) from DB (all severities)."
            )

    # -------------- monitoring loop --------------

    def start_monitoring(self):
        if self.monitoring:
            self.status_label.config(text="Monitoring already running.")
            return

        self.monitoring = True
        self.status_label.config(text="Monitoring started...")

        def loop():
            while self.monitoring:
                interval = int(self.refresh_slider.get())
                self.process_logs_once()
                time.sleep(interval)

        self.monitor_thread = threading.Thread(target=loop, daemon=True)
        self.monitor_thread.start()

    def stop_monitoring(self):
        self.monitoring = False
        self.status_label.config(text="Monitoring stopped.")


if __name__ == "__main__":
    app = WatchtowerApp()
    app.mainloop()
