# ui/app.py

import tkinter as tk
from tkinter import ttk
import threading
import time

from siem.log_ingestor import ingest_all_logs, LOG_DIR, RULE_DIR
from siem.rule_engine import RuleEngine


class WatchtowerApp(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Watchtower SIEM")
        self.geometry("950x550")

        # Monitoring state
        self.monitoring = False
        self.monitor_thread = None

        # Global dark style
        style = ttk.Style(self)
        try:
            style.theme_use("clam")
        except tk.TclError:
            pass  # fall back to default if clam is not available

        # Dark background for tree and headings
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

        # Top section
        top = ttk.Frame(self, padding=10)
        top.pack(side=tk.TOP, fill=tk.X)

        self.info_label = ttk.Label(
            top,
            text=f"Log dir: {LOG_DIR}    Rules loaded: {len(self.rule_engine.rules)}"
        )
        self.info_label.pack(side=tk.LEFT)

        # Slider for refresh interval
        slider_frame = ttk.Frame(top)
        slider_frame.pack(side=tk.RIGHT, padx=10)

        ttk.Label(slider_frame, text="Refresh (sec)").pack()
        self.refresh_slider = ttk.Scale(
            slider_frame, from_=1, to=10, orient=tk.HORIZONTAL
        )
        self.refresh_slider.set(3)
        self.refresh_slider.pack()

        # Control buttons
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

        # Severity tag styles for dark mode
        self.tree.tag_configure(
            "high",
            background="#5c1a1a",      # dark red
            foreground="#ffd6d6",
        )
        self.tree.tag_configure(
            "medium",
            background="#5c4a1a",      # dark amber
            foreground="#ffe9a6",
        )
        self.tree.tag_configure(
            "low",
            background="#1a5c33",      # dark green
            foreground="#b3ffd9",
        )

        # Status bar
        bottom = ttk.Frame(self, padding=10)
        bottom.pack(side=tk.BOTTOM, fill=tk.X)

        self.status_label = ttk.Label(bottom, text="Ready")
        self.status_label.pack(side=tk.LEFT)

    def clear_table(self):
        for row in self.tree.get_children():
            self.tree.delete(row)
        self.status_label.config(text="Alerts cleared.")

    def run_analysis(self):
        """Single run for manual analysis."""
        self.status_label.config(text="Running analysis...")
        self.update_idletasks()

        self.rule_engine.load_rules()
        self.info_label.config(
            text=f"Log dir: {LOG_DIR}    Rules loaded: {len(self.rule_engine.rules)}"
        )

        self.clear_table()
        alert_count = self.process_logs_once()

        self.status_label.config(
            text=f"Analysis complete, {alert_count} alert(s) found.")

    def process_logs_once(self):
        """Processes logs once and populates the table."""
        count = 0

        for source, raw in ingest_all_logs():
            event = {"log_type": source, "raw": raw}
            alerts = self.rule_engine.match_event(event)

            for alert in alerts:
                count += 1

                sev = str(alert.get("severity", "")).lower()
                if sev == "high":
                    tags = ("high",)
                elif sev == "medium":
                    tags = ("medium",)
                else:
                    tags = ("low",)

                self.tree.insert(
                    "",
                    tk.END,
                    values=(
                        source,
                        alert.get("rule_id"),
                        alert.get("severity"),
                        alert.get("description"),
                        alert["event"].get("raw", ""),
                    ),
                    tags=tags,
                )

        return count

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
