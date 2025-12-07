# ui/app.py

import tkinter as tk
from tkinter import ttk

from pathlib import Path
import os

from siem.log_ingestor import ingest_all_logs, LOG_DIR, RULE_DIR
from siem.rule_engine import RuleEngine


class WatchtowerApp(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Watchtower SIEM")
        self.geometry("900x500")

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

        run_btn = ttk.Button(top, text="Run Analysis",
                             command=self.run_analysis)
        run_btn.pack(side=tk.RIGHT)

        # Table section
        table_frame = ttk.Frame(self, padding=10)
        table_frame.pack(fill=tk.BOTH, expand=True)

        cols = ("source", "rule_id", "severity", "description", "event")
        self.tree = ttk.Treeview(table_frame, columns=cols, show="headings")

        self.tree.heading("source", text="Source")
        self.tree.heading("rule_id", text="Rule ID")
        self.tree.heading("severity", text="Severity")
        self.tree.heading("description", text="Description")
        self.tree.heading("event", text="Event")

        self.tree.column("source", width=80)
        self.tree.column("rule_id", width=120)
        self.tree.column("severity", width=90)
        self.tree.column("description", width=250)
        self.tree.column("event", width=350)

        self.tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

        scroll = ttk.Scrollbar(
            table_frame, orient=tk.VERTICAL, command=self.tree.yview)
        scroll.pack(side=tk.RIGHT, fill=tk.Y)
        self.tree.configure(yscrollcommand=scroll.set)

        # Status bar
        bottom = ttk.Frame(self, padding=10)
        bottom.pack(side=tk.BOTTOM, fill=tk.X)

        self.status_label = ttk.Label(bottom, text="Ready")
        self.status_label.pack(side=tk.LEFT)

    def clear_table(self):
        for row in self.tree.get_children():
            self.tree.delete(row)

    def run_analysis(self):
        self.status_label.config(text="Running analysis...")
        self.update_idletasks()

        # Reload rules each run
        self.rule_engine.load_rules()
        self.info_label.config(
            text=f"Log dir: {LOG_DIR}    Rules loaded: {len(self.rule_engine.rules)}"
        )

        self.clear_table()
        alert_count = 0

        for source, raw in ingest_all_logs():
            event = {"log_type": source, "raw": raw}
            alerts = self.rule_engine.match_event(event)

            for alert in alerts:
                alert_count += 1
                self.tree.insert(
                    "",
                    tk.END,
                    values=(
                        source,
                        alert.get("rule_id"),
                        alert.get("severity"),
                        alert.get("description"),
                        alert["event"]["raw"],
                    ),
                )

        if alert_count == 0:
            self.status_label.config(text="Analysis complete, no alerts.")
        else:
            self.status_label.config(
                text=f"Analysis complete, {alert_count} alerts found.")


if __name__ == "__main__":
    app = WatchtowerApp()
    app.mainloop()
