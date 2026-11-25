"""Popup window: choose input folders, press Run, watch the output.

    python -m honeynet.app
"""
import queue
import subprocess
import sys
import threading
import tkinter as tk
from pathlib import Path
from tkinter import filedialog, font as tkfont

REPO_ROOT = Path(__file__).resolve().parent.parent

# (label, command-line option)
INPUTS = [
    ("PCAP folder", "--pcap-dir"),
    ("Cowrie logs folder", "--cowrie-dir"),
    ("Suricata logs folder", "--suricata-dir"),
]


class App:
    def __init__(self, root):
        self.root = root
        root.title("Honeynet analysis")
        root.geometry("760x520")
        # Come up in front of other windows (a window started from a terminal can stay behind)
        root.lift()
        root.attributes("-topmost", True)
        root.after(300, lambda: root.attributes("-topmost", False))   # then behave normally
        root.focus_force()

        form = tk.Frame(root, padx=10, pady=10)
        form.pack(fill="x")
        form.columnconfigure(1, weight=1)
        self.entries = {}
        for row, (label, option) in enumerate(INPUTS):
            tk.Label(form, text=label, anchor="w").grid(row=row, column=0, sticky="w", pady=2)
            entry = tk.Entry(form)
            entry.grid(row=row, column=1, sticky="ew", padx=8, pady=2)
            tk.Button(form, text="Browse...", command=lambda e=entry: self.browse(e)).grid(row=row, column=2, pady=2)
            self.entries[option] = entry

        bar = tk.Frame(root, padx=10)
        bar.pack(fill="x")
        self.button = tk.Button(bar, text="Run", width=10, command=self.run)
        self.button.pack(side="left")
        self.status = tk.Label(bar, text="Ready. Leave a folder empty to skip the steps that need it.",
                               anchor="w", padx=12)
        self.status.pack(side="left", fill="x")

        self.output = tk.Text(root, wrap="word", state="disabled", padx=8, pady=8)
        self.output.pack(fill="both", expand=True, padx=10, pady=10)

        # Line styles. Mid-tone colours so they read on a light or a dark window.
        bold = tkfont.Font(font=self.output["font"]).copy()
        bold.configure(weight="bold")
        self.output.tag_configure("header", font=bold, foreground="#2563eb", spacing1=10)
        self.output.tag_configure("warn", foreground="#d97706")
        self.output.tag_configure("error", foreground="#dc2626")
        self.output.tag_configure("done", font=bold, foreground="#16a34a", spacing1=10)
        self.in_error = False   # True while printing the lines of a traceback

        self.lines = queue.Queue()
        self.returncode = None

    def browse(self, entry):
        folder = filedialog.askdirectory(parent=self.root)
        if folder:
            entry.delete(0, "end")
            entry.insert(0, folder)

    def command(self):
        # -u: unbuffered, so output shows up while the command runs, not at the end
        cmd = [sys.executable, "-u", "-m", "honeynet", "run", "all"]
        for option, entry in self.entries.items():
            value = entry.get().strip()
            if value:
                cmd += [option, value]
        return cmd

    def run(self):
        self.button.config(state="disabled")
        self.status.config(text="Running...")
        self.output.config(state="normal")
        self.output.delete("1.0", "end")
        self.output.config(state="disabled")
        self.in_error = False
        self.returncode = None
        threading.Thread(target=self._work, args=(self.command(),), daemon=True).start()
        self._poll()

    def _work(self, cmd):
        # Runs in a thread so the window stays responsive. Only touches the queue.
        proc = subprocess.Popen(cmd, cwd=REPO_ROOT, stdout=subprocess.PIPE,
                                stderr=subprocess.STDOUT, text=True)
        for line in proc.stdout:
            self.lines.put(line)
        self.returncode = proc.wait()

    def _poll(self):
        while not self.lines.empty():
            self._append(self.lines.get())
        if self.returncode is None:
            self.root.after(100, self._poll)
            return
        self.status.config(text="Finished" if self.returncode == 0
                           else f"Failed (exit code {self.returncode})")
        self.button.config(state="normal")

    def _tag_for(self, line):
        if "=== [" in line:
            self.in_error = False
            return "header"
        if "ERROR" in line.upper() or "FAILED" in line or line.startswith("Traceback"):
            self.in_error = True
            return "error"
        if "WARNING" in line.upper():
            self.in_error = False
            return "warn"
        if "INFO: Done:" in line:
            self.in_error = False
            return "done"
        return "error" if self.in_error else None

    def _append(self, text):
        self.output.config(state="normal")
        self.output.insert("end", text, self._tag_for(text))
        self.output.see("end")
        self.output.config(state="disabled")


def main():
    root = tk.Tk()
    App(root)
    root.mainloop()


if __name__ == "__main__":
    main()
