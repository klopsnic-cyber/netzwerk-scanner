"""
Tkinter-Oberfläche für den Netzwerk-Scanner.

Der Scan läuft in einem Hintergrund-Thread; Fortschritt und Ergebnisse
werden über eine Queue an den GUI-Thread gemeldet (Tk ist nicht
thread-sicher).
"""

from __future__ import annotations

import os
import queue
import threading
import tkinter as tk
from tkinter import filedialog, messagebox, ttk
from typing import List, Optional

from . import __app_name__, __version__
from . import exporter
from .oui import database_size
from .scanner import Host, ScanConfig, Scanner, guess_local_network

DEPTH_LABELS = {
    "schnell": "Schnell (nur wichtigste Ports)",
    "standard": "Standard",
    "gruendlich": "Gründlich (alle Ports + Banner)",
}
DEPTH_ORDER = ["schnell", "standard", "gruendlich"]

TREE_COLUMNS = [
    ("ip", "IP-Adresse", 120),
    ("vendor", "Hersteller", 150),
    ("device", "Gerätetyp", 170),
    ("hostname", "Netzwerkname", 160),
    ("mac", "MAC-Adresse", 140),
    ("winfunc", "Windows-Funktion", 150),
    ("ports", "Offene Ports", 160),
]


class App(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title(f"{__app_name__} {__version__}")
        self.geometry("1080x680")
        self.minsize(900, 560)

        self.scanner: Optional[Scanner] = None
        self.scan_thread: Optional[threading.Thread] = None
        self.hosts: List[Host] = []
        # None = eingebaute Vorlage (in den Programmcode eingebacken).
        self.template_path = None
        self.msg_queue: "queue.Queue" = queue.Queue()

        self._build_ui()
        self.after(100, self._poll_queue)

    # ------------------------------------------------------------------ UI
    def _build_ui(self):
        pad = {"padx": 8, "pady": 4}
        style = ttk.Style(self)
        try:
            style.theme_use("aqua")  # nativer Look auf macOS
        except tk.TclError:
            pass

        # --- Kopfdaten -------------------------------------------------
        top = ttk.LabelFrame(self, text="Kundendaten (optional)")
        top.pack(fill="x", **pad)
        self.var_kunde = tk.StringVar()
        self.var_kundennr = tk.StringVar()
        self.var_datum = tk.StringVar()
        ttk.Label(top, text="Kundenname:").grid(row=0, column=0, sticky="e", padx=4, pady=4)
        ttk.Entry(top, textvariable=self.var_kunde, width=28).grid(row=0, column=1, padx=4)
        ttk.Label(top, text="Tomedo Kundennr.:").grid(row=0, column=2, sticky="e", padx=4)
        ttk.Entry(top, textvariable=self.var_kundennr, width=18).grid(row=0, column=3, padx=4)
        ttk.Label(top, text="Installationsdatum:").grid(row=0, column=4, sticky="e", padx=4)
        ttk.Entry(top, textvariable=self.var_datum, width=14).grid(row=0, column=5, padx=4)

        # --- Scan-Einstellungen ---------------------------------------
        cfg = ttk.LabelFrame(self, text="Scan")
        cfg.pack(fill="x", **pad)
        ttk.Label(cfg, text="Netzbereich (CIDR):").grid(row=0, column=0, sticky="e", padx=4, pady=6)
        self.var_cidr = tk.StringVar(value=guess_local_network())
        ttk.Entry(cfg, textvariable=self.var_cidr, width=22).grid(row=0, column=1, padx=4)
        ttk.Button(cfg, text="Erkennen", command=self._detect_net).grid(row=0, column=2, padx=4)

        ttk.Label(cfg, text="Tiefe:").grid(row=0, column=3, sticky="e", padx=4)
        self.var_depth = tk.StringVar(value=DEPTH_LABELS["gruendlich"])
        depth_box = ttk.Combobox(cfg, textvariable=self.var_depth, state="readonly",
                                 values=[DEPTH_LABELS[d] for d in DEPTH_ORDER], width=30)
        depth_box.grid(row=0, column=4, padx=4)

        self.btn_scan = ttk.Button(cfg, text="Scan starten", command=self._start_scan)
        self.btn_scan.grid(row=0, column=5, padx=8)
        self.btn_cancel = ttk.Button(cfg, text="Abbrechen", command=self._cancel_scan, state="disabled")
        self.btn_cancel.grid(row=0, column=6, padx=4)

        # --- Vorlage ---------------------------------------------------
        tpl = ttk.Frame(self)
        tpl.pack(fill="x", **pad)
        ttk.Label(tpl, text="Excel-Vorlage:").pack(side="left", padx=4)
        self.var_tpl = tk.StringVar(value="Netzwerkdoku-Vorlage (eingebaut)")
        ttk.Label(tpl, textvariable=self.var_tpl, foreground="#3366aa").pack(side="left", padx=4)
        ttk.Button(tpl, text="Andere Vorlage wählen …", command=self._pick_template).pack(side="left", padx=8)
        ttk.Button(tpl, text="Zurück zur eingebauten", command=self._reset_template).pack(side="left", padx=2)

        # --- Fortschritt ----------------------------------------------
        prog = ttk.Frame(self)
        prog.pack(fill="x", **pad)
        self.progress = ttk.Progressbar(prog, mode="determinate", maximum=1.0)
        self.progress.pack(side="left", fill="x", expand=True, padx=4)
        self.var_status = tk.StringVar(value=f"Bereit – OUI-Datenbank: {database_size()} Hersteller.")
        ttk.Label(prog, textvariable=self.var_status, width=48, anchor="w").pack(side="left", padx=8)

        # --- Ergebnis-Tabelle -----------------------------------------
        table_frame = ttk.Frame(self)
        table_frame.pack(fill="both", expand=True, **pad)
        cols = [c[0] for c in TREE_COLUMNS]
        self.tree = ttk.Treeview(table_frame, columns=cols, show="headings")
        for key, label, width in TREE_COLUMNS:
            self.tree.heading(key, text=label)
            self.tree.column(key, width=width, anchor="w")
        vsb = ttk.Scrollbar(table_frame, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscrollcommand=vsb.set)
        self.tree.pack(side="left", fill="both", expand=True)
        vsb.pack(side="right", fill="y")

        # --- Aktionen --------------------------------------------------
        actions = ttk.Frame(self)
        actions.pack(fill="x", **pad)
        self.var_count = tk.StringVar(value="0 Geräte")
        ttk.Label(actions, textvariable=self.var_count).pack(side="left", padx=4)
        self.btn_export = ttk.Button(actions, text="In Excel exportieren …",
                                     command=self._export, state="disabled")
        self.btn_export.pack(side="right", padx=4)

    # ------------------------------------------------------------- Aktionen
    def _detect_net(self):
        self.var_cidr.set(guess_local_network())

    def _pick_template(self):
        path = filedialog.askopenfilename(
            title="Excel-Vorlage wählen",
            filetypes=[("Excel", "*.xlsx"), ("Alle Dateien", "*.*")])
        if path:
            self.template_path = path
            self.var_tpl.set(os.path.basename(path))

    def _reset_template(self):
        self.template_path = None
        self.var_tpl.set("Netzwerkdoku-Vorlage (eingebaut)")

    def _current_depth(self) -> str:
        label = self.var_depth.get()
        for key, lbl in DEPTH_LABELS.items():
            if lbl == label:
                return key
        return "gruendlich"

    def _start_scan(self):
        if self.scan_thread and self.scan_thread.is_alive():
            return
        cidr = self.var_cidr.get().strip()
        try:
            import ipaddress
            ipaddress.ip_network(cidr, strict=False)
        except ValueError:
            messagebox.showerror("Ungültiger Netzbereich",
                                 f"'{cidr}' ist kein gültiges CIDR-Netz (z.B. 192.168.1.0/24).")
            return

        self.hosts = []
        for item in self.tree.get_children():
            self.tree.delete(item)
        self.var_count.set("0 Geräte")
        self.btn_scan.config(state="disabled")
        self.btn_cancel.config(state="normal")
        self.btn_export.config(state="disabled")
        self.progress["value"] = 0

        self.scanner = Scanner(ScanConfig(depth=self._current_depth()))

        def worker():
            def prog(frac, msg):
                self.msg_queue.put(("progress", frac, msg))
            def on_host(h):
                self.msg_queue.put(("host", h))
            try:
                result = self.scanner.scan(cidr, progress=prog, on_host=on_host)
                self.msg_queue.put(("done", result))
            except Exception as e:  # pragma: no cover
                self.msg_queue.put(("error", str(e)))

        self.scan_thread = threading.Thread(target=worker, daemon=True)
        self.scan_thread.start()

    def _cancel_scan(self):
        if self.scanner:
            self.scanner.cancel()
        self.var_status.set("Abbruch angefordert …")

    def _export(self):
        if not self.hosts:
            return
        fname = exporter.suggested_filename(self.var_kunde.get())
        path = filedialog.asksaveasfilename(
            title="Netzwerkdoku speichern", defaultextension=".xlsx",
            initialfile=fname, filetypes=[("Excel", "*.xlsx")])
        if not path:
            return
        try:
            exporter.export(
                self.hosts, path, template_path=self.template_path,
                kundenname=self.var_kunde.get(), kundennummer=self.var_kundennr.get(),
                installationsdatum=self.var_datum.get())
        except Exception as e:
            messagebox.showerror("Export fehlgeschlagen", str(e))
            return
        if messagebox.askyesno("Fertig",
                               f"Gespeichert:\n{path}\n\nOrdner im Finder öffnen?"):
            try:
                import subprocess
                subprocess.run(["open", "-R", path])
            except Exception:
                pass

    # ------------------------------------------------------------- Queue
    def _add_host_row(self, h: Host):
        ports = ", ".join(str(p) for p in sorted(h.open_ports))
        self.tree.insert("", "end", values=(
            h.ip, h.vendor, h.device_type, h.hostname, h.mac, h.win_function, ports))

    def _poll_queue(self):
        try:
            while True:
                item = self.msg_queue.get_nowait()
                kind = item[0]
                if kind == "progress":
                    _, frac, msg = item
                    self.progress["value"] = frac
                    self.var_status.set(msg)
                elif kind == "host":
                    h = item[1]
                    self.hosts.append(h)
                    self._add_host_row(h)
                    self.var_count.set(f"{len(self.hosts)} Geräte")
                elif kind == "done":
                    self.hosts = item[1] or self.hosts
                    self._finish_scan()
                elif kind == "error":
                    messagebox.showerror("Scan-Fehler", item[1])
                    self._finish_scan()
        except queue.Empty:
            pass
        self.after(120, self._poll_queue)

    def _finish_scan(self):
        self.btn_scan.config(state="normal")
        self.btn_cancel.config(state="disabled")
        if self.hosts:
            self.btn_export.config(state="normal")
        self.var_count.set(f"{len(self.hosts)} Geräte")


def main():
    App().mainloop()


if __name__ == "__main__":
    main()
