"""
Tkinter-Oberfläche für den Netzwerk-Scanner – modernes, helles Theme.

Der Scan läuft in einem Hintergrund-Thread; Fortschritt und Ergebnisse
werden über eine Queue an den GUI-Thread gemeldet (Tk ist nicht
thread-sicher).
"""

from __future__ import annotations

import datetime
import ipaddress
import json
import os
import queue
import subprocess
import sys
import threading
import tkinter as tk
import tkinter.font as tkfont
import webbrowser
from tkinter import filedialog, messagebox, ttk
from typing import List, Optional

from . import __app_name__, __version__
from . import exporter
from . import update as update_check
from .oui import database_size
from .scanner import Host, ScanConfig, Scanner, guess_local_network

# --- Farbpalette (modern, hell) -------------------------------------------
BG = "#EEF1F7"        # Fensterhintergrund
CARD = "#FFFFFF"      # Kartenflächen
ACCENT = "#2482F9"    # Akzent (Blau, wie App-Icon)
ACCENT_DK = "#1B5FBE"
TEXT = "#1E2430"
MUTED = "#6B7280"
BORDER = "#DCE1EA"
SHADOW = "#D2D8E4"    # dezenter Kartenschatten
STRIPE = "#F3F7FE"    # Zebra-Zeile
HOVER = "#E3EEFF"     # Zeile unter dem Mauszeiger
HEAD_BG = "#0E2A4A"   # Tabellenkopf dunkelblau
SEL = "#CFE3FF"       # Auswahl


class RoundedCard(tk.Frame):
    """Karte mit abgerundeten Ecken und dezentem Schatten (Canvas-Hintergrund).

    `expand=False` (Standard) misst die Höhe selbst am Inhalt (für Karten,
    die nur so hoch wie ihr Inhalt sein sollen). `expand=True` übernimmt die
    vom Layout zugewiesene Höhe (für Karten, die den Restplatz füllen, z.B.
    die Ergebnistabelle).
    """

    def __init__(self, parent, pad=16, radius=14, expand=False,
                 bg_color=CARD, border_color=BORDER):
        super().__init__(parent, bg=BG)
        self._pad = pad
        self._radius = radius
        self._expand = expand
        self._bg_color = bg_color
        self._border_color = border_color
        self.canvas = tk.Canvas(self, bg=BG, highlightthickness=0, bd=0)
        self.canvas.pack(fill="both", expand=True)
        self.body = tk.Frame(self.canvas, bg=bg_color)
        self._win = self.canvas.create_window(pad, pad, anchor="nw", window=self.body)
        self.canvas.bind("<Configure>", self._redraw)

    def _round_points(self, x1, y1, x2, y2, r):
        r = max(0, min(r, (x2 - x1) / 2, (y2 - y1) / 2))
        return [x1 + r, y1, x2 - r, y1, x2, y1, x2, y1 + r,
                x2, y2 - r, x2, y2, x2 - r, y2, x1 + r, y2,
                x1, y2, x1, y2 - r, x1, y1 + r, x1, y1]

    def _redraw(self, event=None):
        w = self.canvas.winfo_width()
        if self._expand:
            h = self.canvas.winfo_height()
        else:
            h = self.body.winfo_reqheight() + 2 * self._pad + 4
            if self.canvas.winfo_reqheight() != h:
                self.canvas.configure(height=h)
        if w < 8 or h < 8:
            return
        self.canvas.delete("shape")
        r = self._radius
        self.canvas.create_polygon(
            self._round_points(2, 3, w - 2, h - 1, r),
            smooth=True, fill=SHADOW, outline="", tags="shape")
        self.canvas.create_polygon(
            self._round_points(0, 0, w - 4, h - 4, r),
            smooth=True, fill=self._bg_color, outline=self._border_color,
            width=1, tags="shape")
        self.canvas.tag_lower("shape")
        self.canvas.coords(self._win, self._pad, self._pad)
        self.canvas.itemconfig(
            self._win,
            width=max(w - 4 - 2 * self._pad, 1),
            height=max(h - 4 - 2 * self._pad, 1))

DEPTH_LABELS = {
    "schnell": "Schnell (nur wichtigste Ports)",
    "standard": "Standard",
    "gruendlich": "Gründlich (alle Ports + Banner)",
}
DEPTH_ORDER = ["schnell", "standard", "gruendlich"]

# Ports, bei denen ein Doppelklick/Hover auf die Web-Oberfläche hinweist.
WEB_PORTS = {80, 443, 8080, 8443}

# Session-Persistenz (letzter Scan wird beim Beenden gesichert).
if sys.platform == "win32":
    SESSION_DIR = os.path.join(os.environ.get("APPDATA", os.path.expanduser("~")), "Netzwerk-Scanner")
else:
    SESSION_DIR = os.path.expanduser("~/Library/Application Support/Netzwerk-Scanner")
SESSION_FILE = os.path.join(SESSION_DIR, "last_session.json")

# Spalten: (key, Überschrift, Breite, Ausrichtung)
TREE_COLUMNS = [
    ("icon", "", 40, "center"),
    ("ip", "IP-Adresse", 120, "w"),
    ("vendor", "Hersteller", 160, "w"),
    ("device", "Gerätetyp", 190, "w"),
    ("hostname", "Netzwerkname", 170, "w"),
    ("mac", "MAC-Adresse", 140, "w"),
    ("winfunc", "Windows-Funktion", 150, "w"),
    ("ports", "Offene Ports", 150, "w"),
]


def reveal_in_file_manager(path: str):
    """Zeigt eine Datei im Finder (macOS) bzw. Explorer (Windows) an."""
    try:
        if sys.platform == "win32":
            subprocess.run(["explorer", f"/select,{path}"])
        else:
            subprocess.run(["open", "-R", path])
    except Exception:
        pass


def device_emoji(device_type: str, os_hint: str = "") -> str:
    d = (device_type or "").lower()
    if "drucker" in d:
        return "🖨"
    if "nas" in d or "fileserver" in d:
        return "🗄"
    if "router" in d or "gateway" in d:
        return "🌐"
    if "voip" in d or "telefon" in d:
        return "☎"
    if "kartenleser" in d or "ti-" in d:
        return "💳"
    if "server" in d:
        return "🖧"
    if "virtuelle" in d:
        return "🫙"
    if "mac" in d:
        return "🍎"
    if "pc" in d or "workstation" in d or os_hint == "Windows":
        return "🖥"
    if "handy" in d or "phone" in d or "iphone" in d:
        return "📱"
    return "🔵"


class App(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title(f"{__app_name__} {__version__}")
        self.geometry("1120x720")
        self.minsize(940, 600)
        self.configure(bg=BG)

        self.scanner: Optional[Scanner] = None
        self.scan_thread: Optional[threading.Thread] = None
        self.hosts: List[Host] = []
        self.template_path = None  # None = eingebaute Vorlage
        self.msg_queue: "queue.Queue" = queue.Queue()
        self._icon_img = None
        self._sort_state = {}
        self._sort_col = None
        self._sort_dir = False
        self._hover_item = None
        self._item_host = {}  # Tree-Item-ID -> Host
        self._last_status = f"Bereit · OUI-Datenbank: {database_size()} Hersteller"

        self._init_fonts()
        self._init_style()
        self._build_ui()
        self._set_window_icon()
        self.protocol("WM_DELETE_WINDOW", self._on_close)
        self.after(100, self._poll_queue)
        self.after(50, self._maybe_restore_session)
        threading.Thread(target=self._check_update_bg, daemon=True).start()

    # ------------------------------------------------------------- Styling
    def _init_fonts(self):
        avail = set(tkfont.families())
        family = "TkDefaultFont"
        for candidate in ("Segoe UI Variable", "Segoe UI", "SF Pro Text",
                          "Helvetica Neue", "Helvetica", "Arial"):
            if candidate in avail:
                family = candidate
                break
        self.f_base = tkfont.Font(family=family, size=13)
        self.f_small = tkfont.Font(family=family, size=11)
        self.f_bold = tkfont.Font(family=family, size=13, weight="bold")
        self.f_row = tkfont.Font(family=family, size=12)
        self.f_head = tkfont.Font(family=family, size=12, weight="bold")

    def _init_style(self):
        style = ttk.Style(self)
        style.theme_use("clam")  # voll gestaltbar (im Gegensatz zu 'aqua')

        style.configure(".", background=BG, foreground=TEXT, font=self.f_base)
        style.configure("TFrame", background=BG)
        style.configure("Card.TFrame", background=CARD)
        style.configure("TLabel", background=CARD, foreground=TEXT, font=self.f_base)
        style.configure("Win.TLabel", background=BG, foreground=TEXT)
        style.configure("Muted.TLabel", background=CARD, foreground=MUTED, font=self.f_small)
        style.configure("CardTitle.TLabel", background=CARD, foreground=ACCENT_DK,
                        font=self.f_bold)
        style.configure("Accentval.TLabel", background=CARD, foreground=ACCENT,
                        font=self.f_bold)

        # Eingaben
        style.configure("TEntry", fieldbackground="#FBFCFE", bordercolor=BORDER,
                        relief="flat", padding=5)
        style.configure("TCombobox", fieldbackground="#FBFCFE", bordercolor=BORDER,
                        padding=4)
        style.map("TCombobox", fieldbackground=[("readonly", "#FBFCFE")])

        # Buttons
        style.configure("TButton", background="#E7ECF4", foreground=TEXT,
                        bordercolor=BORDER, relief="flat",
                        padding=(12, 6), font=self.f_base)
        style.map("TButton",
                  background=[("active", "#D8E0EC"), ("disabled", "#EFF1F5")],
                  foreground=[("disabled", "#A6ADBB")])
        style.configure("Accent.TButton", background=ACCENT, foreground="#FFFFFF",
                        bordercolor=ACCENT, padding=(16, 7), font=self.f_bold)
        style.map("Accent.TButton",
                  background=[("active", ACCENT_DK), ("disabled", "#A9C6F2")],
                  foreground=[("disabled", "#EAF1FC")])
        style.configure("Link.TButton", background=CARD, foreground=ACCENT,
                        relief="flat", padding=(6, 4), font=self.f_small)
        style.map("Link.TButton", background=[("active", "#EEF4FF")])

        # Fortschritt
        style.configure("Accent.Horizontal.TProgressbar", troughcolor="#E3E8F0",
                        background=ACCENT, bordercolor="#E3E8F0", lightcolor=ACCENT,
                        darkcolor=ACCENT, thickness=10)

        # Tabelle
        style.configure("Treeview", background=CARD, fieldbackground=CARD,
                        foreground=TEXT, rowheight=32, font=self.f_row,
                        bordercolor=BORDER, borderwidth=0)
        style.map("Treeview", background=[("selected", SEL)],
                  foreground=[("selected", TEXT)])
        style.configure("Treeview.Heading", background=HEAD_BG, foreground="#FFFFFF",
                        font=self.f_head, relief="flat", padding=6)
        style.map("Treeview.Heading", background=[("active", "#1C3F66")])

    def _set_window_icon(self):
        for base in (getattr(sys, "_MEIPASS", None),
                     os.path.dirname(os.path.dirname(os.path.abspath(__file__)))):
            if not base:
                continue
            p = os.path.join(base, "assets", "app_icon.png")
            if os.path.exists(p):
                try:
                    self._icon_img = tk.PhotoImage(file=p)
                    self.iconphoto(True, self._icon_img)
                    return
                except Exception:
                    pass

    # ------------------------------------------------------------------ UI
    def _card(self, parent, pad=16, expand=False, radius=14):
        """Weiße Karte mit abgerundeten Ecken und dezentem Schatten."""
        card = RoundedCard(parent, pad=pad, radius=radius, expand=expand)
        return card, card.body

    def _build_ui(self):
        # --- Kopfzeile (nur Update-Button) ------------------------------
        header = tk.Frame(self, bg=BG)
        header.pack(fill="x")
        self._update_info = None  # gesetzt sobald ein Update gefunden wurde
        self.btn_update = tk.Button(
            header, text=f"v{__version__} · Nach Updates suchen", bg="#E7ECF4", fg=TEXT,
            activebackground="#D8E0EC", activeforeground=TEXT, relief="flat",
            font=self.f_small, padx=10, pady=3, cursor="hand2", bd=0, highlightthickness=0,
            command=self._on_update_click)
        self.btn_update.pack(side="right", padx=18, pady=(12, 0))

        wrap = tk.Frame(self, bg=BG)
        wrap.pack(fill="both", expand=True, padx=18, pady=16)

        # --- Kundendaten ----------------------------------------------
        c1, b1 = self._card(wrap)
        c1.pack(fill="x", pady=(0, 14))
        ttk.Label(b1, text="Kundendaten (optional)", style="CardTitle.TLabel").grid(
            row=0, column=0, columnspan=8, sticky="w", pady=(0, 8))
        self.var_kunde = tk.StringVar()
        self.var_kundennr = tk.StringVar()
        self.var_datum = tk.StringVar(value=datetime.date.today().strftime("%d.%m.%Y"))
        self.var_passwort = tk.StringVar()
        ttk.Label(b1, text="Kundenname").grid(row=1, column=0, sticky="w", padx=(0, 6))
        ttk.Entry(b1, textvariable=self.var_kunde, width=26).grid(row=1, column=1, padx=(0, 16))
        ttk.Label(b1, text="Tomedo Kundennr.").grid(row=1, column=2, sticky="w", padx=(0, 6))
        ttk.Entry(b1, textvariable=self.var_kundennr, width=16).grid(row=1, column=3, padx=(0, 16))
        ttk.Label(b1, text="Installationsdatum").grid(row=1, column=4, sticky="w", padx=(0, 6))
        ttk.Entry(b1, textvariable=self.var_datum, width=14).grid(row=1, column=5, padx=(0, 16))
        ttk.Label(b1, text="Passwort").grid(row=1, column=6, sticky="w", padx=(0, 6))
        ttk.Entry(b1, textvariable=self.var_passwort, width=16, show="•").grid(row=1, column=7)
        ttk.Label(b1, text="Verschlüsselt die exportierte Excel-Datei mit diesem Kennwort (Passwortabfrage beim Öffnen), wenn ausgefüllt.",
                 style="Muted.TLabel").grid(row=2, column=0, columnspan=8, sticky="w", pady=(6, 0))

        # --- Scan-Einstellungen ---------------------------------------
        c2, b2 = self._card(wrap)
        c2.pack(fill="x", pady=(0, 14))
        ttk.Label(b2, text="Scan", style="CardTitle.TLabel").grid(
            row=0, column=0, columnspan=8, sticky="w", pady=(0, 8))
        ttk.Label(b2, text="Netzbereich (CIDR)").grid(row=1, column=0, sticky="w", padx=(0, 6))
        self.var_cidr = tk.StringVar(value=guess_local_network())
        ttk.Entry(b2, textvariable=self.var_cidr, width=20).grid(row=1, column=1, padx=(0, 6))
        ttk.Button(b2, text="Erkennen", command=self._detect_net).grid(row=1, column=2, padx=(0, 16))
        ttk.Label(b2, text="Tiefe").grid(row=1, column=3, sticky="w", padx=(0, 6))
        self.var_depth = tk.StringVar(value=DEPTH_LABELS["gruendlich"])
        ttk.Combobox(b2, textvariable=self.var_depth, state="readonly",
                     values=[DEPTH_LABELS[d] for d in DEPTH_ORDER], width=30).grid(
            row=1, column=4, padx=(0, 16))
        self.btn_scan = ttk.Button(b2, text="Scan starten", style="Accent.TButton",
                                   command=self._start_scan)
        self.btn_scan.grid(row=1, column=5, padx=(0, 6))
        self.btn_cancel = ttk.Button(b2, text="Abbrechen", command=self._cancel_scan,
                                     state="disabled")
        self.btn_cancel.grid(row=1, column=6)

        # Vorlage-Zeile
        ttk.Label(b2, text="Excel-Vorlage").grid(row=2, column=0, sticky="w", pady=(10, 0))
        self.var_tpl = tk.StringVar(value="Netzwerkdoku-Vorlage (eingebaut)")
        ttk.Label(b2, textvariable=self.var_tpl, style="Accentval.TLabel").grid(
            row=2, column=1, columnspan=2, sticky="w", pady=(10, 0))
        ttk.Button(b2, text="Andere wählen …", style="Link.TButton",
                   command=self._pick_template).grid(row=2, column=3, sticky="w", pady=(10, 0))
        ttk.Button(b2, text="Zurück zur eingebauten", style="Link.TButton",
                   command=self._reset_template).grid(row=2, column=4, sticky="w", pady=(10, 0))

        # --- Fortschritt ----------------------------------------------
        prog = tk.Frame(wrap, bg=BG)
        prog.pack(fill="x", pady=(0, 8))
        self.progress = ttk.Progressbar(prog, mode="determinate", maximum=1.0,
                                        style="Accent.Horizontal.TProgressbar")
        self.progress.pack(side="left", fill="x", expand=True)
        self.var_status = tk.StringVar(value=f"Bereit · OUI-Datenbank: {database_size()} Hersteller")
        tk.Label(prog, textvariable=self.var_status, bg=BG, fg=MUTED,
                 font=self.f_small, anchor="w", width=52).pack(side="left", padx=12)

        # --- Aktionen (unten fest verankert, verschwindet nie hinter der
        # Tabelle - vor der Tabelle gepackt + side="bottom") -------------
        actions = tk.Frame(wrap, bg=BG)
        actions.pack(side="bottom", fill="x", pady=(10, 0))
        self.var_count = tk.StringVar(value="0 Geräte")
        tk.Label(actions, textvariable=self.var_count, bg=BG, fg=TEXT,
                 font=self.f_bold).pack(side="left")
        self.var_summary = tk.StringVar(value="")
        tk.Label(actions, textvariable=self.var_summary, bg=BG, fg=MUTED,
                 font=self.f_small).pack(side="left", padx=12)
        self.btn_export = ttk.Button(actions, text="In Excel exportieren …",
                                     style="Accent.TButton", command=self._export,
                                     state="disabled")
        self.btn_export.pack(side="right")

        # --- Ergebnis-Tabelle -----------------------------------------
        c3, b3 = self._card(wrap, pad=4, expand=True)
        c3.pack(fill="both", expand=True)

        filter_row = tk.Frame(b3, bg=CARD)
        filter_row.pack(fill="x", padx=8, pady=(8, 4))
        ttk.Label(filter_row, text="Filter/Suche").pack(side="left", padx=(0, 6))
        self.var_filter = tk.StringVar()
        filter_entry = ttk.Entry(filter_row, textvariable=self.var_filter, width=40)
        filter_entry.pack(side="left")
        filter_entry.bind("<KeyRelease>", self._apply_filter)

        tree_frame = tk.Frame(b3, bg=CARD)
        tree_frame.pack(fill="both", expand=True)
        cols = [c[0] for c in TREE_COLUMNS]
        self.tree = ttk.Treeview(tree_frame, columns=cols, show="headings", selectmode="browse")
        for key, label, width, anchor in TREE_COLUMNS:
            if key == "icon":
                self.tree.heading(key, text=label)
            else:
                self.tree.heading(key, text=label, command=lambda k=key: self._sort_by(k))
            self.tree.column(key, width=width, anchor=anchor,
                             stretch=(key in ("device", "hostname", "vendor")))
        self._col_labels = {k: label for k, label, *_ in TREE_COLUMNS}
        self.tree.tag_configure("odd", background=CARD)
        self.tree.tag_configure("even", background=STRIPE)
        self.tree.tag_configure("muted", foreground=MUTED)
        self.tree.tag_configure("hover", background=HOVER)
        vsb = ttk.Scrollbar(tree_frame, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscrollcommand=vsb.set)
        self.tree.pack(side="left", fill="both", expand=True)
        vsb.pack(side="right", fill="y")
        self.tree.bind("<Double-1>", self._on_double_click)
        self.tree.bind("<Button-2>", self._show_context_menu)
        self.tree.bind("<Button-3>", self._show_context_menu)
        self.tree.bind("<Motion>", self._on_tree_motion)
        self.tree.bind("<Leave>", self._on_tree_leave)

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
            ipaddress.ip_network(cidr, strict=False)
        except ValueError:
            messagebox.showerror("Ungültiger Netzbereich",
                                 f"'{cidr}' ist kein gültiges CIDR-Netz (z.B. 192.168.1.0/24).")
            return

        self.hosts = []
        self._item_host = {}
        self.tree.delete(*self.tree.get_children())
        self.var_count.set("0 Geräte")
        self.var_summary.set("")
        self.btn_scan.config(state="disabled")
        self.btn_cancel.config(state="normal")
        self.btn_export.config(state="disabled")
        self.progress["value"] = 0

        self.scanner = Scanner(ScanConfig(depth=self._current_depth()))

        def worker():
            try:
                result = self.scanner.scan(
                    cidr,
                    progress=lambda f, m: self.msg_queue.put(("progress", f, m)),
                    on_host=lambda h: self.msg_queue.put(("host", h)))
                self.msg_queue.put(("done", result))
            except Exception as e:  # pragma: no cover
                self.msg_queue.put(("error", str(e)))

        self.scan_thread = threading.Thread(target=worker, daemon=True)
        self.scan_thread.start()

    def _cancel_scan(self):
        if self.scanner:
            self.scanner.cancel()
        self.var_status.set("Abbruch angefordert …")

    # --------------------------------------------------- Session-Persistenz
    def _on_close(self):
        if self.scan_thread and self.scan_thread.is_alive():
            self._cancel_scan()
        if self.hosts:
            self._save_session()
        self.destroy()

    def _save_session(self):
        try:
            os.makedirs(SESSION_DIR, exist_ok=True)
            data = {
                "kunde": self.var_kunde.get(),
                "kundennr": self.var_kundennr.get(),
                "datum": self.var_datum.get(),
                "hosts": [h.to_dict() for h in self.hosts],
            }
            with open(SESSION_FILE, "w", encoding="utf-8") as f:
                json.dump(data, f, ensure_ascii=False, indent=2)
        except Exception:
            pass  # Session-Sicherung ist ein Komfortfeature, kein Beinbruch

    def _maybe_restore_session(self):
        if not os.path.exists(SESSION_FILE):
            return
        if not messagebox.askyesno("Sitzung wiederherstellen",
                                   "Letzten Scan wiederherstellen?"):
            return
        try:
            with open(SESSION_FILE, "r", encoding="utf-8") as f:
                data = json.load(f)
            self.var_kunde.set(data.get("kunde", ""))
            self.var_kundennr.set(data.get("kundennr", ""))
            self.var_datum.set(data.get("datum", ""))
            self.hosts = [Host.from_dict(d) for d in data.get("hosts", [])]
            self._rebuild_tree()
            self._set_counts()
            if self.hosts:
                self.btn_export.config(state="normal")
            self._update_summary()
        except Exception as e:
            messagebox.showerror("Wiederherstellen fehlgeschlagen", str(e))

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
                installationsdatum=self.var_datum.get(), passwort=self.var_passwort.get())
        except Exception as e:
            messagebox.showerror("Export fehlgeschlagen", str(e))
            return
        if messagebox.askyesno("Fertig",
                               f"Gespeichert:\n{path}\n\nIm Finder anzeigen?"):
            reveal_in_file_manager(path)

    # ------------------------------------------------------- Tabelle/Events
    def _row_values(self, h: Host):
        ports = ", ".join(str(p) for p in sorted(h.open_ports))
        icon = "⚠" if h.scan_warning else device_emoji(h.device_type, h.os_hint)
        return (icon, h.ip, h.vendor,
                h.device_type, h.hostname, h.mac, h.win_function, ports)

    def _add_host_row(self, h: Host):
        tag = "even" if len(self.tree.get_children()) % 2 else "odd"
        tags = (tag, "muted") if h.ignored else (tag,)
        item = self.tree.insert("", "end", values=self._row_values(h), tags=tags)
        self._item_host[item] = h

    def _restripe(self):
        for i, item in enumerate(self.tree.get_children()):
            self.tree.item(item, tags=("even" if i % 2 else "odd",))

    def _matches_filter(self, h: Host, q: str) -> bool:
        haystacks = (h.ip, h.vendor, h.device_type, h.hostname, h.mac)
        return any(q in (v or "").lower() for v in haystacks)

    def _rebuild_tree(self):
        q = self.var_filter.get().strip().lower() if hasattr(self, "var_filter") else ""
        self.tree.delete(*self.tree.get_children())
        self._item_host = {}
        for h in self.hosts:
            if q and not self._matches_filter(h, q):
                continue
            self._add_host_row(h)

    def _apply_filter(self, event=None):
        self._rebuild_tree()

    def _has_web_port(self, h: Host) -> bool:
        return bool(WEB_PORTS & set(h.open_ports))

    def _set_counts(self):
        n = len(self.hosts)
        ignored = sum(1 for h in self.hosts if h.ignored)
        text = f"{n} Geräte" + (f" ({ignored} ignoriert)" if ignored else "")
        self.var_count.set(text)

    def _sort_by(self, key):
        idx = [c[0] for c in TREE_COLUMNS].index(key)
        reverse = self._sort_state.get(key, False)

        def sort_key(h):
            v = self._row_values(h)[idx]
            if key == "ip":
                try:
                    return (0, int(ipaddress.ip_address(h.ip)))
                except ValueError:
                    return (1, 0)
            return (str(v) == "", str(v).lower())

        self.hosts.sort(key=sort_key, reverse=reverse)
        self._sort_state[key] = not reverse
        self._sort_col, self._sort_dir = key, reverse
        self._update_sort_headers()
        self._rebuild_tree()

    def _update_sort_headers(self):
        for key, label in self._col_labels.items():
            if key == "icon":
                continue
            if key == self._sort_col:
                label += " ▼" if self._sort_dir else " ▲"
            self.tree.heading(key, text=label)

    def _on_double_click(self, event):
        item = self.tree.identify_row(event.y)
        h = self._item_host.get(item) if item else None
        if not h or not self._has_web_port(h):
            return
        scheme = "https" if (443 in h.open_ports or 8443 in h.open_ports) else "http"
        webbrowser.open(f"{scheme}://{h.ip}")

    def _show_context_menu(self, event):
        item = self.tree.identify_row(event.y)
        if not item:
            return
        h = self._item_host.get(item)
        if h is None:
            return
        self.tree.selection_set(item)
        menu = tk.Menu(self, tearoff=0)
        menu.add_command(label="Bearbeiten…", command=lambda: self._edit_host(h))
        label = "Nicht mehr ignorieren" if h.ignored else "Ignorieren"
        menu.add_command(label=label, command=lambda: self._toggle_ignored(h))
        try:
            menu.tk_popup(event.x_root, event.y_root)
        finally:
            menu.grab_release()

    def _toggle_ignored(self, h: Host):
        h.ignored = not h.ignored
        self._rebuild_tree()
        self._set_counts()

    def _edit_host(self, h: Host):
        dlg = tk.Toplevel(self)
        dlg.title(f"Bearbeiten – {h.ip}")
        dlg.configure(bg=BORDER)
        dlg.transient(self)
        dlg.resizable(False, False)
        inner = tk.Frame(dlg, bg=CARD)
        inner.pack(fill="both", expand=True, padx=1, pady=1)
        body = tk.Frame(inner, bg=CARD)
        body.pack(fill="both", expand=True, padx=18, pady=16)

        title = h.hostname or h.vendor or h.device_type or "Gerät"
        ttk.Label(body, text=f"{h.ip} · {title}", style="CardTitle.TLabel").grid(
            row=0, column=0, columnspan=2, sticky="w", pady=(0, 12))

        var_standort = tk.StringVar(value=h.standort)
        var_user = tk.StringVar(value=h.user)
        var_verbunden = tk.StringVar(value=h.angebunden_an)
        var_eingerichtet = tk.StringVar(value=h.eingerichtet_von)
        rows = [
            ("Standort", var_standort),
            ("User", var_user),
            ("angebunden an", var_verbunden),
            ("eingerichtet von", var_eingerichtet),
        ]
        for i, (label, var) in enumerate(rows, start=1):
            ttk.Label(body, text=label).grid(row=i, column=0, sticky="w", padx=(0, 10), pady=4)
            ttk.Entry(body, textvariable=var, width=28).grid(row=i, column=1, pady=4)

        def save():
            h.standort = var_standort.get()
            h.user = var_user.get()
            h.angebunden_an = var_verbunden.get()
            h.eingerichtet_von = var_eingerichtet.get()
            dlg.destroy()

        btns = tk.Frame(body, bg=CARD)
        btns.grid(row=len(rows) + 1, column=0, columnspan=2, sticky="e", pady=(14, 0))
        ttk.Button(btns, text="Abbrechen", command=dlg.destroy).pack(side="right", padx=(6, 0))
        ttk.Button(btns, text="Speichern", style="Accent.TButton", command=save).pack(side="right")
        dlg.grab_set()

    def _on_tree_motion(self, event):
        item = self.tree.identify_row(event.y)
        h = self._item_host.get(item) if item else None
        self.var_status.set(h.scan_warning if (h and h.scan_warning) else self._last_status)
        self.tree.configure(cursor="hand2" if (h and self._has_web_port(h)) else "")
        self._set_hover(item)

    def _on_tree_leave(self, event):
        self.var_status.set(self._last_status)
        self.tree.configure(cursor="")
        self._set_hover(None)

    def _set_hover(self, item):
        if item == self._hover_item:
            return
        if self._hover_item and self.tree.exists(self._hover_item):
            tags = tuple(t for t in self.tree.item(self._hover_item, "tags") if t != "hover")
            self.tree.item(self._hover_item, tags=tags)
        if item:
            tags = tuple(t for t in self.tree.item(item, "tags") if t != "hover") + ("hover",)
            self.tree.item(item, tags=tags)
        self._hover_item = item

    def _update_summary(self):
        from collections import Counter
        c = Counter(h.device_type or "Unbekannt" for h in self.hosts)
        top = ", ".join(f"{v}× {k}" for k, v in c.most_common(4))
        self.var_summary.set(top)

    # ------------------------------------------------------------- Queue
    def _poll_queue(self):
        try:
            while True:
                item = self.msg_queue.get_nowait()
                kind = item[0]
                if kind == "progress":
                    _, frac, msg = item
                    self.progress["value"] = frac
                    self.var_status.set(msg)
                    self._last_status = msg
                elif kind == "host":
                    h = item[1]
                    self.hosts.append(h)
                    self._add_host_row(h)
                    self._set_counts()
                elif kind == "done":
                    self.hosts = item[1] or self.hosts
                    self._finish_scan()
                elif kind == "error":
                    messagebox.showerror("Scan-Fehler", item[1])
                    self._finish_scan()
                elif kind == "update":
                    self._on_update_result(item[1], manual=item[2], error=item[3])
                elif kind == "install_progress":
                    _, frac, msg = item
                    self.btn_update.config(text=msg)
                elif kind == "install_done":
                    self._relaunch_after_update(item[1])
                elif kind == "install_error":
                    self._install_update_failed(item[1])
        except queue.Empty:
            pass
        self.after(120, self._poll_queue)

    # ------------------------------------------------------------ Update
    def _check_update_bg(self, manual: bool = False):
        # Beim stillen Auto-Check (Programmstart) ist ein Netzwerkfehler
        # normal und wird ignoriert. Beim manuellen Klick soll ein echter
        # Fehlschlag NICHT als "kein Update" erscheinen, sondern angezeigt
        # werden - sonst denkt der Nutzer fälschlich, er sei aktuell.
        if manual:
            try:
                info = update_check.check_for_update_or_raise()
                self.msg_queue.put(("update", info, manual, None))
            except Exception as e:
                self.msg_queue.put(("update", None, manual, str(e)))
        else:
            info = update_check.check_for_update()
            self.msg_queue.put(("update", info, manual, None))

    def _on_update_click(self):
        if self._update_info:
            self._confirm_and_install()
            return
        self.btn_update.config(text="Prüfe …", state="disabled")
        threading.Thread(target=self._check_update_bg, args=(True,), daemon=True).start()

    def _on_update_result(self, info: Optional[dict], manual: bool, error: Optional[str] = None):
        self.btn_update.config(state="normal")
        if info:
            self._update_info = info
            self.btn_update.config(text=f"Update verfügbar: v{info['version']}",
                                   bg="#FFC942", fg="#3A2A00",
                                   activebackground="#F5B900")
        elif manual and error:
            self.btn_update.config(text=f"v{__version__} · Prüfung fehlgeschlagen")
            messagebox.showwarning(
                "Update-Prüfung fehlgeschlagen",
                f"GitHub konnte nicht erreicht werden:\n{error}\n\n"
                "Kein Internet, oder GitHub gerade nicht erreichbar.")
            self.after(3000, lambda: self.btn_update.config(
                text=f"v{__version__} · Nach Updates suchen"))
        elif manual:
            self.btn_update.config(text=f"v{__version__} · aktuell")
            self.after(3000, lambda: self.btn_update.config(
                text=f"v{__version__} · Nach Updates suchen"))
        # Stiller Auto-Check ohne Ergebnis: Button bleibt wie er ist.

    def _confirm_and_install(self):
        info = self._update_info
        if sys.platform != "darwin":
            # Automatisches Ersetzen ist macOS-spezifisch (.app-Bundle,
            # hdiutil/ditto). Auf Windows bleibt es beim sicheren Rückfall:
            # Release-Seite öffnen, Installer manuell ausführen.
            webbrowser.open(info["url"])
            return
        notes = f"\n\n{info['notes']}" if info.get("notes") else ""
        if not messagebox.askyesno(
                "Update installieren",
                f"Version {info['version']} jetzt herunterladen und installieren?\n"
                f"Die App startet danach neu.{notes}"):
            return
        self.btn_update.config(state="disabled")
        threading.Thread(target=self._install_update_bg, args=(info,), daemon=True).start()

    def _install_update_bg(self, info: dict):
        try:
            new_path = update_check.install_update(
                info, progress=lambda f, m: self.msg_queue.put(("install_progress", f, m)))
            self.msg_queue.put(("install_done", new_path))
        except Exception as e:
            self.msg_queue.put(("install_error", str(e)))

    def _relaunch_after_update(self, app_path: str):
        subprocess.Popen(["open", app_path])
        self._on_close()

    def _install_update_failed(self, error: str):
        self.btn_update.config(state="normal", text=f"Update verfügbar: v{self._update_info['version']}")
        if messagebox.askyesno(
                "Installation fehlgeschlagen",
                f"Automatische Installation fehlgeschlagen:\n{error}\n\n"
                "Stattdessen die Release-Seite im Browser öffnen (manueller Download)?"):
            webbrowser.open(self._update_info["url"])

    def _finish_scan(self):
        self.btn_scan.config(state="normal")
        self.btn_cancel.config(state="disabled")
        if self.hosts:
            self.btn_export.config(state="normal")
        self._set_counts()
        self._update_summary()


def main():
    App().mainloop()


if __name__ == "__main__":
    main()
