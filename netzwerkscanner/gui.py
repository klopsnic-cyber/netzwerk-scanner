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
import traceback
import tkinter as tk
import tkinter.font as tkfont
import webbrowser
from tkinter import filedialog, messagebox, simpledialog, ttk
from typing import List, Optional

from . import __app_name__, __version__
from . import exporter
from . import update as update_check
from .oui import database_size
from .scanner import Host, ScanConfig, Scanner, guess_local_network, hosts_in_network, _MAC_DOPPELT

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

# Session-Persistenz (Sitzung wird nach Scan/Bearbeitung/Kundendaten-Änderung gesichert).
if sys.platform == "win32":
    SESSION_DIR = os.path.join(os.environ.get("APPDATA", os.path.expanduser("~")), "Netzwerk-Scanner")
else:
    SESSION_DIR = os.path.expanduser("~/Library/Application Support/Netzwerk-Scanner")
SESSION_FILE = os.path.join(SESSION_DIR, "last_session.json")

# Spalten: (key, Überschrift, Breite, Ausrichtung)
TREE_COLUMNS = [
    ("icon", "", 36, "center"),
    ("ip", "IP-Adresse", 110, "w"),
    ("vendor", "Hersteller", 140, "w"),
    ("device", "Gerätetyp", 150, "w"),
    ("hostname", "Netzwerkname", 140, "w"),
    ("mac", "MAC-Adresse", 130, "w"),
    ("winfunc", "Windows-Funktion", 130, "w"),
    ("ports", "Offene Ports", 120, "w"),
    ("warn", "Hinweis", 150, "w"),
]

MAC_PRIVACY_URL = "x-apple.systempreferences:com.apple.preference.security?Privacy_LocalNetwork"
NO_NET_HINT = "Kein Netzwerk erkannt – bitte Netz eintragen (z. B. 192.168.1.0/24)"
GONE_WARNING = "Diesmal nicht erreichbar (Handeingaben behalten)"
if sys.platform == "darwin":
    PERM_HINT = ("Keine/kaum Geräte gefunden. macOS: Systemeinstellungen → Datenschutz & Sicherheit → "
                 "Lokales Netzwerk → Netzwerk-Scanner erlauben; außerdem Netzbereich und Verbindung "
                 "(nicht Gast-WLAN/VPN) prüfen.")
else:
    PERM_HINT = ("Keine/kaum Geräte gefunden. Bitte Firewall (Netzwerk-Scanner erlauben), VPN und "
                 "den gewählten Netzbereich prüfen; Rechner muss im Praxisnetz sein (nicht Gast-WLAN).")


def reveal_in_file_manager(path: str):
    """Zeigt eine Datei im Finder (macOS) bzw. Explorer (Windows) an."""
    try:  # Popen: nicht blockieren (explorer liefert ohnehin Exitcode 1)
        if sys.platform == "win32":
            subprocess.Popen(["explorer", f"/select,{path}"])
        else:
            subprocess.Popen(["open", "-R", path])
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
        return "▦"
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
        sw, sh = self.winfo_screenwidth(), self.winfo_screenheight()
        self.geometry(f"{min(1120, sw - 40)}x{min(720, sh - 110)}")
        self.minsize(min(960, sw), min(540, sh - 60))  # passt auch auf 1366x768
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
        # Handeingaben pro Gerät (IP und/oder MAC), über mehrere Scans gesammelt
        self._notes: List[dict] = []
        self._prev_hosts: List[Host] = []   # Ergebnis vor dem laufenden Scan
        self._scanning = False
        self._cancel_requested = False
        self._scan_cidr = ""
        self._save_job = None
        self._session_pending = False       # Datei bleibt unberührt, bis bestätigt
        self._pending_data = None
        self._notices: dict = {}            # Schlüssel -> dauerhafter Hinweistext
        self._error_seen = set()
        self.report_callback_exception = self._tk_exception

        self._init_fonts()
        self._init_style()
        self._build_ui()
        self._set_window_icon()
        self.protocol("WM_DELETE_WINDOW", self._on_close)
        self.after(100, self._poll_queue)
        self.after(50, self._maybe_restore_session)
        for v in (self.var_kunde, self.var_kundennr, self.var_datum):
            v.trace_add("write", lambda *a: self._schedule_save())
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
        self.ent_pw = ttk.Entry(b1, textvariable=self.var_passwort, width=16, show="•")
        self.ent_pw.grid(row=1, column=7, padx=(0, 6))
        self.var_show_pw = tk.BooleanVar(value=False)
        ttk.Checkbutton(b1, text="anzeigen", variable=self.var_show_pw,
                        command=lambda: self.ent_pw.config(show="" if self.var_show_pw.get() else "•")
                        ).grid(row=1, column=8)
        ttk.Label(b1, text="Verschlüsselt die exportierte Excel-Datei mit diesem Kennwort (Passwortabfrage beim Öffnen), wenn ausgefüllt.",
                 style="Muted.TLabel").grid(row=2, column=0, columnspan=9, sticky="w", pady=(6, 0))

        # --- Scan-Einstellungen ---------------------------------------
        c2, b2 = self._card(wrap)
        c2.pack(fill="x", pady=(0, 14))
        ttk.Label(b2, text="Scan", style="CardTitle.TLabel").grid(
            row=0, column=0, columnspan=8, sticky="w", pady=(0, 8))
        ttk.Label(b2, text="Netzbereich (CIDR)").grid(row=1, column=0, sticky="w", padx=(0, 6))
        self.var_cidr = tk.StringVar(value=self._guess_net())
        ent_cidr = ttk.Entry(b2, textvariable=self.var_cidr, width=20)
        ent_cidr.grid(row=1, column=1, padx=(0, 6))
        ent_cidr.bind("<Return>", lambda e: self._start_scan())
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
        status_row = tk.Frame(wrap, bg=BG)
        status_row.pack(fill="x", pady=(0, 6))
        self.lbl_status = tk.Label(status_row, textvariable=self.var_status, bg=BG, fg=MUTED,
                                   font=self.f_small, anchor="w", justify="left")
        self.lbl_status.pack(fill="x")
        # Dauerhafte Hinweise (Berechtigung, Scan-Probleme, Speicherfehler …)
        self.notice_row = tk.Frame(wrap, bg="#FFF4D6", highlightbackground="#F0D58A",
                                   highlightthickness=1)
        self.lbl_notice = tk.Label(self.notice_row, text="", bg="#FFF4D6", fg="#6B4A00",
                                   font=self.f_small, anchor="w", justify="left")
        self.lbl_notice.pack(side="left", fill="x", expand=True, padx=8, pady=4)
        self.btn_perm = tk.Button(self.notice_row, text="Einstellungen öffnen", relief="flat",
                                  font=self.f_small, bd=0, highlightthickness=0, padx=8,
                                  command=lambda: subprocess.Popen(["open", MAC_PRIVACY_URL]))
        self._status_row = status_row

        def _wrap(e):
            self.lbl_status.config(wraplength=max(e.width - 20, 200))
            self.lbl_notice.config(wraplength=max(e.width - 200, 200))
        wrap.bind("<Configure>", _wrap)
        self._refresh_notice()

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
                             stretch=(key in ("device", "hostname", "vendor", "warn")))
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
        self.tree.bind("<Control-Button-1>", self._show_context_menu)  # macOS
        self.tree.bind("<Return>", self._edit_selected)
        self.tree.bind("<KP_Enter>", self._edit_selected)
        self.tree.bind("<Shift-F10>", self._menu_for_selection)
        for seq in ("<App>", "<Menu>"):  # Menütaste (je nach Plattform gültig)
            try:
                self.tree.bind(seq, self._menu_for_selection)
            except tk.TclError:
                pass
        self.tree.bind("<Motion>", self._on_tree_motion)
        self.tree.bind("<Leave>", self._on_tree_leave)

    def _guess_net(self) -> str:
        """Lokales Netz oder "" (dann Hinweis statt 127.x/Phantomnetz)."""
        try:
            cidr = guess_local_network() or ""
        except Exception:
            cidr = ""
        if cidr.startswith("127."):
            cidr = ""
        self._notices["net"] = "" if cidr else NO_NET_HINT
        if hasattr(self, "lbl_notice"):
            self._refresh_notice()
        return cidr

    def _detect_net(self):
        self.var_cidr.set(self._guess_net())

    # ------------------------------------------------- Hinweise / Fehler
    def _refresh_notice(self):
        text = "\n".join(t for t in self._notices.values() if t)
        self.lbl_notice.config(text=text)
        if text:
            self.notice_row.pack(fill="x", pady=(0, 6), after=self._status_row)
        else:
            self.notice_row.pack_forget()
        if sys.platform == "darwin" and self._notices.get("perm"):
            self.btn_perm.pack(side="right", padx=6, pady=3)
        else:
            self.btn_perm.pack_forget()

    def _set_notice(self, key: str, text: str):
        if self._notices.get(key, "") != text:
            self._notices[key] = text
            self._refresh_notice()

    def _log_error(self, context: str, exc: BaseException) -> str:
        """Schreibt einen Fehler (ohne Eingaben/Passwörter) ins Log, gibt den Pfad zurück."""
        path = os.path.join(SESSION_DIR, "fehler.log")
        try:
            os.makedirs(SESSION_DIR, exist_ok=True)
            if os.path.exists(path) and os.path.getsize(path) > 256 * 1024:
                os.replace(path, path + ".alt")
            with open(path, "a", encoding="utf-8") as f:
                f.write(f"--- {datetime.datetime.now():%Y-%m-%d %H:%M:%S} {__version__} {context}\n")
                f.write("".join(traceback.format_exception(type(exc), exc, exc.__traceback__)))
        except Exception:
            pass
        return path

    def _report_error(self, context: str, exc: BaseException):
        path = self._log_error(context, exc)
        key = f"{context}:{exc}"
        if key not in self._error_seen:  # gleiche Meldung nur einmal anzeigen
            self._error_seen.add(key)
            self._set_notice("error", f"Interner Fehler: {exc} (Details in {path})")

    def _tk_exception(self, exc_type, exc, tb):
        exc.__traceback__ = tb
        self._report_error("Tk-Callback", exc)

    # ------------------------------------------------------------- Aktionen
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

    def _scan_was_cancelled(self) -> bool:
        flag = getattr(self.scanner, "cancelled", None)
        if flag is None and self.scanner is not None:
            flag = self.scanner._cancel.is_set()
        return bool(flag) or self._cancel_requested

    def _start_scan(self):
        if self.scan_thread and self.scan_thread.is_alive():
            return
        cidr = self.var_cidr.get().strip()
        if not cidr:
            messagebox.showerror("Netzbereich fehlt", NO_NET_HINT)
            return
        try:
            net = ipaddress.ip_network(cidr, strict=False)
        except ValueError:
            messagebox.showerror("Ungültiger Netzbereich",
                                 f"'{cidr}' ist kein gültiges CIDR-Netz (z.B. 192.168.1.0/24).")
            return
        try:
            hosts_in_network(cidr)  # wirft ValueError mit deutscher Meldung (IPv6/zu groß)
        except ValueError as e:
            messagebox.showerror("Netzbereich nicht möglich", str(e))
            return
        if net.version != 4:
            messagebox.showerror("Netzbereich nicht möglich", "Nur IPv4-Netze werden unterstützt.")
            return

        if self._session_pending:
            d = self._pending_data or {}
            if not messagebox.askyesno(
                    "Gespeicherte Sitzung überschreiben?",
                    "Die noch nicht wiederhergestellte Sitzung "
                    f"({self._session_label(d)}) wird durch diesen Scan überschrieben.\n"
                    "Die Handeingaben daraus werden übernommen. Fortfahren?"):
                return
            self._merge_notes_from(d)
            self._session_pending = False
            self._pending_data = None
            self._set_notice("restore", "")
        if self._notes and getattr(self, "_notes_kunde", None) not in (None, self.var_kunde.get().strip()):
            if messagebox.askyesno("Kunde geändert",
                                   "Der Kundenname hat sich geändert. Gespeicherte Handeingaben "
                                   "(Standort, User …) des vorherigen Kunden verwerfen?"):
                self._notes = []
        self._notes_kunde = self.var_kunde.get().strip()

        # Vorheriges Ergebnis sichern (Wiederherstellen bei Abbruch ohne Geräte);
        # Handeingaben stehen dauerhaft in self._notes.
        for h in self.hosts:
            self._remember(h)
        self._prev_hosts = list(self.hosts)
        self.hosts = []
        self._item_host = {}
        self._scan_cidr = cidr
        self._cancel_requested = False
        self._scanning = True
        self.tree.delete(*self.tree.get_children())
        self.var_count.set("0 Geräte")
        self.var_summary.set("")
        self._set_notice("perm", "")
        self._set_notice("problems", "")
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
                self._log_error("Scan", e)
                self.msg_queue.put(("error", str(e)))

        self.scan_thread = threading.Thread(target=worker, daemon=True)
        self.scan_thread.start()

    # ------------------------------------------------------- Handeingaben
    MANUAL_FIELDS = ("standort", "user", "angebunden_an", "eingerichtet_von", "ignored")
    TEXT_FIELDS = MANUAL_FIELDS[:4]

    @staticmethod
    def _note_mac(h: Host) -> str:
        """MAC als Schlüssel für Handeingaben – nicht bei Repeater/Proxy-ARP (eine MAC, viele Geräte)."""
        return "" if _MAC_DOPPELT in (h.scan_warning or "") else (h.mac or "")

    def _find_note(self, ip: str, mac: str) -> Optional[dict]:
        """Eintrag per MAC (stabil), sonst per IP (nur wenn die MACs nicht widersprechen)."""
        mac = (mac or "").lower()
        if mac:
            for n in self._notes:
                if (n.get("mac") or "").lower() == mac:
                    return n
        for n in self._notes:
            nm = (n.get("mac") or "").lower()
            if n.get("ip") == ip and (not mac or not nm or nm == mac):
                return n
        return None

    def _remember(self, h: Host):
        """Merkt sich die Handeingaben eines Geräts (leer = Eintrag entfernen)."""
        n = self._find_note(h.ip, self._note_mac(h))
        if not any(getattr(h, f) for f in self.MANUAL_FIELDS):
            if n is not None:
                self._notes.remove(n)
            return
        if n is None:
            n = {}
            self._notes.append(n)
        n.update(ip=h.ip, mac=self._note_mac(h), vendor=h.vendor or n.get("vendor", ""),
                 hostname=h.hostname or n.get("hostname", ""),
                 device_type=h.device_type or n.get("device_type", ""),
                 **{f: getattr(h, f) for f in self.MANUAL_FIELDS})

    def _carry_manual(self, h: Host):
        n = self._find_note(h.ip, self._note_mac(h))
        if n is not None:
            n["ip"] = h.ip  # DHCP: gleiche MAC, neue IP
            for f in self.MANUAL_FIELDS:
                if f in n:
                    setattr(h, f, n[f])

    def _merge_notes_from(self, data: dict):
        """Übernimmt Handeingaben aus einer Sitzungsdatei (alte Dateien: aus den Hosts)."""
        for n in data.get("handeingaben", []) or []:
            if isinstance(n, dict) and n.get("ip") and not self._find_note(n["ip"], n.get("mac", "")):
                self._notes.append(n)
        for d in data.get("hosts", []) or []:
            try:
                self._remember(Host.from_dict(d))
            except Exception:
                pass

    def _gone_hosts(self, found: List[Host], cidr: str) -> List[Host]:
        """Geräte mit Handeingaben, die diesmal nicht geantwortet haben."""
        try:
            net = ipaddress.ip_network(cidr, strict=False)
        except ValueError:
            return []
        seen = {id(self._find_note(h.ip, self._note_mac(h))) for h in found}
        out = []
        for n in self._notes:
            if id(n) in seen or n.get("ignored") or not any(n.get(f) for f in self.TEXT_FIELDS):
                continue
            try:
                if ipaddress.ip_address(n.get("ip", "")) not in net:
                    continue
            except ValueError:
                continue
            g = Host(ip=n["ip"], mac=n.get("mac", ""), vendor=n.get("vendor", ""),
                     hostname=n.get("hostname", ""), device_type=n.get("device_type", ""),
                     scan_warning=GONE_WARNING)
            for f in self.MANUAL_FIELDS:
                setattr(g, f, n.get(f, getattr(g, f)))
            g.ignored = False
            out.append(g)
        return out

    def _cancel_scan(self):
        self._cancel_requested = True
        if self.scanner:
            self.scanner.cancel()
        self.var_status.set("Abbruch angefordert …")

    # --------------------------------------------------- Session-Persistenz
    def _on_close(self):
        if self.scan_thread and self.scan_thread.is_alive():
            self._cancel_scan()
        self._save_session()
        self.destroy()

    def _schedule_save(self):
        """Entprellt: Kundendaten-Änderungen werden 1,5 s nach dem letzten Tastendruck gesichert."""
        if self._save_job is not None:
            self.after_cancel(self._save_job)
        self._save_job = self.after(1500, self._save_session)

    def _save_session(self) -> bool:
        if self._save_job is not None:
            try:
                self.after_cancel(self._save_job)
            except Exception:
                pass
            self._save_job = None
        if self._session_pending:  # ältere Sitzung noch nicht entschieden: nicht überschreiben
            return False
        hosts = self._prev_hosts if self._scanning else self.hosts
        if not hosts and not self._notes:
            return False
        for h in hosts:
            self._remember(h)
        data = {
            "kunde": self.var_kunde.get(),
            "kundennr": self.var_kundennr.get(),
            "datum": self.var_datum.get(),
            "gespeichert_am": datetime.datetime.now().isoformat(timespec="seconds"),
            "handeingaben_kunde": getattr(self, "_notes_kunde", self.var_kunde.get().strip()),
            "hosts": [h.to_dict() for h in hosts],
            "handeingaben": self._notes,
        }
        tmp = SESSION_FILE + ".tmp"
        try:
            os.makedirs(SESSION_DIR, mode=0o700, exist_ok=True)
            fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
            with os.fdopen(fd, "w", encoding="utf-8") as f:
                json.dump(data, f, ensure_ascii=False, indent=2)
            os.chmod(tmp, 0o600)
            os.replace(tmp, SESSION_FILE)  # atomar: nie eine halbe Datei
        except Exception as e:
            self._log_error("Sitzung speichern", e)
            self._set_notice("save", f"Sitzung konnte nicht gespeichert werden: {e}")
            return False
        self._set_notice("save", "")
        return True

    def _session_label(self, data: dict) -> str:
        kunde = (data.get("kunde") or "").strip() or "ohne Kundenname"
        when = data.get("gespeichert_am")
        try:
            when = datetime.datetime.fromisoformat(when).strftime("%d.%m.%Y %H:%M")
        except (TypeError, ValueError):
            try:
                ts = datetime.datetime.fromtimestamp(os.path.getmtime(SESSION_FILE))
                when = ts.strftime("%d.%m.%Y %H:%M") + " (Dateidatum)"
            except OSError:
                when = "unbekannt"
        return f"Kunde: {kunde}, gespeichert: {when}, {len(data.get('hosts', []) or [])} Geräte"

    def _read_session(self) -> Optional[dict]:
        if not os.path.exists(SESSION_FILE):
            return None
        try:
            with open(SESSION_FILE, "r", encoding="utf-8") as f:
                data = json.load(f)
            if not isinstance(data, dict):
                raise ValueError("Sitzungsdatei hat ein unerwartetes Format")
            return data
        except Exception as e:
            try:
                os.replace(SESSION_FILE, SESSION_FILE + ".defekt")
            except OSError:
                pass
            messagebox.showerror("Sitzung nicht lesbar",
                                 f"{e}\n\nDie Datei wurde als last_session.json.defekt beiseitegelegt.")
            return None

    def _maybe_restore_session(self):
        data = self._read_session()
        if data is None:
            return
        ans = messagebox.askyesnocancel(
            "Sitzung wiederherstellen",
            f"Gespeicherte Sitzung gefunden:\n{self._session_label(data)}\n\n"
            "Ja = wiederherstellen\nNein = verwerfen (Datei wird gelöscht)\n"
            "Abbrechen = später entscheiden (Datei bleibt unverändert)")
        if ans:
            self._apply_session(data)
        elif ans is False and messagebox.askyesno(
                "Sitzung verwerfen?", "Gespeicherte Sitzung wirklich löschen? Das lässt sich nicht rückgängig machen."):
            try:
                os.remove(SESSION_FILE)
            except OSError as e:
                self._set_notice("save", f"Sitzungsdatei nicht löschbar: {e}")
        else:  # Abbrechen oder Rückfrage verneint: Datei behalten, nicht überschreiben
            self._session_pending = True
            self._pending_data = data
            self._set_notice("restore", "Gespeicherte Sitzung noch nicht wiederhergestellt – sie wird erst "
                                        "nach Bestätigung beim nächsten Scan überschrieben.")

    def _apply_session(self, data: dict):
        try:
            hosts = [Host.from_dict(d) for d in data.get("hosts", [])]
            self.var_kunde.set(data.get("kunde", ""))
            self.var_kundennr.set(data.get("kundennr", ""))
            self.var_datum.set(data.get("datum", ""))
            self._notes_kunde = data.get("handeingaben_kunde", data.get("kunde", "")).strip()
            self.hosts = hosts
            self._merge_notes_from(data)
            self._rebuild_tree()
            self._set_counts()
            if self.hosts:
                self.btn_export.config(state="normal")
            self._update_summary()
        except Exception as e:
            self._log_error("Sitzung laden", e)
            messagebox.showerror("Wiederherstellen fehlgeschlagen", str(e))

    def _export(self):
        if not self.hosts:
            return
        pw = self.var_passwort.get()
        if pw:  # Wiederholung VOR dem Dateidialog
            again = simpledialog.askstring(
                "Passwort bestätigen", "Passwort für die Excel-Datei bitte wiederholen:",
                show="" if self.var_show_pw.get() else "•", parent=self)
            if again is None:
                return
            if again != pw:
                messagebox.showerror("Passwort", "Die Passwörter stimmen nicht überein. Nichts gespeichert.")
                return
        fname = exporter.suggested_filename(self.var_kunde.get())
        path = filedialog.asksaveasfilename(
            title="Netzwerkdoku speichern", defaultextension=".xlsx",
            initialfile=fname, filetypes=[("Excel", "*.xlsx")])
        if not path:
            return
        self.btn_export.config(state="disabled")
        self.update_idletasks()
        try:
            exporter.export(
                [h for h in self.hosts if GONE_WARNING not in (h.scan_warning or "")], path, template_path=self.template_path,
                kundenname=self.var_kunde.get(), kundennummer=self.var_kundennr.get(),
                installationsdatum=self.var_datum.get(), passwort=pw)
        except PermissionError:
            messagebox.showerror("Export fehlgeschlagen",
                                 "Die Datei ist vermutlich noch in Excel geöffnet oder schreibgeschützt.\n"
                                 "Bitte schließen und erneut speichern.")
            return
        except Exception as e:
            self._log_error("Export", e)
            messagebox.showerror("Export fehlgeschlagen", str(e))
            return
        finally:
            if self.hosts and not self._scanning:
                self.btn_export.config(state="normal")
        art = "verschlüsselt mit Passwort" if pw else "ohne Passwort"
        gone = sum(1 for h in self.hosts if GONE_WARNING in (h.scan_warning or ""))
        ign = sum(1 for h in self.hosts if h.ignored and GONE_WARNING not in (h.scan_warning or ""))
        manager = "Finder" if sys.platform == "darwin" else "Explorer"
        if messagebox.askyesno("Fertig",
                               f"{len(self.hosts) - ign - gone} Geräte exportiert, {ign} ignoriert"
                               + (f", {gone} nicht erreichbare nicht übernommen" if gone else "") + ".\n"
                               f"Gespeichert ({art}):\n{path}\n\nIm {manager} anzeigen?"):
            reveal_in_file_manager(path)

    # ------------------------------------------------------- Tabelle/Events
    def _row_values(self, h: Host):
        ports = ", ".join(str(p) for p in sorted(h.open_ports))
        icon = "⚠" if h.scan_warning else device_emoji(h.device_type, h.os_hint)
        return (icon, h.ip, h.vendor,
                h.device_type, h.hostname, h.mac, h.win_function, ports, h.scan_warning)

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
            if key == "ports":  # numerisch nach kleinster Portnummer, ohne Ports zuletzt
                return (0, min(h.open_ports)) if h.open_ports else (1, 0)
            return (str(v) == "", str(v).casefold())

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
        if h:
            self._edit_host(h)

    def _edit_selected(self, event=None):
        sel = self.tree.selection()
        h = self._item_host.get(sel[0]) if sel else None
        if h:
            self._edit_host(h)
        return "break"

    def _menu_for_selection(self, event=None):
        sel = self.tree.selection()
        if sel:
            x, y, w, hgt = self.tree.bbox(sel[0]) or (0, 0, 0, 0)
            self._popup_menu(sel[0], self.tree.winfo_rootx() + x + 40,
                             self.tree.winfo_rooty() + y + hgt)
        return "break"

    def _show_context_menu(self, event):
        item = self.tree.identify_row(event.y)
        if item:
            self._popup_menu(item, event.x_root, event.y_root)
        return "break"

    def _popup_menu(self, item, x_root, y_root):
        h = self._item_host.get(item)
        if h is None:
            return
        self.tree.selection_set(item)
        menu = tk.Menu(self, tearoff=0)
        menu.add_command(label="Bearbeiten…", command=lambda: self._edit_host(h))
        menu.add_command(label="IP kopieren", command=lambda: (self.clipboard_clear(), self.clipboard_append(h.ip)))
        if self._has_web_port(h):
            scheme = "https" if (443 in h.open_ports or 8443 in h.open_ports) else "http"
            menu.add_command(label="Im Browser öffnen", command=lambda: webbrowser.open(f"{scheme}://{h.ip}"))
        label = "Nicht mehr ignorieren" if h.ignored else "Ignorieren"
        menu.add_command(label=label, command=lambda: self._toggle_ignored(h))
        try:
            menu.tk_popup(x_root, y_root)
        finally:
            menu.grab_release()

    def _toggle_ignored(self, h: Host):
        h.ignored = not h.ignored
        self._remember(h)
        self._rebuild_tree()
        self._set_counts()
        self._save_session()

    def _edit_host(self, h: Host):
        dlg = tk.Toplevel(self)
        dlg.title(f"Bearbeiten – {h.ip}")
        dlg.configure(bg=BORDER)
        dlg.transient(self)
        dlg.resizable(True, True)
        dlg.minsize(380, 240)
        inner = tk.Frame(dlg, bg=CARD)
        inner.pack(fill="both", expand=True, padx=1, pady=1)
        body = tk.Frame(inner, bg=CARD)
        body.pack(fill="both", expand=True, padx=18, pady=16)
        body.columnconfigure(1, weight=1)

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
            ttk.Entry(body, textvariable=var, width=28).grid(row=i, column=1, pady=4, sticky="ew")
        if h.scan_warning:
            tk.Label(body, text=f"⚠ {h.scan_warning}", bg=CARD, fg="#9A5B00", font=self.f_small,
                     justify="left", anchor="w", wraplength=340).grid(
                row=len(rows) + 1, column=0, columnspan=2, sticky="ew", pady=(8, 0))

        def save():
            h.standort = var_standort.get()
            h.user = var_user.get()
            h.angebunden_an = var_verbunden.get()
            h.eingerichtet_von = var_eingerichtet.get()
            dlg.destroy()
            self._remember(h)
            self._rebuild_tree()
            self._save_session()

        btns = tk.Frame(body, bg=CARD)
        btns.grid(row=len(rows) + 2, column=0, columnspan=2, sticky="e", pady=(14, 0))
        ttk.Button(btns, text="Abbrechen", command=dlg.destroy).pack(side="right", padx=(6, 0))
        ttk.Button(btns, text="Speichern", style="Accent.TButton", command=save).pack(side="right")
        dlg.bind("<Return>", lambda e: save())
        dlg.bind("<Escape>", lambda e: dlg.destroy())
        dlg.grab_set()

    def _on_tree_motion(self, event):
        item = self.tree.identify_row(event.y)
        h = self._item_host.get(item) if item else None
        self.var_status.set(h.scan_warning if (h and h.scan_warning) else self._last_status)
        self._set_hover(item)

    def _on_tree_leave(self, event):
        self.var_status.set(self._last_status)
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
                try:
                    self._handle_message(item)
                except Exception as e:  # nie das Polling sterben lassen
                    self._report_error(f"Nachricht {item[0]}", e)
        except queue.Empty:
            pass
        finally:
            self.after(120, self._poll_queue)

    def _handle_message(self, item):
        kind = item[0]
        if kind == "progress":
            _, frac, msg = item
            self.progress["value"] = frac
            self.var_status.set(msg)
            self._last_status = msg
        elif kind == "host":
            h = item[1]
            self._carry_manual(h)
            self.hosts.append(h)
            q = self.var_filter.get().strip().lower()
            if not q or self._matches_filter(h, q):  # Zebra zählt nur sichtbare Zeilen
                self._add_host_row(h)
            self._set_counts()
        elif kind == "done":
            self._finish_scan(item[1] or [])
        elif kind == "error":
            self._report_error("Scan", RuntimeError(item[1]))
            messagebox.showerror("Scan-Fehler", f"{item[1]}\n\n(Details in {os.path.join(SESSION_DIR, 'fehler.log')})")
            self._finish_scan([], failed=True)
        elif kind == "update":
            self._on_update_result(item[1], manual=item[2], error=item[3])
        elif kind == "install_progress":
            _, frac, msg = item
            self.btn_update.config(text=msg)
        elif kind == "install_done":
            self._relaunch_after_update(item[1])
        elif kind == "install_error":
            self._install_update_failed(item[1])

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
        # "open" ohne -n würde nur die (gleich endende) laufende Instanz aktivieren
        subprocess.Popen(["/bin/sh", "-c", 'sleep 1; open -n "$0"', app_path], start_new_session=True)
        self._on_close()

    def _install_update_failed(self, error: str):
        self.btn_update.config(state="normal", text=f"Update verfügbar: v{self._update_info['version']}")
        if messagebox.askyesno(
                "Installation fehlgeschlagen",
                f"Automatische Installation fehlgeschlagen:\n{error}\n\n"
                "Stattdessen die Release-Seite im Browser öffnen (manueller Download)?"):
            webbrowser.open(self._update_info["url"])

    def _finish_scan(self, result: Optional[List[Host]] = None, failed: bool = False):
        """Ergebnis übernehmen. Alte Geräte erscheinen nie als neues Ergebnis."""
        self._scanning = False
        cancelled = self._scan_was_cancelled()
        found = list(result or self.hosts)  # self.hosts = bisher gestreamte Treffer dieses Scans
        for h in found:
            self._carry_manual(h)
        problems = list(getattr(self.scanner, "last_problems", None) or [])
        msg = ""
        if not found and (cancelled or failed):
            self.hosts = list(self._prev_hosts)  # vorheriges Ergebnis wiederherstellen
            what = "Scan abgebrochen" if cancelled else "Scan fehlgeschlagen"
            msg = (f"{what} – vorheriges Ergebnis wiederhergestellt." if self.hosts
                   else f"{what} – keine Geräte gefunden.")
        elif cancelled or failed:
            self.hosts = found
            msg = f"{'Abgebrochen' if cancelled else 'Scan fehlgeschlagen'} – {len(found)} Geräte (unvollständig)."
        else:
            gone = self._gone_hosts(found, self._scan_cidr)
            self.hosts = sorted(found + gone, key=lambda x: x.sort_key())
            msg = f"Fertig – {len(found)} Geräte" + (
                f", {len(gone)} diesmal nicht erreichbar (nur Handeingaben)." if gone else ".")
            if not found:
                msg = "Keine Geräte gefunden – Tabelle leer (vorheriges Ergebnis wird nicht angezeigt)."
        self._prev_hosts = []
        self._rebuild_tree()  # Sortierung/Filter wieder deckungsgleich mit self.hosts
        self.btn_scan.config(state="normal")
        self.btn_cancel.config(state="disabled")
        self.btn_export.config(state="normal" if self.hosts else "disabled")
        self._set_counts()
        self._update_summary()
        self._last_status = msg
        self.var_status.set(msg)

        few = not cancelled and len(found) <= 1
        self._set_notice("perm", PERM_HINT if few else "")
        self._set_notice("problems", "⚠ " + "\n⚠ ".join(problems) if problems else "")
        self._save_session()
        parts = []
        if few:
            parts.append("Es wurde (fast) nichts gefunden. Bitte prüfen:\n"
                         "• Stimmt der Netzbereich?\n• Ist der Rechner mit dem Praxisnetz verbunden (nicht Gast-WLAN/VPN)?\n"
                         + ("• macOS: Systemeinstellungen → Datenschutz & Sicherheit → Lokales Netzwerk → "
                            "Netzwerk-Scanner erlauben." if sys.platform == "darwin"
                            else "• Firewall/VPN prüfen; Netzwerk-Scanner in der Windows-Firewall zulassen."))
        if problems:
            parts.append("Hinweise zum Scan:\n• " + "\n• ".join(problems))
        if parts:
            text = "\n\n".join(parts)
            if few and sys.platform == "darwin":
                if messagebox.askyesno("Hinweise zum Scan", text + "\n\nSystemeinstellungen jetzt öffnen?"):
                    subprocess.Popen(["open", MAC_PRIVACY_URL])
            else:
                messagebox.showwarning("Hinweise zum Scan", text)


def main():
    App().mainloop()


if __name__ == "__main__":
    main()
