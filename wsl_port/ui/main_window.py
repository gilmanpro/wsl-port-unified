"""Ventana integrada de wsl-port: distros WSL + tunnels/forwards + publicar.

Diseno moderno con ttkbootstrap (superhero theme).
"""
from __future__ import annotations

import datetime
import queue
import threading
import tkinter as tk
import webbrowser
from tkinter import ttk as _ttk, filedialog
from pathlib import Path

import ttkbootstrap as ttk

from .. import core
from .publish_tab import PublishTab

# -- Design tokens (inspired by perfil.gilman.pro) ---------------------------
_FONT = "Segoe UI"
_COLORS = {
    "bg": "#0f1419",
    "card": "#1a2130",
    "accent": "#00d4ff",
    "success": "#00c853",
    "warning": "#ff9100",
    "danger": "#ff1744",
    "info": "#2196f3",
    "muted": "#8b95a5",
    "text": "#e6edf3",
    "border": "#2d3748",
}

_RUN_KEY = r"Software\Microsoft\Windows\CurrentVersion\Run"
_AUTOSTART_NAME = "wsl-port"


def _autostart_command() -> str:
    import sys
    # Find project root (where wsl-port.vbs is)
    project_root = Path(__file__).resolve().parent.parent.parent
    vbs_path = project_root / "wsl-port.vbs"
    return f'wscript.exe "{vbs_path}"'


def autostart_active() -> bool:
    try:
        from winreg import HKEY_CURRENT_USER, OpenKey, QueryValueEx
        with OpenKey(HKEY_CURRENT_USER, _RUN_KEY) as k:
            return QueryValueEx(k, _AUTOSTART_NAME)[0] == _autostart_command()
    except Exception:
        return False


def _set_autostart(active: bool) -> None:
    try:
        from winreg import HKEY_CURRENT_USER, CreateKey, DeleteValue, SetValueEx
        with CreateKey(HKEY_CURRENT_USER, _RUN_KEY) as k:
            if active:
                SetValueEx(k, _AUTOSTART_NAME, 0, 1, _autostart_command())
            else:
                try:
                    DeleteValue(k, _AUTOSTART_NAME)
                except OSError:
                    pass
    except Exception:
        pass


def _fmt_bytes(n) -> str:
    n = float(n or 0)
    for u in ("B", "KB", "MB", "GB", "TB"):
        if n < 1024 or u == "TB":
            return f"{n:.1f} {u}"
        n /= 1024
    return f"{n:.1f} TB"


def _make_tree(parent, columns: list[str], widths: list[int]) -> _ttk.Treeview:
    """Create a modern styled Treeview."""
    tv = _ttk.Treeview(parent, columns=columns, show="headings", height=8)
    for col, w in zip(columns, widths):
        tv.heading(col, text=col, anchor="w")
        tv.column(col, width=w, anchor="w")
    # Scrollbar
    sb = _ttk.Scrollbar(parent, orient="vertical", command=tv.yview)
    tv.configure(yscrollcommand=sb.set)
    tv.pack(side="left", fill="both", expand=True, padx=(6, 0), pady=(0, 6))
    sb.pack(side="right", fill="y", pady=(0, 6))
    return tv


class _FormDialog(tk.Toplevel):
    """Dialogo modal generico con campos dinamicos."""
    def __init__(self, parent, title: str, fields: list[tuple[str, str, str]],
                 validate=None, size=(420, 400)):
        super().__init__(parent)
        self.title(title)
        self.geometry(f"{size[0]}x{size[1]}")
        self.resizable(False, False)
        self.transient(parent)
        self.grab_set()
        self.result = None
        self._validate = validate

        frame = ttk.Frame(self, padding=16)
        frame.pack(fill="both", expand=True)

        self._vars: dict[str, tk.Variable] = {}
        for i, (key, label, kind) in enumerate(fields):
            ttk.Label(frame, text=label + ":", font=(_FONT, 10)).grid(
                row=i, column=0, sticky="w", pady=6)
            if kind == "entry":
                var = tk.StringVar()
                ttk.Entry(frame, textvariable=var, width=30, font=(_FONT, 10)).grid(
                    row=i, column=1, sticky="ew", padx=(12, 0), pady=6)
            elif kind == "password":
                var = tk.StringVar()
                ttk.Entry(frame, textvariable=var, width=30, show="*", font=(_FONT, 10)).grid(
                    row=i, column=1, sticky="ew", padx=(12, 0), pady=6)
            elif kind == "int":
                var = tk.IntVar(value=0)
                ttk.Entry(frame, textvariable=var, width=10, font=(_FONT, 10)).grid(
                    row=i, column=1, sticky="w", padx=(12, 0), pady=6)
            elif kind == "combo":
                var = tk.StringVar()
                ttk.Combobox(frame, textvariable=var, width=27, state="readonly",
                             font=(_FONT, 10)).grid(row=i, column=1, sticky="ew", padx=(12, 0), pady=6)
            elif kind == "file":
                var = tk.StringVar()
                f = ttk.Frame(frame)
                f.grid(row=i, column=1, sticky="ew", padx=(12, 0), pady=6)
                ttk.Entry(f, textvariable=var, width=22, font=(_FONT, 10)).pack(side="left", fill="x", expand=True)
                ttk.Button(f, text="...", width=3, bootstyle="outline",
                           command=lambda v=var: self._browse(v)).pack(side="left", padx=(4, 0))
            else:
                var = tk.StringVar()
                ttk.Entry(frame, textvariable=var, width=30, font=(_FONT, 10)).grid(
                    row=i, column=1, sticky="ew", padx=(12, 0), pady=6)
            self._vars[key] = var

        frame.columnconfigure(1, weight=1)

        btns = ttk.Frame(frame)
        btns.grid(row=len(fields), column=0, columnspan=2, pady=(20, 0))
        ttk.Button(btns, text="Aceptar", bootstyle="success", width=12,
                   command=self._ok).pack(side="left", padx=6)
        ttk.Button(btns, text="Cancelar", bootstyle="secondary outline", width=12,
                   command=self.cancel).pack(side="left", padx=6)

        self.protocol("WM_DELETE_WINDOW", self.cancel)
        self.bind("<Return>", lambda e: self._ok())
        self.bind("<Escape>", lambda e: self.cancel())

    def _browse(self, var: tk.StringVar):
        p = filedialog.askopenfilename(title="Seleccionar clave SSH")
        if p:
            var.set(p)

    def set_combo_values(self, key: str, values: list[str]):
        var = self._vars.get(key)
        if var and hasattr(self, "_vars"):
            for child in self.winfo_children():
                for sub in child.winfo_children():
                    if isinstance(sub, ttk.Combobox) and sub.cget("textvariable") == str(var):
                        sub["values"] = values
                        if values:
                            var.set(values[0])

    def _ok(self):
        data = {}
        for key, var in self._vars.items():
            try:
                data[key] = var.get()
            except Exception:
                data[key] = ""
        if self._validate:
            try:
                self._validate(data)
            except ValueError as e:
                from tkinter import messagebox
                messagebox.showerror("Validacion", str(e), parent=self)
                return
        self.result = data
        self.destroy()

    def cancel(self):
        self.result = None
        self.destroy()


class MainWindow:
    def __init__(self) -> None:
        self.root = ttk.Window(themename="superhero", title="wsl-port — WSL + Port Forwarding")
        self.root.geometry("1200x800")
        self.root.minsize(1000, 650)
        self._q: queue.Queue = queue.Queue()
        self._build()
        self._refresh()
        self.root.after(200, self._poll)
        self.root.after(15000, self._schedule_refresh)
        self.root.lift()
        self.root.focus_force()

    def _notify(self, title: str, message: str, level: str = "info") -> None:
        """Notificacion de actividad: banner en-app (siempre visible) + toast Windows.

        Thread-safe: el banner se actualiza via la cola (main thread).
        level: info | success | warning | error
        """
        try:
            self._q.put({"_action": "notify", "title": title,
                         "message": message, "level": level})
        except Exception:
            pass
        # Toast de Windows (opcional, en thread aparte)
        try:
            def _toast():
                try:
                    from winotify import Notification
                    Notification(app_id="wsl-port", title=title,
                                 msg=message).show()
                except Exception:
                    pass  # winotify no esta instalado: el banner in-app cubre
            threading.Thread(target=_toast, daemon=True).start()
        except Exception:
            print(f"[{level.upper()}] {title}: {message}")

    def _show_activity(self, title: str, message: str, level: str = "info") -> None:
        """Pinta el mensaje en el banner y lo borra tras 5s."""
        colors = {"info": _COLORS["info"], "success": _COLORS["success"],
                  "warning": _COLORS["warning"], "error": _COLORS["danger"]}
        self.activity_var.set(f"[{title}] {message}")
        self.activity_lbl.configure(foreground=colors.get(level, _COLORS["info"]))
        try:
            self.root.after(5000, lambda: self.activity_var.set(""))
        except Exception:
            pass

    # -- UI ------------------------------------------------------------------

    def _build(self) -> None:
        style = ttk.Style()
        style.configure("Treeview", rowheight=28, font=(_FONT, 10), background=_COLORS["card"],
                        fieldbackground=_COLORS["card"], foreground=_COLORS["text"])
        style.configure("Treeview.Heading", font=(_FONT, 10, "bold"), background=_COLORS["bg"],
                        foreground=_COLORS["accent"])
        style.map("Treeview", background=[("selected", _COLORS["accent"])],
                  foreground=[("selected", _COLORS["bg"])])
        style.configure("Header.TLabel", font=(_FONT, 16, "bold"), foreground=_COLORS["accent"])
        style.configure("Sub.TLabel", font=(_FONT, 10), foreground=_COLORS["muted"])
        style.configure("Card.TLabelframe", background=_COLORS["card"], foreground=_COLORS["text"])
        style.configure("Card.TLabelframe.Label", font=(_FONT, 11, "bold"), foreground=_COLORS["accent"])

        # -- Header ---------------------------------------------------------------
        header = ttk.Frame(self.root, padding=(20, 16))
        header.pack(fill="x")
        ttk.Label(header, text="wsl-port", style="Header.TLabel").pack(side="left")
        ttk.Label(header, text="  WSL + Port Forwarding integrados",
                  style="Sub.TLabel").pack(side="left")
        self.header_status = ttk.Label(header, text="", style="Sub.TLabel")
        self.header_status.pack(side="right")
        ttk.Separator(self.root).pack(fill="x")

        # -- Notebook -------------------------------------------------------------
        nb = ttk.Notebook(self.root, padding=8)
        nb.pack(fill="both", expand=True, padx=12, pady=(8, 0))

        # -- Distros WSL ----------------------------------------------------------
        d_tab = ttk.Frame(nb, padding=8)
        nb.add(d_tab, text="  Distros WSL  ")
        self._build_distros_tab(d_tab)

        # -- Publicar -------------------------------------------------------------
        self.publish_tab = PublishTab(nb)
        nb.add(self.publish_tab, text="  Publicar en Internet  ")

        # -- Tunnels / VPS --------------------------------------------------------
        t_tab = ttk.Frame(nb, padding=8)
        nb.add(t_tab, text="  Tunnels / VPS  ")
        self._build_tunnels_tab(t_tab)

        # -- Forwards -------------------------------------------------------------
        f_tab = ttk.Frame(nb, padding=8)
        nb.add(f_tab, text="  Forwards  ")
        self._build_forwards_tab(f_tab)

        # -- Logs -----------------------------------------------------------------
        l_tab = ttk.Frame(nb, padding=8)
        nb.add(l_tab, text="  Logs  ")
        self._build_logs_tab(l_tab)

        # -- Ajustes --------------------------------------------------------------
        s_tab = ttk.Frame(nb, padding=8)
        nb.add(s_tab, text="  Ajustes  ")
        self._build_settings_tab(s_tab)

        # -- Status bar -----------------------------------------------------------
        ttk.Separator(self.root).pack(fill="x")
        bar = ttk.Frame(self.root, padding=(20, 8))
        bar.pack(fill="x", side="bottom")
        self.status_var = tk.StringVar(value="cargando...")
        ttk.Label(bar, textvariable=self.status_var, style="Sub.TLabel").pack(side="left")

        # -- Activity banner (mensajes de tareas iniciadas/terminadas) ------------
        self.activity_var = tk.StringVar(value="")
        self.activity_lbl = ttk.Label(self.root, textvariable=self.activity_var,
                                      font=(_FONT, 10, "bold"), padding=(20, 4),
                                      foreground=_COLORS["info"])
        self.activity_lbl.pack(fill="x", side="bottom")

    # -- Distros tab ------------------------------------------------------------

    def _build_distros_tab(self, parent) -> None:
        bar = ttk.Frame(parent)
        bar.pack(fill="x", pady=(0, 8))
        for text, style, cmd in [
            ("Refrescar", "success", self._refresh_full),
            ("Iniciar", "info", self._start_selected_distro),
            ("Detener", "warning", self._stop_selected_distro),
            ("Reiniciar", "info", self._restart_selected_distro),
            ("Iniciar todas", "info outline", self._start_all_distros),
            ("Apagar todas", "danger outline", self._shutdown_all_distros),
            ("Snapshot", "secondary", self._snapshot_selected),
            ("Metricas", "secondary", self._show_metrics),
            ("Terminal", "primary", self._open_terminal),
            ("Crear...", "success outline", self._create_distro_dialog),
            ("Eliminar", "danger outline", self._delete_selected_distro),
            ("Exportar...", "secondary outline", self._export_selected_distro),
            ("Importar...", "secondary outline", self._import_distro_dialog),
        ]:
            ttk.Button(bar, text=text, bootstyle=style, command=cmd).pack(side="left", padx=2)
        self.distro_tree = _make_tree(parent, ["Distro", "Estado", "IP", "Version"],
                                      [200, 100, 160, 80])

    # -- Tunnels tab ------------------------------------------------------------

    def _build_tunnels_tab(self, parent) -> None:
        # Tunnels section
        ttk.Label(parent, text="Tunnels SSH", style="Header.TLabel").pack(anchor="w", pady=(0, 4))
        tun_bar = ttk.Frame(parent)
        tun_bar.pack(fill="x", pady=(0, 8))
        for text, style, cmd in [
            ("Refrescar", "success", self._refresh_full),
            ("Nuevo Tunnel...", "info", self._add_tunnel_dialog),
            ("Editar...", "secondary outline", self._edit_selected_tunnel),
            ("Iniciar", "success outline", self._start_selected_tunnel),
            ("Detener", "warning outline", self._stop_selected_tunnel),
            ("Reiniciar", "info outline", self._restart_selected_tunnel),
            ("Eliminar", "danger outline", self._remove_selected_tunnel),
        ]:
            ttk.Button(tun_bar, text=text, bootstyle=style, command=cmd).pack(side="left", padx=2)
        self.tun_tree = _make_tree(parent, ["ID", "Tipo", "VPS", "Local", "Remoto", "Estado", "Trafico"],
                                   [150, 70, 130, 140, 170, 80, 200])

        ttk.Separator(parent).pack(fill="x", pady=8)

        # VPS section
        ttk.Label(parent, text="Servidores VPS", style="Header.TLabel").pack(anchor="w", pady=(0, 4))
        vps_bar = ttk.Frame(parent)
        vps_bar.pack(fill="x", pady=(0, 8))
        for text, style, cmd in [
            ("Nuevo VPS...", "info", self._add_vps_dialog),
            ("Editar VPS...", "secondary outline", self._edit_vps_selected),
            ("Eliminar VPS", "danger outline", self._remove_vps_selected),
        ]:
            ttk.Button(vps_bar, text=text, bootstyle=style, command=cmd).pack(side="left", padx=2)
        self.vps_tree = _make_tree(parent, ["VPS", "Host", "Usuario", "Puerto", "Auth"],
                                   [150, 220, 130, 80, 120])

    # -- Forwards tab -----------------------------------------------------------

    def _build_forwards_tab(self, parent) -> None:
        bar = ttk.Frame(parent)
        bar.pack(fill="x", pady=(0, 8))
        for text, style, cmd in [
            ("Refrescar", "success", self._refresh_full),
            ("Nuevo Forward...", "info", self._add_forward_dialog),
            ("Reaplicar todos", "info outline", self._apply_forwards),
            ("Eliminar", "danger outline", self._remove_selected_forward),
            ("Limpiar todos", "danger outline", self._clear_forwards),
        ]:
            ttk.Button(bar, text=text, bootstyle=style, command=cmd).pack(side="left", padx=2)
        self.fwd_tree = _make_tree(parent, ["ID", "Listen", "Distro", "WSL Port", "Proto", "Estado"],
                                   [160, 90, 160, 90, 70, 100])

    # -- Logs tab ---------------------------------------------------------------

    def _build_logs_tab(self, parent) -> None:
        bar = ttk.Frame(parent)
        bar.pack(fill="x", pady=(0, 8))
        ttk.Button(bar, text="Refrescar logs", bootstyle="success",
                   command=self._refresh_logs).pack(side="left", padx=2)
        self.log_text = tk.Text(parent, font=("Consolas", 9), bg=_COLORS["card"],
                                fg=_COLORS["text"], state="disabled", wrap="word",
                                insertbackground=_COLORS["accent"])
        self.log_text.pack(fill="both", expand=True)

    # -- Settings tab -----------------------------------------------------------

    def _build_settings_tab(self, parent) -> None:
        canvas = tk.Canvas(parent, highlightthickness=0, bg=_COLORS["bg"])
        scrollbar = ttk.Scrollbar(parent, orient="vertical", command=canvas.yview)
        inner = ttk.Frame(canvas)
        inner.bind("<Configure>", lambda e: canvas.configure(scrollregion=canvas.bbox("all")))
        canvas.create_window((0, 0), window=inner, anchor="nw", tags="inner")
        canvas.configure(yscrollcommand=scrollbar.set)
        canvas.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")
        canvas.bind("<Configure>", lambda e: canvas.itemconfig("inner", width=e.width - 4))

        # Mouse wheel scrolling
        def _on_mousewheel(event):
            canvas.yview_scroll(int(-1 * (event.delta / 120)), "units")

        def _bind_mousewheel(event):
            canvas.bind_all("<MouseWheel>", _on_mousewheel)

        def _unbind_mousewheel(event):
            canvas.unbind_all("<MouseWheel>")

        canvas.bind("<Enter>", _bind_mousewheel)
        canvas.bind("<Leave>", _unbind_mousewheel)
        inner.bind("<Enter>", _bind_mousewheel)
        inner.bind("<Leave>", _unbind_mousewheel)

        PAD = 12

        def _card(parent, title: str, row: int, col: int, colspan: int = 1) -> ttk.LabelFrame:
            card = ttk.LabelFrame(parent, text=f"  {title}  ", padding=12, style="Card.TLabelframe")
            card.grid(row=row, column=col, columnspan=colspan, sticky="nsew",
                      padx=PAD // 2, pady=PAD // 2)
            parent.columnconfigure(col, weight=1)
            return card

        def _row(parent, r: int, label_text: str, widget_factory, hint: str = "") -> int:
            ttk.Label(parent, text=label_text, font=(_FONT, 10)).grid(
                row=r, column=0, sticky="w", pady=4)
            w = widget_factory(parent)
            w.grid(row=r, column=1, sticky="ew", padx=(12, 0), pady=4)
            parent.columnconfigure(1, weight=1)
            if hint:
                ttk.Label(parent, text=hint, style="Sub.TLabel", wraplength=280).grid(
                    row=r + 1, column=0, columnspan=2, sticky="w", pady=(0, 4))
                return r + 2
            return r + 1

        # ROW 0: General | Comportamiento
        card_general = _card(inner, "General", row=0, col=0)
        card_behav = _card(inner, "Comportamiento", row=0, col=1)

        r = 0
        self.theme_var = tk.StringVar(value="superhero")
        r = _row(card_general, r, "Tema:", lambda p: ttk.Combobox(
            p, textvariable=self.theme_var, values=[
                "superhero", "darkly", "cyborg", "cosmo", "flatly", "journal",
                "litera", "lumen", "minty", "pulse", "sandstone", "united", "yeti",
            ], width=14, state="readonly"))
        self.sup_interval_var = tk.StringVar(value="10")
        r = _row(card_general, r, "Intervalo supervisor (seg):",
                 lambda p: ttk.Entry(p, textvariable=self.sup_interval_var, width=6))
        self.metrics_retention_var = tk.StringVar(value="30")
        r = _row(card_general, r, "Retencion metricas (dias):",
                 lambda p: ttk.Entry(p, textvariable=self.metrics_retention_var, width=6))

        r = 0
        self.min_var = tk.BooleanVar(value=False)
        ttk.Checkbutton(card_behav, text="Iniciar en segundo plano (solo bandeja)",
                        variable=self.min_var, bootstyle="round-toggle").grid(
            row=r, column=0, columnspan=2, sticky="w", pady=4)
        r += 1
        self.tray_var = tk.BooleanVar(value=True)
        ttk.Checkbutton(card_behav, text="Cerrar ventana = minimizar a bandeja",
                        variable=self.tray_var, bootstyle="round-toggle").grid(
            row=r, column=0, columnspan=2, sticky="w", pady=4)
        r += 1
        self.stop_distros_var = tk.BooleanVar(value=False)
        ttk.Checkbutton(card_behav, text="Al salir: detener todas las distros WSL",
                        variable=self.stop_distros_var, bootstyle="round-toggle").grid(
            row=r, column=0, columnspan=2, sticky="w", pady=4)
        r += 1
        self.keep_tunnels_var = tk.BooleanVar(value=True)
        ttk.Checkbutton(card_behav, text="Al salir: mantener tunnels SSH activos",
                        variable=self.keep_tunnels_var, bootstyle="round-toggle").grid(
            row=r, column=0, columnspan=2, sticky="w", pady=4)
        r += 1
        self.auto_start_var = tk.BooleanVar(value=False)
        ttk.Checkbutton(card_behav, text="Autoarranque con Windows (bandeja)",
                        variable=self.auto_start_var, bootstyle="round-toggle").grid(
            row=r, column=0, columnspan=2, sticky="w", pady=4)

        # ROW 1: Panel Web | API REST
        card_web = _card(inner, "Panel Web", row=1, col=0)
        card_api = _card(inner, "API REST", row=1, col=1)

        r = 0
        self.web_enabled_var = tk.BooleanVar(value=False)
        ttk.Checkbutton(card_web, text="Habilitado", variable=self.web_enabled_var,
                        bootstyle="round-toggle").grid(row=r, column=0, columnspan=2, sticky="w", pady=4)
        r += 1
        self.web_port_var = tk.StringVar(value="8780")
        r = _row(card_web, r, "Puerto:", lambda p: ttk.Entry(p, textvariable=self.web_port_var, width=6))
        self.web_bind_var = tk.StringVar(value="127.0.0.1")
        r = _row(card_web, r, "Bind:", lambda p: ttk.Entry(p, textvariable=self.web_bind_var, width=14))
        self.web_pw_var = tk.StringVar()
        _r_web_pw = r
        r = _row(card_web, r, "Clave:", lambda p: ttk.Entry(p, textvariable=self.web_pw_var, width=20, show="*"),
                 "Obligatoria. Se guarda cifrada (DPAPI).")
        ttk.Button(card_web, text="Generar clave fuerte", bootstyle="info-outline",
                   command=self._generate_web_key
                   ).grid(row=_r_web_pw, column=2, sticky="w", padx=(6, 0))

        r = 0
        self.api_enabled_var = tk.BooleanVar(value=False)
        ttk.Checkbutton(card_api, text="Habilitada (loopback)", variable=self.api_enabled_var,
                        bootstyle="round-toggle").grid(row=r, column=0, columnspan=2, sticky="w", pady=4)
        r += 1
        self.api_port_var = tk.StringVar(value="8781")
        r = _row(card_api, r, "Puerto:", lambda p: ttk.Entry(p, textvariable=self.api_port_var, width=6))
        self.api_scope_var = tk.StringVar(value="write")
        r = _row(card_api, r, "Scope token:", lambda p: ttk.Combobox(
            p, textvariable=self.api_scope_var, values=["read", "write", "admin"],
            state="readonly", width=8))
        ttk.Button(card_api, text="Generar token API", bootstyle="info",
                   command=self._gen_api_token).grid(row=r, column=0, columnspan=2, sticky="ew", pady=(8, 2))
        ttk.Label(card_api, text="Se muestra UNA sola vez.", style="Sub.TLabel").grid(
            row=r + 1, column=0, columnspan=2, sticky="w")

        # ROW 2: MCP | Rutas
        card_mcp = _card(inner, "MCP (agentes LLM)", row=2, col=0)
        card_paths = _card(inner, "Rutas de binarios", row=2, col=1)

        r = 0
        self.mcp_enabled_var = tk.BooleanVar(value=False)
        ttk.Checkbutton(card_mcp, text="Habilitado", variable=self.mcp_enabled_var,
                        bootstyle="round-toggle").grid(row=r, column=0, columnspan=2, sticky="w", pady=4)
        r += 1
        self.mcp_transport_var = tk.StringVar(value="stdio")
        r = _row(card_mcp, r, "Transporte:", lambda p: ttk.Combobox(
            p, textvariable=self.mcp_transport_var, values=["stdio", "http"],
            state="readonly", width=8))
        self.mcp_port_var = tk.StringVar(value="8782")
        r = _row(card_mcp, r, "Puerto (http):", lambda p: ttk.Entry(p, textvariable=self.mcp_port_var, width=6))
        self.mcp_token_var = tk.BooleanVar(value=True)
        ttk.Checkbutton(card_mcp, text="Exigir token", variable=self.mcp_token_var,
                        bootstyle="round-toggle").grid(row=r, column=0, columnspan=2, sticky="w", pady=4)
        r += 1
        self.mcp_key_var = tk.StringVar()
        r = _row(card_mcp, r, "Token:", lambda p: ttk.Entry(p, textvariable=self.mcp_key_var, width=20, show="*"),
                 "Se conserva el actual si lo dejas vacio.")
        self.mcp_exec_var = tk.BooleanVar(value=True)
        ttk.Checkbutton(card_mcp, text="Exponer wsl_exec (RCE en distros)",
                        variable=self.mcp_exec_var, bootstyle="round-toggle").grid(
            row=r, column=0, columnspan=2, sticky="w", pady=4)
        r += 1
        ttk.Label(card_mcp, text="Apagado: la herramienta desaparece de tools/list y toda llamada es rechazada.",
                  style="Sub.TLabel", wraplength=280).grid(
            row=r, column=0, columnspan=2, sticky="w", pady=(0, 4))
        r += 1

        r = 0
        self.wsl_exe_var = tk.StringVar(value="")
        r = _row(card_paths, r, "wsl.exe:", lambda p: ttk.Entry(p, textvariable=self.wsl_exe_var, width=28))
        self.ssh_exe_var = tk.StringVar(value="")
        r = _row(card_paths, r, "ssh.exe:", lambda p: ttk.Entry(p, textvariable=self.ssh_exe_var, width=28))
        self.netsh_exe_var = tk.StringVar(value="")
        r = _row(card_paths, r, "netsh.exe:", lambda p: ttk.Entry(p, textvariable=self.netsh_exe_var, width=28))
        ttk.Label(card_paths, text="Dejar vacio para autodetectar.", style="Sub.TLabel").grid(
            row=r, column=0, columnspan=2, sticky="w", pady=(4, 0))

        # ROW 3: Limites de recursos (.wslconfig)
        card_limits = _card(inner, "Limites de recursos WSL (.wslconfig)", row=3, col=0, colspan=2)

        r = 0
        ttk.Label(card_limits, text="Se escribe en %USERPROFILE%\\.wslconfig. Vacio = sin cambio.",
                  style="Sub.TLabel").grid(row=r, column=0, columnspan=4, sticky="w", pady=(0, 8))
        r += 1
        self.mem_var = tk.StringVar(value="")
        r2 = _row(card_limits, r, "RAM (GB):", lambda p: ttk.Entry(p, textvariable=self.mem_var, width=8),
                  "Ej: 8. Vacio = dejar como esta.")
        self.cpu_var = tk.StringVar(value="")
        r2 = _row(card_limits, r2, "Procesadores:", lambda p: ttk.Entry(p, textvariable=self.cpu_var, width=8),
                  "Ej: 4. Vacio = dejar como esta.")
        self.swap_var = tk.StringVar(value="")
        r2 = _row(card_limits, r2, "Swap (GB):", lambda p: ttk.Entry(p, textvariable=self.swap_var, width=8),
                  "Ej: 4. Vacio = dejar como esta.")
        self.vhd_var = tk.StringVar(value="")
        r2 = _row(card_limits, r2, "VHD max (GB):", lambda p: ttk.Entry(p, textvariable=self.vhd_var, width=8),
                  "defaultVhdSize. Tope de disco para distros nuevas.")
        self.reclaim_var = tk.StringVar(value="")
        r2 = _row(card_limits, r2, "Reclaim RAM:", lambda p: ttk.Combobox(
            p, textvariable=self.reclaim_var, values=["", "gradual", "dropcache", "disabled"],
            state="readonly", width=12), "autoMemoryReclaim: devuelve RAM libre a Windows.")
        self.sparse_var = tk.StringVar(value="")
        r2 = _row(card_limits, r2, "Sparse VHD:", lambda p: ttk.Combobox(
            p, textvariable=self.sparse_var, values=["", "true", "false"],
            state="readonly", width=12), "Disco solo ocupa lo usado.")
        self.lh_var = tk.StringVar(value="")
        r2 = _row(card_limits, r2, "Localhost fwd:", lambda p: ttk.Combobox(
            p, textvariable=self.lh_var, values=["", "true", "false"],
            state="readonly", width=12), "localhostForwarding: acceso desde localhost.")
        ttk.Button(card_limits, text="Aplicar limites", bootstyle="warning",
                   command=self._apply_limits).grid(row=r2, column=0, columnspan=2, sticky="w", pady=(8, 0))

        # Save button
        btn_frame = ttk.Frame(inner)
        btn_frame.grid(row=4, column=0, columnspan=2, pady=(12, 16))
        ttk.Button(btn_frame, text="  Guardar ajustes  ", bootstyle="success",
                   command=self._save_settings).pack(side="left", padx=6)
        ttk.Button(btn_frame, text="  Restaurar valores  ", bootstyle="secondary outline",
                   command=self._load_settings_values).pack(side="left", padx=6)

        self._load_settings_values()

    def _load_settings_values(self) -> None:
        try:
            store = core.pf_store()
            cfg = store.cfg
            self.theme_var.set(cfg.ui.theme if cfg.ui.theme != "dark" else "superhero")
            self.tray_var.set(cfg.ui.close_to_tray)
            self.keep_tunnels_var.set(cfg.on_close.keep_tunnels_alive)
            self.sup_interval_var.set(str(cfg.ui.supervisor_interval_seconds))
            self.metrics_retention_var.set(str(cfg.ui.metrics_retention_days))
            self.web_enabled_var.set(cfg.ui.web_panel_enabled)
            self.web_port_var.set(str(cfg.ui.web_panel_port))
            self.web_bind_var.set(cfg.ui.web_panel_bind)
            # Clave actual pre-cargada (campo enmascarado): evita que el
            # usuario salve con vacio y la app regenere otra clave distinta.
            cur_web = ""
            try:
                from wsl_port.vendor.port_forwarder.utils.secrets import SecretsStore
                _sec = SecretsStore()
                if _sec.check("web_panel_token"):
                    cur_web = _sec.get("web_panel_token") or ""
            except Exception:  # noqa: BLE001
                pass
            self.web_pw_var.set(cur_web or cfg.ui.web_panel_token or "")
            self.api_enabled_var.set(cfg.api.enabled)
            self.api_port_var.set(str(cfg.api.port))
            self.mcp_enabled_var.set(cfg.mcp.enabled)
            self.mcp_transport_var.set(cfg.mcp.transport)
            self.mcp_port_var.set(str(cfg.mcp.port))
            self.mcp_token_var.set(cfg.mcp.token_required)
            self.mcp_key_var.set(cfg.mcp.token or "")
            self.mcp_exec_var.set(bool(getattr(cfg.mcp, "expose_exec", True)))
            self.wsl_exe_var.set(cfg.windows.wsl_exe)
            self.ssh_exe_var.set(cfg.windows.ssh_exe)
            self.netsh_exe_var.set(cfg.windows.netsh_exe)
        except Exception:
            pass
        # Limites de recursos (.wslconfig)
        try:
            limits = core.get_global_limits()
            self.mem_var.set(str(limits.get("memory_gb", "")) if limits.get("memory_gb") else "")
            self.cpu_var.set(str(limits.get("processors", "")) if limits.get("processors") else "")
            self.swap_var.set(str(limits.get("swap_gb", "")) if limits.get("swap_gb") else "")
            self.vhd_var.set(str(limits.get("default_vhd_gb", "")) if limits.get("default_vhd_gb") else "")
            self.reclaim_var.set(limits.get("auto_memory_reclaim", "") or "")
            self.sparse_var.set(str(limits.get("sparse_vhd", "")) if limits.get("sparse_vhd") else "")
            self.lh_var.set(str(limits.get("localhost_forwarding", "")) if limits.get("localhost_forwarding") else "")
        except Exception:
            pass

    def _gen_api_token(self) -> None:
        import hashlib
        import secrets as _sec
        from tkinter import messagebox
        token = _sec.token_urlsafe(32)
        scope = self.api_scope_var.get()
        try:
            from wsl_port.vendor.port_forwarder.utils.secrets import SecretsStore
            store_s = SecretsStore()
            import json
            tokens = {}
            if store_s.check("api_tokens"):
                try:
                    tokens = json.loads(store_s.get("api_tokens"))
                except Exception:
                    tokens = {}
            token_id = f"token-{_sec.token_hex(4)}"
            tokens[token_id] = {"hash": hashlib.sha256(token.encode()).hexdigest(), "scope": scope}
            store_s.set("api_tokens", json.dumps(tokens))
        except Exception as e:
            messagebox.showerror("API", f"No se pudo guardar el token: {e}")
            return
        messagebox.showinfo("API REST",
                            f"Token API generado (scope {scope}).\n\n{token}\n\n"
                            "Guardalo: NO se volvera a mostrar.\n"
                            f"Uso: Authorization: Bearer {token}")

    def _apply_limits(self) -> None:
        """Aplicar limites de recursos a .wslconfig (seguro, sin bridged)."""
        from tkinter import messagebox
        try:
            kwargs = {}
            mem = self.mem_var.get().strip()
            if mem:
                kwargs["memory_gb"] = float(mem)
            cpu = self.cpu_var.get().strip()
            if cpu:
                kwargs["processors"] = int(cpu)
            swap = self.swap_var.get().strip()
            if swap:
                kwargs["swap_gb"] = float(swap)
            vhd = self.vhd_var.get().strip()
            if vhd:
                kwargs["default_vhd_gb"] = float(vhd)
            reclaim = self.reclaim_var.get().strip()
            if reclaim:
                kwargs["auto_memory_reclaim"] = reclaim
            sparse = self.sparse_var.get().strip()
            if sparse:
                kwargs["sparse_vhd"] = sparse
            lh = self.lh_var.get().strip()
            if lh:
                kwargs["localhost_forwarding"] = lh
            if not kwargs:
                messagebox.showwarning("Limites", "Escribe al menos un valor.")
                return
            r = core.set_global_limits(**kwargs)
            if r.get("ok"):
                self._notify("Limites", r.get("message", "Limites aplicados"), "success")
                messagebox.showinfo("Limites", r.get("message", "Limites aplicados"))
            else:
                self._notify("Limites", f"Error: {r.get('error')}", "error")
                messagebox.showerror("Limites", r.get("error", "Error"))
        except Exception as e:
            messagebox.showerror("Limites", f"Error: {e}")

    def _generate_web_key(self) -> None:
        import secrets

        self.web_pw_var.set(secrets.token_urlsafe(32))
        messagebox.showinfo("Ajustes",
            "Clave fuerte generada (43 caracteres).\n"
            "Pulsa Guardar ajustes; es la que pedira el navegador.")

    def _save_settings(self) -> None:
        from tkinter import messagebox
        try:
            store = core.pf_store()
            cfg = store.cfg
            cfg.ui.theme = self.theme_var.get()
            cfg.ui.close_to_tray = self.tray_var.get()
            cfg.on_close.keep_tunnels_alive = self.keep_tunnels_var.get()
            cfg.on_close.stop_distros = self.stop_distros_var.get()
            cfg.ui.supervisor_interval_seconds = int(self.sup_interval_var.get() or 10)
            cfg.ui.metrics_retention_days = int(self.metrics_retention_var.get() or 30)
            web_on = self.web_enabled_var.get()
            web_pw = self.web_pw_var.get()
            had_web_token = bool(cfg.ui.web_panel_token)
            if web_on and not web_pw and not had_web_token:
                try:
                    from wsl_port.vendor.port_forwarder.utils.secrets import SecretsStore as _Sec
                    had_web_token = _Sec().check("web_panel_token")
                except Exception:  # noqa: BLE001
                    pass
            if web_on and not web_pw and not had_web_token:
                messagebox.showerror("Ajustes",
                    "El panel web debe tener una clave (es obligatoria).\n"
                    "Escribela en 'Clave' o pulsa 'Generar clave fuerte'.")
                return
            cfg.ui.web_panel_enabled = web_on
            cfg.ui.web_panel_port = int(self.web_port_var.get() or 8780)
            cfg.ui.web_panel_bind = self.web_bind_var.get().strip() or "127.0.0.1"
            if web_pw and len(web_pw) < 12:
                messagebox.showerror("Ajustes",
                    "Clave demasiado corta (minimo 12 caracteres).\n"
                    "Usa 'Generar clave fuerte'.")
                return
            bind = cfg.ui.web_panel_bind
            if web_on and bind not in ("127.0.0.1", "localhost", "::1"):
                from wsl_port.vendor.port_forwarder.utils.secrets import SecretsStore as _SS
                _sec = _SS()
                eff = web_pw or cfg.ui.web_panel_token or (
                    _sec.get("web_panel_token") if _sec.check("web_panel_token") else "")
                if len(eff) < 24:
                    messagebox.showerror("Ajustes",
                        f"Con bind expuesto ({bind}) la clave debe tener al "
                        "menos 24 caracteres.\nUsa 'Generar clave fuerte'.\n\n"
                        "Recuerda: el panel sirve HTTP sin TLS; considera "
                        "bind 127.0.0.1 y acceso por tunel SSH.")
                    return
            if web_pw:
                from wsl_port.vendor.port_forwarder.utils.secrets import SecretsStore
                SecretsStore().set("web_panel_token", web_pw)
            cfg.api.enabled = self.api_enabled_var.get()
            cfg.api.port = int(self.api_port_var.get() or 8781)
            mcp_on = self.mcp_enabled_var.get()
            mcp_token = self.mcp_key_var.get()
            # Solo se genera un token nuevo si NO existe ninguno: antes la app
            # regeneraba uno al azar en cada guardado y el MCP publicado quedaba
            # con una clave distinta a la del usuario.
            mcp_generated = False
            if (mcp_on and self.mcp_token_var.get() and not mcp_token
                    and not cfg.mcp.token):
                import secrets
                mcp_token = secrets.token_urlsafe(24)
                mcp_generated = True
            cfg.mcp.enabled = mcp_on
            cfg.mcp.transport = self.mcp_transport_var.get()
            cfg.mcp.port = int(self.mcp_port_var.get() or 8782)
            cfg.mcp.token_required = self.mcp_token_var.get()
            cfg.mcp.expose_exec = self.mcp_exec_var.get()
            if mcp_token:
                cfg.mcp.token = mcp_token
            if self.wsl_exe_var.get().strip():
                cfg.windows.wsl_exe = self.wsl_exe_var.get().strip()
            if self.ssh_exe_var.get().strip():
                cfg.windows.ssh_exe = self.ssh_exe_var.get().strip()
            if self.netsh_exe_var.get().strip():
                cfg.windows.netsh_exe = self.netsh_exe_var.get().strip()
            _set_autostart(self.auto_start_var.get())
            store.save()
            msg = "Ajustes guardados.\nEl tema se aplica al reiniciar."
            if mcp_generated:
                msg += f"\n\nToken MCP generado: {mcp_token}"
            if self.auto_start_var.get():
                msg += "\n\nAutoarranque con Windows: ACTIVADO."
            messagebox.showinfo("Ajustes", msg)
        except Exception as e:
            messagebox.showerror("Ajustes", f"Error: {e}")

    # -- WSL distro actions ---------------------------------------------------

    def _get_selected_distro(self) -> str | None:
        sel = self.distro_tree.selection()
        if not sel:
            from tkinter import messagebox
            messagebox.showwarning("Distros", "Selecciona una distro primero")
            return None
        return str(self.distro_tree.item(sel[0])["values"][0])

    def _start_selected_distro(self) -> None:
        name = self._get_selected_distro()
        if not name:
            return
        self._notify("WSL", f"Iniciando {name}...")
        def _work():
            r = core.start_distro(name)
            self._notify("WSL", f"{name} iniciado" if r.get("ok", True) else f"Error: {r.get('error')}")
            self._q.put({"_action": "refresh"})
        threading.Thread(target=_work, daemon=True).start()

    def _stop_selected_distro(self) -> None:
        name = self._get_selected_distro()
        if not name:
            return
        self._notify("WSL", f"Deteniendo {name}...")
        def _work():
            r = core.stop_distro(name)
            self._notify("WSL", f"{name} detenido" if r.get("ok", True) else f"Error: {r.get('error')}")
            self._q.put({"_action": "refresh"})
        threading.Thread(target=_work, daemon=True).start()

    def _restart_selected_distro(self) -> None:
        name = self._get_selected_distro()
        if not name:
            return
        self._notify("WSL", f"Reiniciando {name}...")
        def _work():
            r = core.restart_distro(name)
            self._notify("WSL", f"{name} reiniciado" if r.get("ok", True) else f"Error: {r.get('error')}")
            self._q.put({"_action": "refresh"})
        threading.Thread(target=_work, daemon=True).start()

    def _open_terminal(self) -> None:
        """Abrir una terminal en la distro WSL seleccionada."""
        name = self._get_selected_distro()
        if not name:
            return
        import subprocess
        try:
            subprocess.Popen(
                ["wt.exe", "wsl", "-d", name, "--cd", "/"],
                creationflags=0x08000000,
            )
            self._notify("Terminal", f"Terminal abierta en {name}")
        except FileNotFoundError:
            try:
                subprocess.Popen(
                    ["cmd.exe", "/c", "start", "cmd.exe", "/k", f"wsl -d {name} --cd /"],
                    creationflags=0x08000000,
                )
                self._notify("Terminal", f"Terminal abierta en {name}")
            except Exception as e:
                from tkinter import messagebox
                messagebox.showerror("Terminal", f"No se pudo abrir terminal: {e}")

    def _start_all_distros(self) -> None:
        self._notify("WSL", "Iniciando todas las distros...")
        def _work():
            for d in core.distros():
                if not d.get("running"):
                    core.start_distro(d["name"])
            self._notify("WSL", "Todas las distros iniciadas")
            self._q.put({"_action": "refresh"})
        threading.Thread(target=_work, daemon=True).start()

    def _shutdown_all_distros(self) -> None:
        from tkinter import messagebox
        if messagebox.askyesno("Apagar todas", "Apagar WSL completamente?"):
            self._notify("WSL", "Apagando WSL...")
            def _work():
                core.shutdown_all()
                self._notify("WSL", "WSL apagado")
                self._q.put({"_action": "refresh"})
            threading.Thread(target=_work, daemon=True).start()

    def _snapshot_selected(self) -> None:
        name = self._get_selected_distro()
        if not name:
            return
        self._notify("Snapshot", f"Creando snapshot de {name}...")
        from tkinter import messagebox
        def _work():
            r = core.snapshot(name)
            if r.get("ok"):
                self._notify("Snapshot", f"Snapshot de {name} creado")
                messagebox.showinfo("Snapshot", f"Snapshot creado:\n{r['path']}")
            else:
                self._notify("Snapshot", f"Error: {r.get('error')}")
                messagebox.showerror("Snapshot", f"Error: {r.get('error')}")
        threading.Thread(target=_work, daemon=True).start()

    def _show_metrics(self) -> None:
        name = self._get_selected_distro()
        if not name:
            return
        self._notify("Metricas", f"Obteniendo metricas de {name}...")
        from tkinter import messagebox
        m = core.distro_metrics(name)
        if m is None:
            messagebox.showinfo("Metricas", f"La distro '{name}' no esta corriendo o no responde")
            return
        ram = f"{m.get('ram_used_mb', 'N/A')}/{m.get('ram_total_mb', 'N/A')} MB ({m.get('ram_percent', 'N/A')}%)" if m.get('ram_total_mb') else 'N/A'
        msg = (f"Distro: {m['name']}\n"
               f"IP: {m.get('ip') or 'N/A'}\n"
               f"RAM: {ram}\n"
               f"CPUs: {m.get('cpus') or 'N/A'}\n"
               f"Uptime: {m.get('uptime_s', 0)}s")
        messagebox.showinfo("Metricas", msg)

    def _create_distro_dialog(self) -> None:
        from tkinter import messagebox
        available = core.list_available_distros()
        if not available:
            available = ["Ubuntu", "Debian", "kali-linux", "openSUSE-42",
                         "Ubuntu-20.04", "Ubuntu-22.04", "Ubuntu-24.04"]
        def _validate(data):
            if not data.get("name", "").strip():
                raise ValueError("Selecciona una distro")
        fields = [("name", "Distro a instalar", "combo")]
        dlg = _FormDialog(self.root, "Crear nueva distro WSL", fields,
                          validate=_validate, size=(350, 180))
        dlg.set_combo_values("name", available)
        self.root.wait_window(dlg)
        if not dlg.result:
            return
        distro_name = dlg.result["name"].strip()
        self._notify("Crear distro", f"Instalando {distro_name}...")
        def _work():
            messagebox.showinfo("Crear distro",
                                f"Instalando '{distro_name}'...\nEsto puede tardar varios minutos.")
            r = core.create_distro(distro_name, no_launch=True)
            if r.get("ok"):
                self._notify("Crear distro", f"Distro '{distro_name}' instalada")
                messagebox.showinfo("Crear distro", f"Distro '{distro_name}' instalada correctamente")
            else:
                self._notify("Crear distro", f"Error: {r.get('error')}")
                messagebox.showerror("Crear distro", f"Error: {r.get('error')}")
            self._q.put({"_action": "refresh"})
        threading.Thread(target=_work, daemon=True).start()

    def _delete_selected_distro(self) -> None:
        name = self._get_selected_distro()
        if not name:
            return
        from tkinter import messagebox
        if not messagebox.askyesno("Eliminar distro",
                                   f"ATENCION: Esto eliminara la distro '{name}' y TODOS sus datos.\n\n"
                                   "¿Continuar?"):
            return
        self._notify("Eliminar distro", f"Eliminando {name}...")
        def _work():
            r = core.delete_distro(name)
            if r.get("ok"):
                self._notify("Eliminar distro", f"Distro '{name}' eliminada")
                messagebox.showinfo("Eliminar distro", f"Distro '{name}' eliminada")
            else:
                self._notify("Eliminar distro", f"Error: {r.get('error')}")
                messagebox.showerror("Eliminar distro", f"Error: {r.get('error')}")
            self._q.put({"_action": "refresh"})
        threading.Thread(target=_work, daemon=True).start()

    def _export_selected_distro(self) -> None:
        name = self._get_selected_distro()
        if not name:
            return
        from tkinter import messagebox
        target = filedialog.asksaveasfilename(
            title=f"Exportar distro '{name}'", defaultextension=".tar",
            filetypes=[("TAR files", "*.tar"), ("All files", "*.*")],
            initialfile=f"{name}.tar")
        if not target:
            return
        self._notify("Exportar", f"Exportando {name}...")
        def _work():
            r = core.export_distro(name, target)
            if r.get("ok"):
                self._notify("Exportar", f"Distro '{name}' exportada a {target}", "success")
                messagebox.showinfo("Exportar", f"Distro '{name}' exportada a:\n{target}")
            else:
                self._notify("Exportar", f"Error: {r.get('error')}", "error")
                messagebox.showerror("Exportar", f"Error: {r.get('error')}")
            self._q.put({"_action": "refresh"})
        threading.Thread(target=_work, daemon=True).start()

    def _import_distro_dialog(self) -> None:
        from tkinter import messagebox
        source = filedialog.askopenfilename(
            title="Seleccionar archivo .tar para importar",
            filetypes=[("TAR files", "*.tar"), ("All files", "*.*")])
        if not source:
            return
        def _validate(data):
            if not data.get("name", "").strip():
                raise ValueError("El nombre es obligatorio")
            if not data.get("install_dir", "").strip():
                raise ValueError("El directorio de instalacion es obligatorio")
        fields = [
            ("name", "Nombre de la nueva distro", "entry"),
            ("install_dir", "Directorio de instalacion", "entry"),
        ]
        dlg = _FormDialog(self.root, "Importar distro", fields,
                          validate=_validate, size=(400, 200))
        import os
        default_dir = os.path.join(os.environ.get("LOCALAPPDATA", ""), "WSL", "distros")
        dlg._vars["install_dir"].set(default_dir)
        self.root.wait_window(dlg)
        if not dlg.result:
            return
        distro_name = dlg.result["name"].strip()
        install_dir = dlg.result["install_dir"].strip()
        self._notify("Importar", f"Importando {distro_name}...")
        def _work():
            r = core.import_distro(source, distro_name, install_dir)
            if r.get("ok"):
                final_dir = r.get("install_dir") or install_dir
                self._notify("Importar", f"Distro '{distro_name}' importada en {final_dir}", "success")
                messagebox.showinfo("Importar", f"Distro '{distro_name}' importada correctamente en:\n{final_dir}")
            else:
                self._notify("Importar", f"Error: {r.get('error')}", "error")
                messagebox.showerror("Importar", f"Error: {r.get('error')}")
            self._q.put({"_action": "refresh"})
        threading.Thread(target=_work, daemon=True).start()

    # -- Tunnel actions -------------------------------------------------------

    def _get_selected_tunnel(self) -> str | None:
        sel = self.tun_tree.selection()
        if not sel:
            from tkinter import messagebox
            messagebox.showwarning("Tunnels", "Selecciona un tunnel primero")
            return None
        return str(self.tun_tree.item(sel[0])["values"][0])

    def _add_tunnel_dialog(self) -> None:
        vps_list = core.vps_list()
        if not vps_list:
            from tkinter import messagebox
            messagebox.showwarning("Tunnels", "Primero crea un VPS en la seccion Servidores VPS")
            return
        def _validate(data):
            if not data.get("id", "").strip():
                raise ValueError("El ID es obligatorio")
            if not data.get("local_port", 0):
                raise ValueError("El puerto local es obligatorio")
            if not data.get("remote_port", 0):
                raise ValueError("El puerto remoto es obligatorio")
        fields = [
            ("id", "ID del tunnel", "entry"),
            ("vps_id", "VPS destino", "combo"),
            ("local_port", "Puerto local (WSL)", "int"),
            ("remote_port", "Puerto publico (VPS)", "int"),
            ("local_host", "Host local", "entry"),
            ("remote_host", "Host remoto", "entry"),
        ]
        dlg = _FormDialog(self.root, "Nuevo Tunnel SSH", fields, validate=_validate)
        dlg._vars["local_host"].set("127.0.0.1")
        dlg._vars["remote_host"].set("0.0.0.0")
        vps_ids = [v["id"] for v in vps_list]
        dlg.set_combo_values("vps_id", vps_ids)
        self.root.wait_window(dlg)
        if not dlg.result:
            return
        data = dlg.result
        self._notify("Tunnel", f"Creando tunnel '{data['id']}'...")
        r = core.add_tunnel(
            tun_id=data["id"].strip(), vps_id=data["vps_id"].strip(),
            local_host=data.get("local_host", "127.0.0.1").strip() or "127.0.0.1",
            local_port=int(data["local_port"]),
            remote_host=data.get("remote_host", "0.0.0.0").strip() or "0.0.0.0",
            remote_port=int(data["remote_port"]))
        from tkinter import messagebox
        if r.get("ok"):
            self._notify("Tunnel", f"Tunnel '{data['id']}' creado")
            messagebox.showinfo("Tunnel", f"Tunnel '{data['id']}' creado")
            self._refresh()
        else:
            self._notify("Tunnel", f"Error: {r.get('error')}")
            messagebox.showerror("Tunnel", f"Error: {r.get('error')}")

    def _start_selected_tunnel(self) -> None:
        tid = self._get_selected_tunnel()
        if not tid:
            return
        self._notify("Tunnel", f"Iniciando {tid}...")
        def _work():
            r = core.start_tunnel(tid)
            self._notify("Tunnel", f"{tid} iniciado" if r.get("ok") else f"Error: {r.get('error')}")
            self._q.put({"_action": "refresh"})
        threading.Thread(target=_work, daemon=True).start()

    def _stop_selected_tunnel(self) -> None:
        tid = self._get_selected_tunnel()
        if not tid:
            return
        self._notify("Tunnel", f"Deteniendo {tid}...")
        def _work():
            r = core.stop_tunnel(tid)
            self._notify("Tunnel", f"{tid} detenido" if r.get("ok") else f"Error: {r.get('error')}")
            self._q.put({"_action": "refresh"})
        threading.Thread(target=_work, daemon=True).start()

    def _restart_selected_tunnel(self) -> None:
        tid = self._get_selected_tunnel()
        if not tid:
            return
        self._notify("Tunnel", f"Reiniciando {tid}...")
        def _work():
            r = core.restart_tunnel(tid)
            self._notify("Tunnel", f"{tid} reiniciado" if r.get("ok") else f"Error: {r.get('error')}")
            self._q.put({"_action": "refresh"})
        threading.Thread(target=_work, daemon=True).start()

    def _edit_selected_tunnel(self) -> None:
        tid = self._get_selected_tunnel()
        if not tid:
            return
        vps_list = core.vps_list()
        if not vps_list:
            from tkinter import messagebox
            messagebox.showwarning("Tunnels", "Primero crea un VPS en la seccion Servidores VPS")
            return
        store = core.pf_store()
        tun = store.get_tunnel(tid)
        if not tun:
            from tkinter import messagebox
            messagebox.showerror("Tunnel", f"Tunnel '{tid}' no encontrado")
            return
        def _validate(data):
            if not data.get("vps_id", "").strip():
                raise ValueError("El VPS es obligatorio")
        fields = [
            ("vps_id", "VPS destino", "combo"),
            ("local_host", "Host local", "entry"),
            ("local_port", "Puerto local", "int"),
            ("remote_host", "Host remoto", "entry"),
            ("remote_port", "Puerto remoto", "int"),
            ("auto_start", "Auto-iniciar", "bool"),
        ]
        dlg = _FormDialog(self.root, f"Editar Tunnel '{tid}'", fields, validate=_validate)
        dlg._vars["vps_id"].set(tun.vps_id)
        dlg._vars["local_host"].set(tun.local_bind.host)
        dlg._vars["local_port"].set(tun.local_bind.port)
        dlg._vars["remote_host"].set(tun.remote_binds[0].host if tun.remote_binds else "0.0.0.0")
        dlg._vars["remote_port"].set(tun.remote_binds[0].port if tun.remote_binds else 0)
        dlg._vars["auto_start"].set(tun.auto_start)
        vps_ids = [v["id"] for v in vps_list]
        dlg.set_combo_values("vps_id", vps_ids)
        self.root.wait_window(dlg)
        if not dlg.result:
            return
        data = dlg.result
        self._notify("Tunnel", f"Actualizando tunnel '{tid}'...")
        r = core.update_tunnel(
            tid,
            vps_id=data["vps_id"].strip(),
            local=f"{data.get('local_host', '127.0.0.1').strip() or '127.0.0.1'}:{data['local_port']}",
            remote=f"{data.get('remote_host', '0.0.0.0').strip() or '0.0.0.0'}:{data['remote_port']}",
            auto_start=bool(data.get("auto_start", True)),
        )
        from tkinter import messagebox
        if r.get("ok"):
            self._notify("Tunnel", f"Tunnel '{tid}' actualizado")
            messagebox.showinfo("Tunnel", f"Tunnel '{tid}' actualizado")
            self._refresh()
        else:
            self._notify("Tunnel", f"Error: {r.get('error')}")
            messagebox.showerror("Tunnel", f"Error: {r.get('error')}")

    def _remove_selected_tunnel(self) -> None:
        tid = self._get_selected_tunnel()
        if not tid:
            return
        from tkinter import messagebox
        if messagebox.askyesno("Eliminar tunnel", f"Eliminar tunnel '{tid}'?"):
            self._notify("Tunnel", f"Eliminando {tid}...")
            r = core.remove_tunnel(tid)
            if r.get("ok"):
                self._notify("Tunnel", f"{tid} eliminado")
                self._refresh()
            else:
                self._notify("Tunnel", f"Error: {r.get('error')}")
                messagebox.showerror("Tunnel", f"Error: {r.get('error')}")

    # -- VPS actions ----------------------------------------------------------

    def _get_selected_vps(self) -> str | None:
        sel = self.vps_tree.selection()
        if not sel:
            from tkinter import messagebox
            messagebox.showwarning("VPS", "Selecciona un VPS primero")
            return None
        return str(self.vps_tree.item(sel[0])["values"][0])

    def _add_vps_dialog(self) -> None:
        def _validate(data):
            if not data.get("id", "").strip():
                raise ValueError("El ID es obligatorio")
            if not data.get("host", "").strip():
                raise ValueError("El host es obligatorio")
        fields = [
            ("id", "ID del VPS", "entry"),
            ("host", "Host / IP", "entry"),
            ("user", "Usuario SSH", "entry"),
            ("port", "Puerto SSH", "int"),
            ("identity_file", "Clave SSH (key file)", "file"),
            ("password", "Contrasena SSH", "password"),
        ]
        dlg = _FormDialog(self.root, "Nuevo VPS", fields, validate=_validate, size=(450, 380))
        dlg._vars["user"].set("debian")
        dlg._vars["port"].set(22)
        self.root.wait_window(dlg)
        if not dlg.result:
            return
        data = dlg.result
        self._notify("VPS", f"Creando VPS '{data['id']}'...")
        r = core.add_vps(
            vps_id=data["id"].strip(), host=data["host"].strip(),
            user=data.get("user", "").strip(), port=int(data.get("port", 22) or 22),
            identity_file=data.get("identity_file", "").strip(),
            password=data.get("password", "").strip())
        from tkinter import messagebox
        if r.get("ok"):
            self._notify("VPS", f"VPS '{data['id']}' creado")
            messagebox.showinfo("VPS", f"VPS '{data['id']}' creado")
            self._refresh()
        else:
            self._notify("VPS", f"Error: {r.get('error')}")
            messagebox.showerror("VPS", f"Error: {r.get('error')}")

    def _edit_vps_selected(self) -> None:
        vps_id = self._get_selected_vps()
        if not vps_id:
            return
        vps = next((v for v in core.vps_list() if v.get("id") == vps_id), None)
        if not vps:
            from tkinter import messagebox
            messagebox.showerror("VPS", f"VPS '{vps_id}' no encontrado")
            return
        def _validate(data):
            if not data.get("host", "").strip():
                raise ValueError("El host es obligatorio")
        fields = [
            ("host", "Host / IP", "entry"),
            ("user", "Usuario SSH", "entry"),
            ("port", "Puerto SSH", "int"),
            ("identity_file", "Clave SSH (key file)", "file"),
            ("password", "Contrasena SSH", "password"),
        ]
        dlg = _FormDialog(self.root, f"Editar VPS: {vps_id}", fields, validate=_validate, size=(450, 350))
        dlg._vars["host"].set(vps.get("host", ""))
        dlg._vars["user"].set(vps.get("user", ""))
        dlg._vars["port"].set(vps.get("port", 22))
        dlg._vars["identity_file"].set(vps.get("identity_file", ""))
        dlg._vars["password"].set(vps.get("password", ""))
        self.root.wait_window(dlg)
        if not dlg.result:
            return
        data = dlg.result
        self._notify("VPS", f"Actualizando VPS '{vps_id}'...")
        core.remove_vps(vps_id)
        r = core.add_vps(
            vps_id=vps_id, host=data["host"].strip(),
            user=data.get("user", "").strip(), port=int(data.get("port", 22) or 22),
            identity_file=data.get("identity_file", "").strip(),
            password=data.get("password", "").strip())
        from tkinter import messagebox
        if r.get("ok"):
            self._notify("VPS", f"VPS '{vps_id}' actualizado")
            messagebox.showinfo("VPS", f"VPS '{vps_id}' actualizado")
            self._refresh()
        else:
            self._notify("VPS", f"Error: {r.get('error')}")
            messagebox.showerror("VPS", f"Error: {r.get('error')}")

    def _remove_vps_selected(self) -> None:
        vps_id = self._get_selected_vps()
        if not vps_id:
            return
        from tkinter import messagebox
        if messagebox.askyesno("Eliminar VPS", f"Eliminar VPS '{vps_id}'?"):
            self._notify("VPS", f"Eliminando VPS '{vps_id}'...")
            r = core.remove_vps(vps_id)
            if r.get("ok"):
                self._notify("VPS", f"VPS '{vps_id}' eliminado")
                self._refresh()
            else:
                self._notify("VPS", f"Error: {r.get('error')}")
                messagebox.showerror("VPS", f"Error: {r.get('error')}")

    # -- Forward actions ------------------------------------------------------

    def _get_selected_forward(self) -> str | None:
        sel = self.fwd_tree.selection()
        if not sel:
            from tkinter import messagebox
            messagebox.showwarning("Forwards", "Selecciona un forward primero")
            return None
        return str(self.fwd_tree.item(sel[0])["values"][0])

    def _add_forward_dialog(self) -> None:
        distros = core.distros()
        distro_names = [d["name"] for d in distros]
        def _validate(data):
            if not data.get("id", "").strip():
                raise ValueError("El ID es obligatorio")
            if not data.get("listen_port", 0):
                raise ValueError("El puerto listen es obligatorio")
            if not data.get("wsl_port", 0):
                raise ValueError("El puerto WSL es obligatorio")
            if not data.get("distro", "").strip():
                raise ValueError("La distro es obligatoria")
        fields = [
            ("id", "ID del forward", "entry"),
            ("listen_address", "Direccion listen", "combo"),
            ("listen_port", "Puerto listen (Windows)", "int"),
            ("distro", "Distro WSL", "combo"),
            ("wsl_port", "Puerto WSL", "int"),
            ("protocol", "Protocolo", "combo"),
        ]
        dlg = _FormDialog(self.root, "Nuevo Forward", fields, validate=_validate, size=(420, 380))
        dlg.set_combo_values("distro", distro_names)
        dlg.set_combo_values("protocol", ["tcp", "udp"])
        dlg.set_combo_values("listen_address", [
            "0.0.0.0 (todas)", "127.0.0.1 (loopback 1)", "127.0.0.2 (loopback 2)",
            "127.0.0.3 (loopback 3)", "127.0.0.4 (loopback 4)"])
        self.root.wait_window(dlg)
        if not dlg.result:
            return
        data = dlg.result
        listen_addr = data.get("listen_address", "0.0.0.0 (todas)")
        listen_addr = listen_addr.split(" ")[0].strip()
        self._notify("Forward", f"Creando forward '{data['id']}'...")
        r = core.add_forward(
            fwd_id=data["id"].strip(), listen_port=int(data["listen_port"]),
            wsl_distro=data["distro"].strip(), wsl_port=int(data["wsl_port"]),
            protocol=data.get("protocol", "tcp") or "tcp", listen_address=listen_addr)
        from tkinter import messagebox
        if r.get("ok"):
            self._notify("Forward", f"Forward '{data['id']}' creado")
            messagebox.showinfo("Forward", f"Forward '{data['id']}' creado")
            self._refresh()
        else:
            messagebox.showerror("Forward", f"Error: {r.get('error')}")

    def _remove_selected_forward(self) -> None:
        fwd_id = self._get_selected_forward()
        if not fwd_id:
            return
        from tkinter import messagebox
        if messagebox.askyesno("Eliminar forward", f"Eliminar forward '{fwd_id}'?"):
            self._notify("Forward", f"Eliminando forward '{fwd_id}'...")
            r = core.remove_forward(fwd_id)
            if r.get("ok"):
                self._notify("Forward", f"Forward '{fwd_id}' eliminado")
                self._refresh()
            else:
                self._notify("Forward", f"Error: {r.get('error')}")
                messagebox.showerror("Forward", f"Error: {r.get('error')}")

    def _apply_forwards(self) -> None:
        self._notify("Forward", "Aplicando forwards...")
        def _work():
            r = core.apply_forwards()
            self._notify("Forward", "Forwards aplicados" if r.get("ok") else f"Error: {r.get('error')}")
            self._q.put({"_action": "refresh"})
        threading.Thread(target=_work, daemon=True).start()

    def _clear_forwards(self) -> None:
        from tkinter import messagebox
        if messagebox.askyesno("Limpiar forwards", "Eliminar TODOS los forwards de netsh?"):
            self._notify("Forward", "Limpiando forwards...")
            def _work():
                r = core.clear_forwards()
                self._notify("Forward", "Forwards limpiados" if r.get("ok") else f"Error: {r.get('error')}")
                self._q.put({"_action": "refresh"})
            threading.Thread(target=_work, daemon=True).start()

    # -- Logs -----------------------------------------------------------------

    def _refresh_logs(self) -> None:
        try:
            from wsl_port.vendor.port_forwarder.utils.path import logs_dir
            log_file = logs_dir() / "port-forwarder.log"
            if log_file.exists():
                text = log_file.read_text(encoding="utf-8", errors="replace")
                lines = text.splitlines()[-200:]
                self.log_text.config(state="normal")
                self.log_text.delete("1.0", "end")
                self.log_text.insert("1.0", "\n".join(lines))
                self.log_text.config(state="disabled")
        except Exception:
            pass

    # -- datos / refresco ---------------------------------------------------------

    def _work(self, fast: bool = False):
        try:
            return core.status(fast=fast)
        except Exception as e:
            return {"error": str(e)}

    def _refresh(self, fast: bool = False) -> None:
        threading.Thread(target=self._worker, args=(fast,), daemon=True).start()

    def _refresh_full(self) -> None:
        """Manual refresh: re-probar WSL (tras reinicio) + IPs completas."""
        core.wsl_reset()  # cerrar breaker/cache por si WSL se reinicio
        self._refresh(fast=False)

    def _worker(self, fast: bool = False) -> None:
        try:
            self._q.put(self._work(fast=fast))
        except Exception as e:
            self._q.put({"error": str(e)})

    def _poll(self) -> None:
        try:
            self._apply()
        except Exception:
            pass
        self.root.after(200, self._poll)

    def _schedule_refresh(self) -> None:
        self._refresh(fast=True)  # Fast refresh for periodic updates
        self.root.after(30000, self._schedule_refresh)  # Every 30 seconds

    def _apply(self) -> None:
        while True:
            try:
                st = self._q.get_nowait()
            except queue.Empty:
                return
            if "_action" in st:
                if st["_action"] == "refresh":
                    self._refresh()
                elif st["_action"] == "notify":
                    self._show_activity(st.get("title", ""), st.get("message", ""),
                                        st.get("level", "info"))
                continue
            if "error" in st:
                self.status_var.set(f"error: {st['error']}")
                continue
            
            # Check WSL health
            wsl_hung = st.get("wsl_hung", False)
            if wsl_hung:
                breaker = st.get("wsl_breaker", {})
                text = "WSL no responde - reinicia el PC"
                if breaker.get("open"):
                    text = "WSL colgado - se re-probara en ~30s"
                self.header_status.configure(text=text, foreground="orange")
                continue
            
            up = sum(1 for d in st["distros"] if d.get("running"))
            tun_ok = sum(1 for t in st["tunnels"] if t.get("state") == "running")
            self.header_status.configure(
                text=f"distros {up}/{len(st['distros'])} · tuneles {tun_ok}/{len(st['tunnels'])}"
                     + (" · MANTENIMIENTO" if st["maintenance"] else ""),
                foreground="white")
            self._fill(self.distro_tree, [
                [d.get("name", "?"), d.get("state", "?"), d.get("ip") or "-",
                 str(d.get("version", "?"))] for d in st["distros"]])
            self._fill(self.tun_tree, [
                [t.get("id", "?"), t.get("type", "ssh"), t.get("vps_id", "?"),
                 t.get("local", "?"), ", ".join(t.get("remote") or []),
                 t.get("state", "?"), self._fmt_traffic(t.get("traffic"))] for t in st["tunnels"]])
            self._fill(self.vps_tree, [
                [v.get("id", "?"), v.get("host", "?"), v.get("user", "?"),
                 str(v.get("port", 22)),
                 "key" if v.get("identity_file") else ("pass" if v.get("password") else "-")]
                for v in st["vps"]])
            self._fill(self.fwd_tree, [
                [f.get("id", "?"), str(f.get("listen_port", "?")), f.get("wsl_distro", "?"),
                 str(f.get("wsl_port", "?")), f.get("protocol", "?"), f.get("state", "?")]
                for f in st["forwards"]])
            self.publish_tab.refresh_options()
            ts = datetime.datetime.now().strftime("%H:%M:%S")
            self.status_var.set(f"actualizado {ts} · supervisor {'ON' if st['supervisor_running'] else 'OFF'}")

    def _fill(self, tree, rows) -> None:
        tree.delete(*tree.get_children())
        for r in rows:
            tree.insert("", "end", values=r)

    def _fmt_traffic(self, tf) -> str:
        if not tf:
            return "-"
        return (f"rx {_fmt_bytes(tf.get('rx_bytes',0))} tx {_fmt_bytes(tf.get('tx_bytes',0))}"
                f" {_fmt_bytes(tf.get('rx_rate_bps',0))}/s {_fmt_bytes(tf.get('tx_rate_bps',0))}/s")


def run() -> None:
    if not _single_instance():
        return
    win = MainWindow()
    win.root.mainloop()


_MUTEX = None


def _single_instance() -> bool:
    """Evita abrir dos ventanas de wsl-port a la vez."""
    import ctypes
    global _MUTEX
    _MUTEX = ctypes.windll.kernel32.CreateMutexW(None, False, "wsl-port-unicidad")
    return ctypes.windll.kernel32.GetLastError() != 183  # ERROR_ALREADY_EXISTS
