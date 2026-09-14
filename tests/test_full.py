"""Tests completos de wsl-port: core + CLI + GUI (todos los botones).

Usa mocks para no depender de WSL real ni de windows nativo.
"""
from __future__ import annotations

import sys
import io
import time
import threading
import queue
from unittest import mock
from contextlib import redirect_stdout, redirect_stderr

import pytest

from wsl_port import core


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def mock_wsl(monkeypatch):
    """Mock wsl_health_check to always return True (healthy WSL)."""
    monkeypatch.setattr(core, "wsl_health_check", lambda force=False: True)
    monkeypatch.setattr(core, "wsl_is_hung", lambda: False)
    return monkeypatch


@pytest.fixture
def isolated_config(monkeypatch, tmp_path):
    """Apunta el singleton pf_store a un config temporal (aislamiento)."""
    from wsl_port.vendor.port_forwarder.core.config import ConfigStore
    store = ConfigStore(path=str(tmp_path / "config.json"))
    monkeypatch.setattr(core, "_pf_store", store)
    # el supervisor cachea su store: descartar cualquier instancia con store
    # live para que keepalive() nunca escriba la config real
    monkeypatch.setattr(core, "_supervisor", None)
    return store


@pytest.fixture
def empty_state(monkeypatch):
    """Estado vacio: sin distros, forwards, tunnels, vps.
    NOTA: no mockea forwards/tunnels/vps_list para no romper roundtrips.
    """
    monkeypatch.setattr(core, "distros", lambda skip_ips=False: [])
    return monkeypatch


# ---------------------------------------------------------------------------
# Core: WSL lifecycle
# ---------------------------------------------------------------------------

class FakeCmdResult:
    def __init__(self, ok=True, output="ok", error=""):
        self.ok = ok
        self.output = output
        self.error = error


class FakeDistro:
    def __init__(self, name, state="Stopped", version=2, default=False):
        self.name = name
        self.state = state
        self.version = version
        self.default = default


@pytest.fixture
def fake_provider(monkeypatch):
    """Reemplaza wsl_provider con un provider fake controlable."""
    class FakeProvider:
        def __init__(self):
            self.calls = []
            self.distros = [FakeDistro("Debian", "Running"), FakeDistro("Ubuntu")]
            self.start_result = FakeCmdResult()
            self.stop_result = FakeCmdResult()
            self.export_result = FakeCmdResult()
            self.import_result = FakeCmdResult()

        def list_distros(self):
            self.calls.append("list_distros")
            return self.distros

        def start(self, name):
            self.calls.append(("start", name))
            return self.start_result

        def stop(self, name):
            self.calls.append(("stop", name))
            return self.stop_result

        def restart(self, name):
            self.calls.append(("restart", name))
            return self.start_result

        def shutdown_all(self):
            self.calls.append("shutdown_all")
            return FakeCmdResult()

        def get_all_ips(self):
            self.calls.append("get_all_ips")
            return {"Debian": "172.26.1.1"}

        def install_new(self, name, no_launch=True):
            self.calls.append(("install", name))
            return FakeCmdResult()

        def metrics(self, name):
            return type("M", (), {"name": name, "running": True, "ip": "1.2.3.4",
                                  "ram_total_mb": 1024, "ram_used_mb": 512,
                                  "ram_percent": 50, "cpus": 4, "uptime_s": 100})()

        def snapshot(self, name):
            return "C:\\snapshots\\x.tar"

        def clone(self, name, new_name):
            return FakeCmdResult()

        def export(self, name, target):
            return self.export_result

        def import_distro(self, source, name, install_dir):
            return self.import_result

        def run_command(self, name, cmd):
            return FakeCmdResult()

    fp = FakeProvider()
    monkeypatch.setattr(core, "wsl_provider", lambda: fp)
    return fp


def test_distros_con_ips(fake_provider, mock_wsl, monkeypatch):
    monkeypatch.setattr(core, "_get_ip_fast", lambda name: "10.0.0.5")
    ds = core.distros()
    assert len(ds) == 2
    debian = ds[0]
    assert debian["name"] == "Debian"
    assert debian["running"] is True
    assert debian["ip"] == "10.0.0.5"


def test_distros_skip_ips(fake_provider, mock_wsl):
    ds = core.distros(skip_ips=True)
    assert ds[0]["ip"] is None


def test_start_stop_restart_distro(fake_provider, mock_wsl, isolated_config):
    r = core.start_distro("Debian")
    assert r["ok"] is True
    assert ("start", "Debian") in fake_provider.calls

    r = core.stop_distro("Debian")
    assert r["ok"] is True
    assert ("stop", "Debian") in fake_provider.calls

    r = core.restart_distro("Debian")
    assert r["ok"] is True


def test_shutdown_all_ok(fake_provider, mock_wsl, isolated_config):
    r = core.shutdown_all()
    assert r["ok"] is True
    assert "shutdown_all" in fake_provider.calls


def test_get_all_ips(fake_provider, mock_wsl):
    ips = core.get_all_ips()
    assert ips.get("Debian") == "172.26.1.1"


def test_create_delete_export_import(fake_provider, mock_wsl, isolated_config,
                                      monkeypatch, tmp_path):
    r = core.create_distro("Ubuntu")
    assert r["ok"] is True
    assert ("install", "Ubuntu") in fake_provider.calls

    monkeypatch.setattr("wsl_port.vendor.wsl_manager.utils.subprocess_async.run",
                        lambda *a, **k: FakeCmdResult())
    r = core.delete_distro("Ubuntu")
    assert r["ok"] is True

    target = str(tmp_path / "d.tar")
    fake_provider.export_result = FakeCmdResult(ok=True)
    r = core.export_distro("Debian", target)
    assert r["ok"] is True

    fake_provider.import_result = FakeCmdResult(ok=True)
    r = core.import_distro(target, "Nueva", "C:\\WSL\\Nueva")
    assert r["ok"] is True


def test_distro_metrics(fake_provider, mock_wsl):
    m = core.distro_metrics("Debian")
    assert m["name"] == "Debian"
    assert m["ram_percent"] == 50


def test_wsl_hung_returns_error(fake_provider, monkeypatch):
    monkeypatch.setattr(core, "wsl_health_check", lambda force=False: False)
    r = core.start_distro("Debian")
    assert r["ok"] is False
    assert "WSL no responde" in r["error"]


# ---------------------------------------------------------------------------
# Core: Forwards / Tunnels / VPS
# ---------------------------------------------------------------------------

def test_forwards_roundtrip(mock_wsl, isolated_config):
    r = core.add_forward("web", 8080, "Debian", 80, "tcp")
    assert r["ok"] is True
    r = core.remove_forward("web")
    assert r["ok"] is True
    r = core.add_forward("web2", 8081, "Debian", 81, "tcp", listen_address="127.0.0.2")
    assert r["ok"] is True
    fwds = core.forwards()
    assert any(f["id"] == "web2" for f in fwds)
    r = core.remove_forward("web2")
    assert r["ok"] is True


def test_tunnel_roundtrip(mock_wsl, isolated_config):
    r = core.add_vps("vps-test", "1.2.3.4", "debian", 22)
    assert r["ok"] is True
    r = core.add_tunnel("tun-test", "vps-test", "127.0.0.1", 9000, "0.0.0.0", 18097)
    assert r["ok"] is True
    tuns = core.tunnels()
    assert any(t["id"] == "tun-test" for t in tuns)
    r = core.remove_tunnel("tun-test")
    assert r["ok"] is True
    r = core.remove_vps("vps-test")
    assert r["ok"] is True


def test_vps_roundtrip(mock_wsl, isolated_config):
    r = core.add_vps("v1", "host1", "user1", 2222)
    assert r["ok"] is True
    vps = core.vps_list()
    assert any(v["id"] == "v1" and v["port"] == 2222 for v in vps)
    r = core.remove_vps("v1")
    assert r["ok"] is True


def test_start_stop_tunnel_error_sin_vps(empty_state, mock_wsl):
    # No tunnels -> error controlado
    r = core.start_tunnel("noexiste")
    assert r["ok"] is False
    r = core.stop_tunnel("noexiste")
    assert r["ok"] is False


# ---------------------------------------------------------------------------
# Core: schedule / profile / maintenance / secrets
# ---------------------------------------------------------------------------

def test_maintenance_roundtrip(empty_state, mock_wsl, monkeypatch):
    r = core.maintenance_on()
    assert r["ok"] is True
    st = core.maintenance_status()
    assert st["active"] is True
    r = core.maintenance_off()
    assert r["ok"] is True


def test_secrets_roundtrip(empty_state, mock_wsl):
    import secrets as _s
    ref = f"test-{_s.token_hex(4)}"
    r = core.secret_set(ref, "valor-secreto")
    assert r["ok"] is True
    r = core.secret_check(ref)
    assert r["ok"] is True and r["exists"] is True


def test_schedule_add_remove(mock_wsl, isolated_config):
    r = core.schedule_add("Mi Tarea", "forwards_apply", "08:00", ["mon"])
    assert r["ok"] is True
    tasks = core.schedule_list()
    assert len(tasks) >= 1
    tid = tasks[-1]["id"]
    r = core.schedule_remove(tid)
    assert r["ok"] is True


def test_profile_capture_apply(mock_wsl, isolated_config):
    r = core.profile_capture("perfil-test", "para tests")
    assert r["ok"] is True
    profs = core.profile_list()
    assert any(p["name"] == "perfil-test" for p in profs)


def test_doctor_and_status_shape(empty_state, mock_wsl):
    st = core.status()
    for k in ["distros", "forwards", "tunnels", "vps", "wsl_healthy"]:
        assert k in st


def test_wslconfig_limits_roundtrip(monkeypatch, tmp_path):
    """get/set_global_limits lee y escribe .wslconfig sin modo bridged."""
    fake = tmp_path / ".wslconfig"
    monkeypatch.setattr(core, "wslconfig_path", lambda: fake)
    # escribir
    r = core.set_global_limits(memory_gb=8, processors=3, swap_gb=2,
                                default_vhd_gb=128, auto_memory_reclaim="gradual",
                                sparse_vhd="true", localhost_forwarding="true")
    assert r["ok"] is True
    content = fake.read_text(encoding="utf-8")
    assert "memory=8GB" in content
    assert "processors=3" in content
    assert "swap=2GB" in content
    assert "defaultVhdSize=128GB" in content
    assert "autoMemoryReclaim=gradual" in content
    assert "sparseVhd=true" in content
    assert "localhostForwarding=true" in content
    assert "networkingMode" not in content.lower(), "nunca debe escribir bridged"
    # leer
    limits = core.get_global_limits()
    assert limits["exists"] is True
    assert limits["memory_gb"] == 8.0
    assert limits["processors"] == 3
    assert limits["swap_gb"] == 2.0
    assert limits["default_vhd_gb"] == 128.0
    assert limits["auto_memory_reclaim"] == "gradual"
    assert limits["sparse_vhd"] == "true"
    assert limits["localhost_forwarding"] == "true"


def test_wslconfig_reclaim_invalido(monkeypatch, tmp_path):
    fake = tmp_path / ".wslconfig"
    monkeypatch.setattr(core, "wslconfig_path", lambda: fake)
    r = core.set_global_limits(auto_memory_reclaim="loco")
    assert r["ok"] is False
    assert "debe ser uno de" in r["error"]


def test_wslconfig_limits_noexiste(monkeypatch, tmp_path):
    fake = tmp_path / "no-existe.wslconfig"
    monkeypatch.setattr(core, "wslconfig_path", lambda: fake)
    limits = core.get_global_limits()
    assert limits["exists"] is False
    assert limits["memory_gb"] is None


# ---------------------------------------------------------------------------
# CLI: all command handlers run
# ---------------------------------------------------------------------------

def run_cli(args):
    import wsl_port.cli as cli
    out = io.StringIO()
    err = io.StringIO()
    code = 1
    try:
        with redirect_stdout(out), redirect_stderr(err):
            code = cli.main(args)
    except SystemExit as e:
        code = e.code if isinstance(e.code, int) else 1
    except Exception as e:
        return code, out.getvalue(), err.getvalue(), str(e)
    return code, out.getvalue(), err.getvalue(), None


@pytest.mark.parametrize("args", [
    ["status"],
    ["--json", "status"],
    ["distro", "list"],
    ["distro", "ips"],
    ["distro", "available"],
    ["autostart", "list"],
    ["forwards", "list"],
    ["tunnels", "list"],
    ["vps", "list"],
    ["alerts", "list"],
    ["schedule", "list"],
    ["profile", "list"],
    ["maintenance", "status"],
    ["drift"],
    ["doctor"],
    ["config", "validate"],
    ["secrets", "check", "web_panel_token"],
])
def test_cli_read_commands(mock_wsl, empty_state, args, monkeypatch):
    # Comandos que dependen de red/WSL real se mockean
    if args[-1] == "available":
        monkeypatch.setattr(core, "list_available_distros", lambda: ["Ubuntu", "Debian"])
    if "doctor" in args:
        monkeypatch.setattr(core, "doctor",
                            lambda: {"ok": True, "checks": [{"check": "x", "ok": True, "message": "ok"}]})
    if args == ["drift"]:
        monkeypatch.setattr(core, "drift_check",
                            lambda: {"ok": True, "drift": [], "total": 0})
    code, out, err, exc = run_cli(args)
    assert exc is None, f"EXC: {exc}"
    assert code == 0, f"rc={code} err={err}"


@pytest.mark.parametrize("args", [
    ["distro", "start", "Debian"],
    ["distro", "stop", "Debian"],
    ["distro", "restart", "Debian"],
    ["distro", "metrics", "Debian"],
])
def test_cli_distro_actions(mock_wsl, fake_provider, args):
    code, out, err, exc = run_cli(args)
    assert exc is None
    assert code == 0


def test_cli_maintenance_on_off(mock_wsl, empty_state):
    code, out, err, exc = run_cli(["maintenance", "on"])
    assert exc is None and code == 0
    code, out, err, exc = run_cli(["maintenance", "off"])
    assert exc is None and code == 0


def test_cli_vps_add_remove(mock_wsl, empty_state):
    code, out, err, exc = run_cli(
        ["vps", "add", "--id", "cvps", "--host", "9.9.9.9", "--user", "root"])
    assert exc is None and code == 0
    code, out, err, exc = run_cli(["vps", "remove", "cvps"])
    assert exc is None and code == 0


# ---------------------------------------------------------------------------
# GUI: todos los botones
# ---------------------------------------------------------------------------

class _FakeVar:
    """Variable tkinter sin Tk real."""
    def __init__(self, value=""):
        self._value = value

    def set(self, value):
        self._value = value

    def get(self):
        return self._value


class _FakeBool(_FakeVar):
    def __init__(self, value=False):
        self._value = value


@pytest.fixture
def gui(monkeypatch, mock_wsl, empty_state):
    """Crea un objeto MainWindow sin UI real (con mocks) para probar handlers."""
    monkeypatch.setattr("wsl_port.ui.main_window._single_instance", lambda: True)
    monkeypatch.setattr("wsl_port.ui.main_window.autostart_active", lambda: False)
    from wsl_port.ui.main_window import MainWindow
    win = MainWindow.__new__(MainWindow)
    win.root = mock.MagicMock()
    win._q = queue.Queue()
    win.status_var = _FakeVar()
    win.header_status = mock.MagicMock()
    win.distro_tree = mock.MagicMock()
    win.tun_tree = mock.MagicMock()
    win.vps_tree = mock.MagicMock()
    win.fwd_tree = mock.MagicMock()
    win.log_text = mock.MagicMock()
    win.web_port_var = _FakeVar("8780")
    win.web_bind_var = _FakeVar("127.0.0.1")
    win.web_pw_var = _FakeVar()
    win.web_enabled_var = _FakeBool(True)
    win.api_enabled_var = _FakeBool(False)
    win.api_port_var = _FakeVar("8781")
    win.api_scope_var = _FakeVar("write")
    win.mcp_enabled_var = _FakeBool(False)
    win.mcp_transport_var = _FakeVar("stdio")
    win.mcp_port_var = _FakeVar("8782")
    win.mcp_token_var = _FakeBool(True)
    win.mcp_key_var = _FakeVar()
    win.mcp_exec_var = _FakeBool(False)
    win.theme_var = _FakeVar("superhero")
    win.tray_var = _FakeBool(True)
    win.keep_tunnels_var = _FakeBool(True)
    win.stop_distros_var = _FakeBool(False)
    win.min_var = _FakeBool(False)
    win.auto_start_var = _FakeBool(False)
    win.sup_interval_var = _FakeVar("10")
    win.metrics_retention_var = _FakeVar("30")
    win.wsl_exe_var = _FakeVar()
    win.ssh_exe_var = _FakeVar()
    win.netsh_exe_var = _FakeVar()

    class PT:
        def refresh_options(self):
            pass
    win.publish_tab = PT()
    return win


def test_gui_notify_muestra_banner(gui):
    """_notify encola un mensaje que _apply pinta en el banner."""
    gui.activity_var = _FakeVar()
    gui.activity_lbl = mock.MagicMock()
    gui._notify("WSL", "Iniciando Debian...", "info")
    assert not gui._q.empty()
    item = gui._q.get_nowait()
    assert item["_action"] == "notify"
    assert item["title"] == "WSL"
    # _apply procesa y pinta el banner
    gui._q.put(item)
    gui._apply()
    assert "Iniciando Debian" in gui.activity_var.get()
    gui.activity_lbl.configure.assert_called()


def test_gui_apply_state(gui):
    """_apply pinta el estado recibido en la cola."""
    st = {
        "distros": [{"name": "Debian", "state": "Running", "ip": "1.2.3.4",
                     "version": 2, "running": True}],
        "tunnels": [], "vps": [], "forwards": [],
        "maintenance": False, "supervisor_running": True, "wsl_hung": False,
    }
    gui._q.put(st)
    gui._apply()
    gui.distro_tree.delete.assert_called()
    gui.distro_tree.insert.assert_called()


def test_gui_apply_wsl_hung(gui):
    """Si WSL no responde, muestra aviso y no pinta distros."""
    st = {"distros": [], "forwards": [], "tunnels": [], "vps": [],
          "maintenance": False, "supervisor_running": False, "wsl_hung": True}
    gui._q.put(st)
    gui._apply()
    gui.header_status.configure.assert_called()
    assert "WSL no responde" in gui.header_status.configure.call_args.kwargs["text"]


def test_gui_button_handlers_exist():
    """Todos los handlers de botones existen y son llamables."""
    from wsl_port.ui.main_window import MainWindow
    handlers = [
        "_refresh_full", "_start_selected_distro", "_stop_selected_distro",
        "_restart_selected_distro", "_start_all_distros", "_shutdown_all_distros",
        "_snapshot_selected", "_show_metrics", "_open_terminal",
        "_create_distro_dialog", "_delete_selected_distro",
        "_export_selected_distro", "_import_distro_dialog",
        "_add_tunnel_dialog", "_start_selected_tunnel", "_stop_selected_tunnel",
        "_remove_selected_tunnel", "_add_vps_dialog", "_edit_vps_selected",
        "_remove_vps_selected", "_add_forward_dialog", "_remove_selected_forward",
        "_apply_forwards", "_clear_forwards", "_refresh_logs",
        "_save_settings", "_gen_api_token", "_load_settings_values",
    ]
    for h in handlers:
        assert callable(getattr(MainWindow, h, None)), f"{h} no existe"


def test_gui_distro_start_queues_refresh(monkeypatch, gui, fake_provider):
    """_start_selected_distro lanza trabajo en thread y encola refresh."""
    from wsl_port.ui.main_window import MainWindow
    calls = {"notify": []}

    monkeypatch.setattr(MainWindow, "_notify",
                        lambda self, t, m, level="info": calls["notify"].append((t, m)))
    monkeypatch.setattr(MainWindow, "_get_selected_distro", lambda self: "Debian")
    monkeypatch.setattr(core, "start_distro", lambda name: {"ok": True})

    gui._start_selected_distro()
    time.sleep(0.4)
    assert not gui._q.empty()
    assert gui._q.get_nowait() == {"_action": "refresh"}
    assert calls["notify"]


def test_gui_distro_stop_queues_refresh(monkeypatch, gui, fake_provider):
    from wsl_port.ui.main_window import MainWindow
    calls = {"notify": []}
    monkeypatch.setattr(MainWindow, "_notify",
                        lambda self, t, m, level="info": calls["notify"].append((t, m)))
    monkeypatch.setattr(MainWindow, "_get_selected_distro", lambda self: "Debian")
    monkeypatch.setattr(core, "stop_distro", lambda name: {"ok": True})

    gui._stop_selected_distro()
    time.sleep(0.4)
    assert not gui._q.empty()
    assert gui._q.get_nowait() == {"_action": "refresh"}
    assert calls["notify"]


def test_gui_export_descarga_directa(monkeypatch, gui):
    """Exportar usa dialogo guardar + core.export_distro (sin navegador)."""
    from wsl_port.ui.main_window import MainWindow
    monkeypatch.setattr(MainWindow, "_get_selected_distro", lambda self: "Debian")
    monkeypatch.setattr("wsl_port.ui.main_window.filedialog.asksaveasfilename",
                        lambda **k: "C:\\tmp\\Debian.tar")
    exported = []
    monkeypatch.setattr(core, "export_distro",
                        lambda name, target: exported.append((name, target)) or {"ok": True})
    monkeypatch.setattr(MainWindow, "_notify",
                        lambda self, t, m, level="info": None)
    monkeypatch.setattr("tkinter.messagebox.showinfo", lambda *a, **k: None)
    monkeypatch.setattr("wsl_port.ui.main_window.webbrowser", mock.MagicMock())
    gui._export_selected_distro()
    time.sleep(0.4)
    assert exported, "debe llamar core.export_distro"
    assert exported[0] == ("Debian", "C:\\tmp\\Debian.tar")
    # No debe abrir navegador
    assert not gui._q.empty()  # encola refresh


def test_gui_import_usa_dialogo_archivo(monkeypatch, gui):
    """Importar usa dialogo abrir + formulario + core.import_distro (sin navegador)."""
    from wsl_port.ui.main_window import MainWindow, _FormDialog
    monkeypatch.setattr("wsl_port.ui.main_window.filedialog.askopenfilename",
                        lambda **k: "C:\\tmp\\backup.tar")

    class FakeDlg:
        def __init__(self):
            self.result = {"name": "nueva-distro",
                           "install_dir": "C:\\WSL\\nueva-distro"}
            self._vars = {"install_dir": mock.MagicMock()}

    monkeypatch.setattr("wsl_port.ui.main_window._FormDialog", lambda *a, **k: FakeDlg())
    imported = []
    monkeypatch.setattr(core, "import_distro",
                        lambda source, name, install_dir: imported.append(
                            (source, name, install_dir)) or {"ok": True})
    monkeypatch.setattr(MainWindow, "_notify",
                        lambda self, t, m, level="info": None)
    monkeypatch.setattr("tkinter.messagebox.showinfo", lambda *a, **k: None)
    monkeypatch.setattr("wsl_port.ui.main_window.webbrowser", mock.MagicMock())
    gui.root.wait_window = lambda dlg: None
    gui._import_distro_dialog()
    time.sleep(0.4)
    assert imported, "debe llamar core.import_distro"
    assert imported[0][0] == "C:\\tmp\\backup.tar"
    assert imported[0][1] == "nueva-distro"


def test_gui_add_forward_dialog(monkeypatch, gui):
    """El dialogo de forward llama a core.add_forward con datos del form."""
    from wsl_port.ui.main_window import MainWindow, _FormDialog
    monkeypatch.setattr(core, "distros", lambda skip_ips=False: [{"name": "Debian"}])
    added = []
    monkeypatch.setattr(core, "add_forward",
                        lambda **kw: added.append(kw) or {"ok": True, "message": "ok"})

    class FakeDlg:
        def __init__(self):
            self.result = {"id": "fwd1", "listen_address": "127.0.0.1 (loopback 1)",
                           "listen_port": 8080, "distro": "Debian",
                           "wsl_port": 80, "protocol": "tcp"}
            self._vars = {}

        def set_combo_values(self, key, values):
            pass

    monkeypatch.setattr(MainWindow, "_refresh", lambda self: None)
    monkeypatch.setattr("wsl_port.ui.main_window._FormDialog", lambda *a, **k: FakeDlg())
    monkeypatch.setattr("tkinter.messagebox.showinfo", lambda *a, **k: None)
    monkeypatch.setattr("tkinter.messagebox.showerror", lambda *a, **k: None)

    gui.root.wait_window = lambda dlg: None
    gui._add_forward_dialog()
    assert added, "add_forward debe ser llamado"
    assert added[0]["listen_address"] == "127.0.0.1"


def test_gui_add_vps_dialog(monkeypatch, gui):
    from wsl_port.ui.main_window import MainWindow
    added = []
    monkeypatch.setattr(core, "add_vps",
                        lambda **kw: added.append(kw) or {"ok": True, "message": "ok"})

    class FakeDlg:
        def __init__(self):
            self.result = {"id": "vps1", "host": "1.2.3.4", "user": "debian",
                           "port": 22, "identity_file": "", "password": ""}
            self._vars = {"user": mock.MagicMock(), "port": mock.MagicMock()}

        def set_combo_values(self, key, values):
            pass

    monkeypatch.setattr("wsl_port.ui.main_window._FormDialog", lambda *a, **k: FakeDlg())
    monkeypatch.setattr(MainWindow, "_refresh", lambda self: None)
    monkeypatch.setattr("tkinter.messagebox.showinfo", lambda *a, **k: None)

    gui.root.wait_window = lambda dlg: None
    gui._add_vps_dialog()
    assert added
    assert added[0]["host"] == "1.2.3.4"


def test_gui_add_tunnel_dialog(monkeypatch, gui):
    from wsl_port.ui.main_window import MainWindow
    monkeypatch.setattr(core, "vps_list", lambda: [{"id": "vps1"}])
    added = []
    monkeypatch.setattr(core, "add_tunnel",
                        lambda **kw: added.append(kw) or {"ok": True, "message": "ok"})

    class FakeDlg:
        def __init__(self):
            self.result = {"id": "tun1", "vps_id": "vps1", "local_host": "127.0.0.1",
                           "local_port": 9000, "remote_host": "0.0.0.0", "remote_port": 18097}
            self._vars = {"local_host": mock.MagicMock(), "remote_host": mock.MagicMock()}

        def set_combo_values(self, key, values):
            pass

    monkeypatch.setattr("wsl_port.ui.main_window._FormDialog", lambda *a, **k: FakeDlg())
    monkeypatch.setattr(MainWindow, "_refresh", lambda self: None)
    monkeypatch.setattr("tkinter.messagebox.showinfo", lambda *a, **k: None)

    gui.root.wait_window = lambda dlg: None
    gui._add_tunnel_dialog()
    assert added
    assert added[0]["local_port"] == 9000


def test_gui_save_settings(monkeypatch, gui):
    from wsl_port.ui.main_window import MainWindow
    saved = []
    monkeypatch.setattr(core, "pf_store",
                        lambda: mock.MagicMock(cfg=mock.MagicMock()))
    monkeypatch.setattr("wsl_port.ui.main_window._set_autostart", lambda active: saved.append(active))
    monkeypatch.setattr("tkinter.messagebox.showinfo", lambda *a, **k: None)
    gui.web_enabled_var.set(False)
    gui._save_settings()
    assert saved == [False]


class _RealCfgStore:
    """Store con AppConfig real para probar la NO regeneracion de claves."""
    def __init__(self):
        from wsl_port.vendor.port_forwarder.core.config import AppConfig
        self.cfg = AppConfig()
        self.saves = 0

    def save(self):
        self.saves += 1


def test_gui_save_no_regenera_token_mcp_existente(monkeypatch, gui):
    """Bug 14/09: cada Guardar ajustes regeneraba el token MCP (el panel
    publicado quedaba con otra clave). Con token existente y campo vacio,
    el token debe conservarse intacto."""
    store = _RealCfgStore()
    store.cfg.mcp.enabled = True
    store.cfg.mcp.token_required = True
    store.cfg.mcp.token = "CLAVE-DEL-USUARIO-9e1f8a"
    monkeypatch.setattr(core, "pf_store", lambda: store)
    monkeypatch.setattr("wsl_port.ui.main_window._set_autostart", lambda a: None)
    monkeypatch.setattr("tkinter.messagebox.showinfo", lambda *a, **k: None)
    gui.web_enabled_var.set(False)
    gui.mcp_enabled_var.set(True)
    gui.mcp_token_var.set(True)
    gui.mcp_key_var.set("")          # usuario deja el campo vacio
    gui._save_settings()
    assert store.cfg.mcp.token == "CLAVE-DEL-USUARIO-9e1f8a"
    assert store.saves == 1


def test_gui_save_panel_no_bloquea_con_clave_ya_configurada(monkeypatch, gui):
    """Con clave del panel ya guardada (vault), un guardado con el campo
    vacio no debe bloquear ni pisarla."""
    store = _RealCfgStore()
    store.cfg.ui.web_panel_enabled = True
    store.cfg.ui.web_panel_token = ""
    monkeypatch.setattr(core, "pf_store", lambda: store)
    monkeypatch.setattr(
        "wsl_port.vendor.port_forwarder.utils.secrets.SecretsStore.check",
        lambda self, ref: True)
    set_calls = []
    monkeypatch.setattr(
        "wsl_port.vendor.port_forwarder.utils.secrets.SecretsStore.set",
        lambda self, ref, val: set_calls.append((ref, val)))
    monkeypatch.setattr("wsl_port.ui.main_window._set_autostart", lambda a: None)
    monkeypatch.setattr("tkinter.messagebox.showinfo", lambda *a, **k: None)
    shown = []
    monkeypatch.setattr("tkinter.messagebox.showerror",
                        lambda *a, **k: shown.append(a))
    gui.web_enabled_var.set(True)
    gui.web_pw_var.set("")           # campo vacio: ya hay clave en vault
    gui._save_settings()
    assert shown == []               # no bloqueado
    assert set_calls == []           # no pisada
    assert store.cfg.ui.web_panel_enabled is True


def test_gui_save_mcp_genera_token_solo_si_no_hay(monkeypatch, gui):
    """El generador aleatorio sigue disponible para el primer arranque
    (sin token configurado en ninguna parte)."""
    store = _RealCfgStore()
    store.cfg.mcp.enabled = True
    store.cfg.mcp.token_required = True
    store.cfg.mcp.token = ""         # ninguno
    monkeypatch.setattr(core, "pf_store", lambda: store)
    monkeypatch.setattr("wsl_port.ui.main_window._set_autostart", lambda a: None)
    infos = []
    monkeypatch.setattr("tkinter.messagebox.showinfo",
                        lambda *a, **k: infos.append(a))
    gui.web_enabled_var.set(False)
    gui.mcp_enabled_var.set(True)
    gui.mcp_token_var.set(True)
    gui.mcp_key_var.set("")
    gui._save_settings()
    assert store.cfg.mcp.token       # generado y guardado
    assert any("Token MCP generado" in str(i) for i in infos)


def test_gui_shutdown_all_distros(monkeypatch, gui):
    from wsl_port.ui.main_window import MainWindow
    monkeypatch.setattr(core, "shutdown_all", lambda: {"ok": True})
    monkeypatch.setattr("tkinter.messagebox.askyesno", lambda *a, **k: True)
    monkeypatch.setattr(MainWindow, "_notify",
                        lambda self, t, m, level="info": None)
    gui._shutdown_all_distros()
    time.sleep(0.4)
    assert not gui._q.empty()