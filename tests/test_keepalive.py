"""Tests: WSL siempre vivo (keepalive en 3 capas).

Capa 1: ensure_wslconfig (vmIdleTimeout=-1)
Capa 2: holders de sesion (sleep infinity con tag)
Capa 3: watchdog cycle() que revive caidas y respeta stopped_by_user
"""
from __future__ import annotations

import json
import subprocess
import sys
import urllib.request

import pytest

from wsl_port import core
from wsl_port.vendor.port_forwarder.core.keepalive import (
    DistroKeepalive, ensure_wslconfig, parse_wsl_list)
from wsl_port.vendor.port_forwarder.web.server import WebPanel


@pytest.fixture
def isolated_config(monkeypatch, tmp_path):
    from wsl_port.vendor.port_forwarder.core.config import ConfigStore
    store = ConfigStore(path=str(tmp_path / "config.json"))
    monkeypatch.setattr(core, "_pf_store", store)
    return store


@pytest.fixture
def mock_wsl_healthy(monkeypatch):
    monkeypatch.setattr(core, "wsl_health_check", lambda force=False: True)
    return monkeypatch


@pytest.fixture
def panel(mock_wsl_healthy, isolated_config):
    import time
    from wsl_port.vendor.port_forwarder.core.supervisor import Supervisor
    sup = Supervisor(isolated_config)
    p = WebPanel(sup, port=0, bind="127.0.0.1", token="test-token")
    p.start()
    base = f"http://127.0.0.1:{p.port}"
    for _ in range(50):
        try:
            urllib.request.urlopen(base + "/", timeout=1)
            break
        except Exception:
            time.sleep(0.1)
    yield p, base
    p.stop()


def _u16(text: str) -> bytes:
    return text.encode("utf-16-le")


# ------------------------------- parseo -------------------------------

def test_parse_wsl_list_simple():
    out = parse_wsl_list(_u16(
        "  NAME                  STATE           VERSION\r\n"
        "* Ubuntu-26.04          Running         2\r\n"
        "  debian2               Stopped         2\r\n"
        "  docker-desktop        Running         2\r\n").decode("utf-16-le"))
    assert out == {"Ubuntu-26.04": "Running", "debian2": "Stopped",
                   "docker-desktop": "Running"}


def test_parse_wsl_list_name_with_spaces():
    out = parse_wsl_list("My Custom Distro       Stopped         2")
    assert out == {"My Custom Distro": "Stopped"}


def test_parse_wsl_list_ignora_basura():
    assert parse_wsl_list("") == {}
    assert parse_wsl_list("NAME  STATE  VERSION") == {}


# ------------------------------- .wslconfig -------------------------------

def test_ensure_wslconfig_crea_cuando_no_existe(tmp_path):
    p = tmp_path / ".wslconfig"
    assert ensure_wslconfig(p) is True
    text = p.read_text()
    assert "[wsl2]" in text and "vmIdleTimeout=-1" in text


def test_ensure_wslconfig_reemplaza_y_es_idempotente(tmp_path):
    p = tmp_path / ".wslconfig"
    p.write_text("[wsl2]\nmemory=12GB\nvmIdleTimeout=60000\nprocessors=3\n")
    assert ensure_wslconfig(p) is True
    lines = p.read_text().splitlines()
    assert "vmIdleTimeout=-1" in lines
    assert "memory=12GB" in lines and "processors=3" in lines
    assert sum(l.startswith("vmIdleTimeout") for l in lines) == 1
    assert ensure_wslconfig(p) is False


def test_ensure_wslconfig_inserta_en_seccion_sin_tocar_otras(tmp_path):
    p = tmp_path / ".wslconfig"
    p.write_text("[wsl2]\nmemory=8GB\n[experimental]\nsparseVhd=true\n")
    assert ensure_wslconfig(p) is True
    text = p.read_text()
    assert "vmIdleTimeout=-1" in text
    assert text.index("vmIdleTimeout=-1") < text.index("[experimental]")
    assert "sparseVhd=true" in text


# ------------------------------- DistroKeepalive -------------------------------

class _KA:
    def __init__(self):
        self.enabled = True
        self.check_interval_seconds = 20
        self.stopped_by_user: list[str] = []


class _Win:
    wsl_exe = "wsl.exe"


class _Cfg:
    def __init__(self):
        self.keepalive = _KA()
        self.windows = _Win()


class _Store:
    def __init__(self):
        self.cfg = _Cfg()
        self.saves = 0

    def save(self):
        self.saves += 1


class _Metrics:
    def __init__(self):
        self.events = []

    def record_event(self, kind, **kw):
        self.events.append((kind, kw))


class _FakeProc:
    def __init__(self, alive=True):
        self._alive = alive

    def poll(self):
        return None if self._alive else 0

    def terminate(self):
        self._alive = False


@pytest.fixture
def ka_store(monkeypatch):
    store = _Store()
    metrics = _Metrics()
    spawned: list[list] = []

    def fake_popen(args, **kw):
        spawned.append(list(args))
        return _FakeProc()

    k = DistroKeepalive(store, metrics, wsl_exe="wsl.exe")
    monkeypatch.setattr(k, "list_states",
                        lambda: {"Ubuntu-26.04": "Running",
                                 "debian2": "Stopped",
                                 "docker-desktop": "Stopped"})
    monkeypatch.setattr(subprocess, "Popen", fake_popen)
    monkeypatch.setattr(sys, "platform", "win32")
    k._wslconfig_done = True  # no tocar .wslconfig real
    k._born = 0.0             # gracia de arranque ya cumplida
    return k, store, metrics, spawned


def test_cycle_revive_stopped_y_holder_para_running(ka_store):
    k, store, metrics, spawned = ka_store
    k.cycle()
    holder_de = lambda n: ["wsl.exe", "-d", n, "--exec", "sh", "-c",
                           "sleep infinity #wsl-port-keepalive"]
    assert holder_de("debian2") in spawned       # caida -> revive
    assert holder_de("Ubuntu-26.04") in spawned  # viva -> retener sesion
    assert not any("docker-desktop" in c for c in spawned)
    assert any(e[0] == "keepalive_revive" and
               e[1]["distro"] == "debian2" for e in metrics.events)
    assert k.revived_count == 1


def test_cycle_respeta_exclusion_por_boton(ka_store):
    k, store, metrics, spawned = ka_store
    k.mark_user_stop("debian2")
    assert "debian2" in store.cfg.keepalive.stopped_by_user
    assert store.saves == 1
    k.cycle()
    assert not any("debian2" in c for c in spawned)
    k.mark_user_start("debian2")  # boton Iniciar -> vuelve a protegerse
    assert "debian2" not in store.cfg.keepalive.stopped_by_user
    k._last_check = 0.0  # fuerza ciclo (el throttle de 20s es intentional)
    k.cycle()
    assert any("debian2" in c for c in spawned)


def test_cycle_global_off_no_revive(ka_store):
    k, store, metrics, spawned = ka_store
    k.ensure_holder("Ubuntu-26.04")
    store.cfg.keepalive.enabled = False
    spawned.clear()
    k._last_check = 0.0
    k.cycle()
    assert spawned == []


def test_holder_idempotente_y_killer(ka_store):
    k, store, metrics, spawned = ka_store
    k.ensure_holder("Ubuntu-26.04")
    assert k.is_holder_alive("Ubuntu-26.04")
    k.ensure_holder("Ubuntu-26.04")
    assert len(spawned) == 1  # vivo -> no duplica
    k.kill_holder("Ubuntu-26.04")
    assert not k.is_holder_alive("Ubuntu-26.04")
    k.ensure_holder("Ubuntu-26.04")
    assert len(spawned) == 2  # muerto -> re-crea


def test_cycle_throttle_y_noop_en_linux(ka_store, monkeypatch):
    k, store, metrics, spawned = ka_store
    k.cycle()
    n = len(spawned)
    k.cycle()  # dentro del intervalo -> no repite
    assert len(spawned) == n
    monkeypatch.setattr(sys, "platform", "linux")
    k._last_check = 0.0
    k.cycle()
    assert len(spawned) == n  # no Windows -> sin llamadas


def test_cycle_holder_muerto_se_recupera(ka_store):
    k, store, metrics, spawned = ka_store
    k.ensure_holder("Ubuntu-26.04")
    proc = k._holders["Ubuntu-26.04"]
    proc._alive = False  # simula que murio (p. ej. crash de la VM)
    k._last_check = 0.0
    k.cycle()
    # Ubuntu seguia Running en el snapshot pero su holder estaba muerto ->
    # debe haberse re-creado el holder (2 spawns para Ubuntu)
    assert sum(1 for c in spawned if "Ubuntu-26.04" in c) == 2


def test_cycle_gracia_de_arranque_no_toca_wsl(ka_store):
    """Recien nacida la app (login de Windows) el watchdog NO lanza nada:
    los arranques concurrentes de wsl.exe al boot pueden atravesar wslservice."""
    k, store, metrics, spawned = ka_store
    k._born = k.clock()  # "ahora mismo" se arranco la app
    k.cycle()
    assert spawned == []
    k._born = 0.0        # gracia cumplida
    k._last_check = 0.0
    k.cycle()
    assert spawned       # ahora si actua


def test_cycle_revividos_escalonados(ka_store, monkeypatch):
    """Con varias distros caidas, como mucho 1 revive por ciclo."""
    k, store, metrics, spawned = ka_store
    monkeypatch.setattr(k, "list_states", lambda: {
        "d1": "Stopped", "d2": "Stopped", "d3": "Stopped"})
    k._last_check = 0.0
    k.cycle()
    assert k.revived_count == 1
    k._last_check = 0.0
    k.cycle()
    assert k.revived_count == 2


# ------------------------------- integracion config/supervisor -------------------------------

def test_supervisor_status_expone_keepalive(isolated_config):
    from wsl_port.vendor.port_forwarder.core.supervisor import Supervisor
    sup = Supervisor(isolated_config)
    st = sup.status()
    assert st["keepalive"]["enabled"] is True
    assert st["keepalive"]["stopped_by_user"] == []


def test_config_roundtrip_keepalive(isolated_config):
    isolated_config.cfg.keepalive.stopped_by_user = ["debian2"]
    isolated_config.cfg.keepalive.enabled = False
    isolated_config.save()
    isolated_config.reload()
    assert isolated_config.cfg.keepalive.stopped_by_user == ["debian2"]
    assert isolated_config.cfg.keepalive.enabled is False


# ------------------------------- endpoints web -------------------------------

def _http_get(url, token="test-token"):
    req = urllib.request.Request(url)
    req.add_header("Authorization", f"Bearer {token}")
    with urllib.request.urlopen(req, timeout=15) as r:
        return json.loads(r.read())


def test_panel_keepalive_endpoints_y_distro_action(panel, monkeypatch):
    from test_web_terminal_tunnel import _http_post
    p, base = panel
    calls: list[list] = []

    class P:
        def poll(self):
            return None
        def terminate(self):
            pass
    monkeypatch.setattr(subprocess, "Popen",
                        lambda args, **kw: (calls.append(list(args)), P())[1])
    monkeypatch.setattr(type(p.supervisor.keepalive), "list_states",
                        lambda self: {"Ubuntu-26.04": "Running",
                                      "debian2": "Stopped"})

    # fake para subprocess.run del panel: --list devuelve tabla utf-16,
    # cualquier otra accion (terminate/no-existe) falla con rc=1
    class _R:
        def __init__(self, rc, out):
            self.returncode = rc
            self.stdout = out
            self.stderr = b""

    def fake_run(cmd, **kw):
        if "--list" in cmd:
            return _R(0, _u16(
                "  NAME             STATE           VERSION\r\n"
                "* Ubuntu-26.04     Running         2\r\n"
                "  debian2          Stopped         2\r\n"
                "  docker-desktop   Stopped         2\r\n"))
        return _R(1, b"no existe")
    monkeypatch.setattr(subprocess, "run", fake_run)

    # no tocar el .wslconfig real ni matar holders reales desde el test
    p.supervisor.keepalive._wslconfig_done = True

    d = _http_get(base + "/api/v1/distros")
    assert d["keepalive"]["enabled"] is True
    by = {x["name"]: x for x in d["distros"]}
    assert by["Ubuntu-26.04"]["auto_revive"] is True

    # excluir debian2
    r = _http_post(base + "/api/v1/distro/debian2/keepalive", {"exempt": True})
    assert r["ok"] and "debian2" in r["keepalive"]["stopped_by_user"]
    d = _http_get(base + "/api/v1/distros")
    by = {x["name"]: x for x in d["distros"]}
    assert by["debian2"]["auto_revive"] is False

    # re-proteger (debe crear holder ya mismo)
    r = _http_post(base + "/api/v1/distro/debian2/keepalive",
                   {"exempt": False})
    assert "debian2" not in r["keepalive"]["stopped_by_user"]
    assert any("debian2" in c for c in calls)

    # toggle global
    r = _http_post(base + "/api/v1/keepalive", {"enabled": False})
    assert r["ok"] and r["keepalive"]["enabled"] is False
    d = _http_get(base + "/api/v1/distros")
    assert all(not x["auto_revive"] for x in d["distros"])
    r = _http_post(base + "/api/v1/keepalive", {"enabled": True})
    assert r["keepalive"]["enabled"] is True

    # stop de distro inexistente -> ok=False y NO deja exclusion colgada
    r = _http_post(base + "/api/v1/distro/no-existe-xyz/stop", {})
    assert r["ok"] is False
    assert "no-existe-xyz" not in \
        p.supervisor.store.cfg.keepalive.stopped_by_user
