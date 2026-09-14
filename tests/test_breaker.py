"""Tests del circuit breaker de WSL (causa raiz del colgado)."""
from __future__ import annotations

import time
from unittest import mock

import pytest

from wsl_port.vendor.wsl_manager.utils import subprocess_async as sa
from wsl_port import core


@pytest.fixture
def clean_breaker():
    sa.reset_breaker()
    yield
    sa.reset_breaker()


def test_breaker_cooldown_escala(clean_breaker, monkeypatch):
    """Cada apertura sucesiva duplica el enfriamiento (30->60->120... tope 300)
    para no martillar un wslservice atrancado; reset_breaker lo baja."""
    monkeypatch.setattr(sa, "_soft_recovery", lambda: None)
    sa._breaker_open_now()
    assert sa.breaker_state()["cooldown"] == 30
    sa._breaker_open_now()
    assert sa.breaker_state()["cooldown"] == 60
    sa._breaker_open_now()
    sa._breaker_open_now()
    sa._breaker_open_now()
    assert sa.breaker_state()["cooldown"] == 300  # tope
    sa.reset_breaker()
    st = sa.breaker_state()
    assert st["cooldown"] == 30 and st["strikes"] == 0


@pytest.mark.skipif(sa.sys.platform != "win32", reason="soft recovery es de Windows")
def test_soft_recovery_tras_tres_fallos(clean_breaker):
    """A la tercera apertura seguida se intenta 'wsl --shutdown' (watchdog)."""
    with mock.patch.object(sa.subprocess, "run") as fake_run:
        sa._breaker_open_now()
        sa._breaker_open_now()
        assert fake_run.call_count == 0
        sa._breaker_open_now()
        assert any("--shutdown" in str(c) for c in fake_run.call_args_list)
    sa.reset_breaker()


def test_circuit_breaker_abre_al_colgarse(clean_breaker):
    """Si un comando wsl.exe se cuelga, el breaker abre por 30s."""
    proc = mock.Mock()
    proc.pid = 1234
    proc.communicate.side_effect = sa.subprocess.TimeoutExpired(cmd="wsl.exe", timeout=1)
    with mock.patch.object(sa.subprocess, "Popen", return_value=proc):
        r = sa.run(["wsl.exe", "--list"], timeout=1)
        assert r.ok is False
        assert "cortocircuito" in r.error
    assert sa.breaker_state()["open"] is True


def test_circuit_breaker_cortocircuita_sin_lanzar(clean_breaker):
    """Con breaker abierto, los comandos wsl.exe fallan al instante sin Popen."""
    sa._breaker_open_now()
    with mock.patch.object(sa.subprocess, "Popen") as fake_popen:
        t0 = time.time()
        r = sa.run(["wsl.exe", "--list"], timeout=5)
        elapsed = time.time() - t0
        assert r.ok is False
        assert elapsed < 0.1, f"debe fallar al instante, tardo {elapsed:.2f}s"
        fake_popen.assert_not_called()  # no lanza proceso


def test_circuit_breaker_no_afecta_otros_comandos(clean_breaker):
    """netsh/cmd/ssh NO se cortocircuitan cuando WSL cuelga."""
    sa._breaker_open_now()
    r = sa.run(["cmd.exe", "/c", "echo", "hola"], timeout=5)
    assert r.ok is True
    assert r.output.strip() == "hola"


def test_breaker_se_cierra_con_exito(clean_breaker):
    """Un wsl.exe exitoso (tras expirar el breaker) funciona y queda cerrado."""
    sa._breaker_open_now()
    sa._BREAKER_UNTIL = time.time() - 1  # expirar el cortocircuito
    proc = mock.Mock()
    proc.returncode = 0
    proc.communicate.return_value = (b"Ubuntu", b"")
    with mock.patch.object(sa.subprocess, "Popen", return_value=proc):
        r = sa.run(["wsl.exe", "--list"], timeout=5)
        assert r.ok is True
    assert sa.breaker_state()["open"] is False


def test_core_health_check_usa_breaker(clean_breaker, monkeypatch):
    """core.wsl_health_check delega en el ejecutor (breaker incluido)."""
    monkeypatch.setattr(core, "_wsl_healthy", None)
    monkeypatch.setattr(core, "_wsl_last_check", 0.0)
    sa._breaker_open_now()
    with mock.patch.object(sa.subprocess, "Popen") as fake_popen:
        t0 = time.time()
        ok = core.wsl_health_check(force=True)
        elapsed = time.time() - t0
        assert ok is False
        assert elapsed < 0.1
        fake_popen.assert_not_called()
    sa.reset_breaker()


def test_core_wsl_reset_cierra_breaker(clean_breaker):
    sa._breaker_open_now()
    assert sa.breaker_state()["open"] is True
    core.wsl_reset()
    assert sa.breaker_state()["open"] is False
    assert core.wsl_breaker_state()["open"] is False


def test_status_incluye_breaker(monkeypatch, clean_breaker):
    monkeypatch.setattr(core, "wsl_health_check", lambda force=False: True)
    monkeypatch.setattr(core, "distros", lambda skip_ips=False: [])
    st = core.status()
    assert "wsl_breaker" in st
    assert st["wsl_breaker"]["open"] is False


def test_kill_tree_no_mata_todas_las_distros(clean_breaker):
    """_kill_tree NO debe usar taskkill /IM wsl.exe (mataria todas las distros)."""
    import subprocess as sp
    calls = []
    real_run = sp.run

    def fake_run(args, *a, **k):
        calls.append(args)
        return real_run(args, *a, **k)

    with mock.patch.object(sa.subprocess, "run", fake_run):
        sa._kill_tree(1234)
    assert calls, "debe llamar taskkill"
    for call in calls:
        joined = " ".join(str(x) for x in call).lower()
        assert "/im" not in joined, f"NO debe matar por nombre: {call}"
        assert "wsl.exe" not in joined, f"NO debe matar por nombre: {call}"
        assert "/pid" in joined, f"debe matar por PID: {call}"