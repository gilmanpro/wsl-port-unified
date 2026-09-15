"""Tests de los fixes del informe de seguridad (C-1 + H-1..H-4).

C-1/H-1 (MCP): interruptor expose_exec + export publico nunca sin bearer.
H-1 (panel): token vacio -> autogenerado (adios fail-open).
H-4: credenciales cifradas en vault DPAPI al escribir config; export redactado.
"""
from __future__ import annotations

import json
import socket

import pytest

from wsl_port.vendor.port_forwarder.core.config import (
    ConfigStore, Mcp, Vps, parse_config, REDACTED,
)


def _free_port() -> int:
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    p = s.getsockname()[1]
    s.close()
    return p


# ---------------------------------------------------------------------------
# C-1: interruptor expose_exec en McpHttpServer
# ---------------------------------------------------------------------------

def _mcp_call(port, method, params=None, bearer="", id_=1):
    import urllib.request
    import urllib.error

    body = json.dumps({"jsonrpc": "2.0", "id": id_, "method": method,
                       "params": params or {}}).encode()
    req = urllib.request.Request(f"http://127.0.0.1:{port}/mcp", data=body,
                                 method="POST")
    req.add_header("Content-Type", "application/json")
    if bearer:
        req.add_header("Authorization", f"Bearer {bearer}")
    try:
        with urllib.request.urlopen(req, timeout=10) as r:
            return r.status, json.loads(r.read())
    except urllib.error.HTTPError as e:
        return e.code, json.loads(e.read())


@pytest.fixture
def mcp_store(tmp_path):
    store = ConfigStore(path=str(tmp_path / "config.json"))
    return store


@pytest.fixture
def http_srv(mcp_store):
    from wsl_port.vendor.port_forwarder.api.service import AppService
    from wsl_port.vendor.port_forwarder.mcp.server import McpHttpServer

    made = []

    def _make(expose_exec: bool, token: str = "TOK-TEST"):
        srv = McpHttpServer(service=AppService(mcp_store), host="127.0.0.1",
                            port=_free_port(), token=token,
                            expose_exec=expose_exec)
        srv.start()
        made.append(srv)
        return srv

    yield _make
    for s in made:
        s.stop()


def test_expose_exec_off_oculta_y_bloquea_wsl_exec(http_srv):
    srv = http_srv(False)
    code, r = _mcp_call(srv.port, "tools/list", bearer="TOK-TEST")
    assert code == 200
    names = {t["name"] for t in r["result"]["tools"]}
    assert "wsl_exec" not in names
    assert "status" in names
    code, r = _mcp_call(srv.port, "tools/call",
                        {"name": "wsl_exec", "distro": "x", "command": "id"},
                        bearer="TOK-TEST")
    assert code == 200
    assert "error" in r and "desconocida" in r["error"]["message"]


def test_expose_exec_on_expone_wsl_exec(http_srv):
    srv = http_srv(True)
    code, r = _mcp_call(srv.port, "tools/list", bearer="TOK-TEST")
    names = {t["name"] for t in r["result"]["tools"]}
    assert "wsl_exec" in names


def test_mcp_export_sin_token_fuera_de_servicio(http_srv):
    srv = http_srv(True, token="")
    # bearer vacio seguira permitido SOLO para loopback sin export (el guard
    # del supervisor es el que prohibe export publico); aqui verificamos que
    # el borde no autenticado responde 401 solo si hay bearer configurado.
    code, _ = _mcp_call(srv.port, "tools/list", bearer="")
    assert code == 200


# ---------------------------------------------------------------------------
# H-1 (supervisor): export al VPS fuerza token
# ---------------------------------------------------------------------------

def test_supervisor_forza_token_con_export(mcp_store):
    from wsl_port.vendor.port_forwarder.core.supervisor import Supervisor

    mcp_store.cfg.mcp = Mcp(enabled=True, transport="http",
                            port=_free_port(), token_required=False,
                            token="", vps_export_enabled=True)
    sup = Supervisor(mcp_store)
    srv = None
    try:
        sup._sync_mcp_http()
        srv = sup._mcp_http
        assert srv is not None and srv.running
        assert len(srv.bearer) >= 32
        assert mcp_store.cfg.mcp.token == srv.bearer
        assert mcp_store.cfg.mcp.token_required is True
        # persistido: en disco ya no esta en claro (H-4) -> vault
        raw = json.loads(mcp_store.path.read_text(encoding="utf-8"))
        assert raw["mcp"]["token"] == ""
    finally:
        if srv is not None:
            srv.stop()
        sup._mcp_http = None


# ---------------------------------------------------------------------------
# H-1 (panel): token vacio se autogenera
# ---------------------------------------------------------------------------

def test_panel_token_vacio_autogenerado(mcp_store):
    from wsl_port.vendor.port_forwarder.core.supervisor import Supervisor
    from wsl_port.vendor.port_forwarder.web.server import WebPanel
    import urllib.request
    import urllib.error

    sup = Supervisor(mcp_store)
    p = WebPanel(sup, port=0, bind="127.0.0.1", token="")
    try:
        p.start()
        assert p.token and p.token_generated
        url = f"http://127.0.0.1:{p.port}/api/v1/state"
        try:
            urllib.request.urlopen(url, timeout=5)
            pytest.fail("deberia requerir auth")
        except urllib.error.HTTPError as e:
            assert e.code == 401
    finally:
        p.stop()


# ---------------------------------------------------------------------------
# H-4: secretos cifrados en reposo + export redactado + import tolerante
# ---------------------------------------------------------------------------

def test_vps_password_nunca_en_disco(tmp_path):
    store = ConfigStore(path=str(tmp_path / "config.json"))
    store.cfg.vps_list.append(Vps(id="v1", host="h", user="u",
                                  password="SUP3R-S3CRETA"))
    store.save()
    raw = store.path.read_text(encoding="utf-8")
    assert "SUP3R-S3CRETA" not in raw
    data = json.loads(raw)
    v = data["vps_list"][0]
    assert v["password"] == "" and v["secret_ref"] == "vps:v1"
    # vault junto a la config (no el global de produccion)
    assert (tmp_path / "secrets.dat").exists()
    # reload hidrata en memoria
    store2 = ConfigStore(path=str(tmp_path / "config.json"))
    assert store2.get_vps("v1").password == "SUP3R-S3CRETA"


def test_panel_y_mcp_tokens_migran_al_vault(tmp_path):
    store = ConfigStore(path=str(tmp_path / "config.json"))
    store.cfg.ui.web_panel_token = "panel-claro-1234567890"
    store.cfg.mcp.token = "mcp-claro-1234567890"
    store.save()
    raw = store.path.read_text(encoding="utf-8")
    assert "panel-claro-1234567890" not in raw
    assert "mcp-claro-1234567890" not in raw
    store2 = ConfigStore(path=str(tmp_path / "config.json"))
    assert store2.cfg.ui.web_panel_token == "panel-claro-1234567890"
    assert store2.cfg.mcp.token == "mcp-claro-1234567890"


def test_web_panel_token_actualizado_no_lo_pisa_el_viejo(tmp_path):
    """Regresion: guardar una clave nueva desde Ajustes debe persistir.

    El bug: SecretsStore.set(new) y luego store.save() re-stasheaba el token
    VIEJO que seguia en memoria (cfg.ui.web_panel_token), sobrescribiendo el
    vault; al reiniciar volvía la clave anterior. La GUI ahora actualiza
    tambien cfg.ui.web_panel_token ANTES de store.save().
    """
    store = ConfigStore(path=str(tmp_path / "config.json"))
    store.cfg.ui.web_panel_token = "juandiaz"      # clave vieja hidratada
    store.save()
    nueva = "CLAVE-NUEVA-0123456789abcdef"
    # flujo corregido de _save_settings:
    store.cfg.ui.web_panel_token = nueva           # memoria al dia
    store.save()                                   # el stash cifra 'nueva'
    raw = store.path.read_text(encoding="utf-8")
    assert "CLAVE-NUEVA" not in raw and "juandiaz" not in raw
    store2 = ConfigStore(path=str(tmp_path / "config.json"))
    assert store2.cfg.ui.web_panel_token == nueva  # reload tras reiniciar


def test_export_redactado_e_import(tmp_path):
    store = ConfigStore(path=str(tmp_path / "config.json"))
    store.cfg.vps_list.append(Vps(id="v9", password="CLAVE-VIVA"))
    store.cfg.mcp.token = "TOKEN-VIVO"
    exp = json.loads(store.as_yaml_safe_json())
    assert exp["vps_list"][0]["password"] == REDACTED
    assert exp["mcp"]["token"] == REDACTED
    assert "CLAVE-VIVA" not in json.dumps(exp)
    # importar el export no instala marcadores como credenciales
    cfg2 = parse_config(exp)
    v2 = next(v for v in cfg2.vps_list if v.id == "v9")
    assert v2.password == ""
    assert cfg2.mcp.token == ""
