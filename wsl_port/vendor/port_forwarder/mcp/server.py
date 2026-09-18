"""Servidor MCP (seccion 21.4): stdio + JSON-RPC 2.0, sin dependencias.

Protocolo minimo compatible con clientes MCP (Zed, Claude Code, Cursor):
initialize -> notifications/initialized -> tools/list -> tools/call.

- Cada tool devuelve {ok, data, message} serializado como texto.
- Autenticacion: si env PORT_FORWARDER_TOKEN esta definido, tools/call exige
  que params.token (o params._meta.token) coincida.
- Todas las tools usan AppService (mismos providers que CLI/API/GUI).
"""

from __future__ import annotations

import json
import logging
import os
import sys
import threading
import time
from typing import Any, Callable

from wsl_port.vendor.port_forwarder import __version__
from wsl_port.vendor.port_forwarder.api.service import AppService

log = logging.getLogger("port-forwarder.mcp")

PROTOCOL_VERSION = "2024-11-05"

# Rate limiting igual que panel web: 5 fallos -> bloqueo 15 min
MCP_MAX_ATTEMPTS = 5
MCP_WINDOW = 300
MCP_BLOCK_TIME = 900


class RateLimiter:
    def __init__(self, max_attempts: int = MCP_MAX_ATTEMPTS,
                 window: float = MCP_WINDOW, block_time: float = MCP_BLOCK_TIME) -> None:
        self.max_attempts = max_attempts
        self.window = window
        self.block_time = block_time
        self._attempts: dict[str, list[float]] = {}
        self._blocked_until: dict[str, float] = {}
        self._lock = threading.Lock()

    def is_blocked(self, key: str) -> tuple[bool, float]:
        now = time.time()
        with self._lock:
            until = self._blocked_until.get(key, 0)
            if now < until:
                return True, until - now
            if key in self._blocked_until and now >= until:
                del self._blocked_until[key]
                self._attempts.pop(key, None)
            lst = self._attempts.get(key, [])
            lst = [t for t in lst if now - t < self.window]
            self._attempts[key] = lst
            return False, 0

    def record_failure(self, key: str) -> None:
        now = time.time()
        with self._lock:
            lst = self._attempts.setdefault(key, [])
            lst.append(now)
            lst[:] = [t for t in lst if now - t < self.window]
            if len(lst) > self.max_attempts:
                self._blocked_until[key] = now + self.block_time
                log.warning("mcp rate limit: %s bloqueado %.0fs tras %d fallos", key, self.block_time, len(lst))

    def record_success(self, key: str) -> None:
        with self._lock:
            self._attempts.pop(key, None)
            self._blocked_until.pop(key, None)

ToolFn = Callable[[dict[str, Any]], dict[str, Any]]


def _tool(name: str, description: str, schema: dict[str, Any], fn: ToolFn) -> dict:
    return {"name": name, "description": description,
            "inputSchema": {"type": "object", "properties": schema,
                            "required": [k for k, v in schema.items()
                                         if v.get("required")]},
            "handler": fn}


def build_tools(svc: AppService) -> list[dict]:
    """Mapeo 1:1 con la tabla de comandos del CLI (19.4)."""
    s = svc
    return [
        _tool("status", "Estado global (forwards, tunnels, supervisor)",
              {}, lambda a: s.status()),
        _tool("forward_list", "Listar forwards con estado real (F1/F4)",
              {}, lambda a: s.forwards_list()),
        _tool("forward_add", "Agregar forward Windows-WSL (F1)",
              {"id": {"type": "string", "required": True},
               "listen_port": {"type": "integer", "required": True},
               "wsl_port": {"type": "integer", "required": True},
               "distro": {"type": "string"},
               "protocol": {"type": "string", "enum": ["tcp", "udp"]},
               "auto_apply": {"type": "boolean"}},
              lambda a: s.forwards_add(
                  forward_id=a["id"], listen_port=int(a["listen_port"]),
                  wsl_port=int(a["wsl_port"]), distro=a.get("distro", ""),
                  protocol=a.get("protocol", "tcp"),
                  auto_apply=bool(a.get("auto_apply", False)))),
        _tool("forward_remove", "Eliminar forward de la config (F1)",
              {"id": {"type": "string", "required": True}},
              lambda a: s.forwards_remove(a["id"])),
        _tool("forward_apply", "Aplicar forwards (F2; admin/UAC)",
              {"all": {"type": "boolean"}},
              lambda a: s.forwards_apply(all_=bool(a.get("all", False)))),
        _tool("forward_clear", "Limpiar TODOS los portproxies (F3; destructivo)",
              {}, lambda a: s.forwards_clear()),
        _tool("forward_test", "Probar conexion TCP del forward (F6)",
              {"id": {"type": "string", "required": True}},
              lambda a: s.forwards_test(a["id"])),
        _tool("forward_conflicts", "Detectar conflictos de puerto (F5)",
              {"port": {"type": "integer", "required": True}},
              lambda a: s.forwards_conflicts(int(a["port"]))),
        _tool("tunnel_list", "Listar tunnels (T1)",
              {}, lambda a: s.tunnels_list()),
        _tool("tunnel_add", "Agregar tunnel SSH (T1)",
              {"id": {"type": "string", "required": True},
               "vps_id": {"type": "string", "required": True},
               "local": {"type": "string", "required": True},
               "remote": {"type": "array", "items": {"type": "string"}, "required": True}},
              lambda a: s.tunnels_add(a["id"], a["vps_id"], a["local"], a.get("remote", []))),
        _tool("tunnel_remove", "Eliminar tunnel (T2)",
              {"id": {"type": "string", "required": True}},
              lambda a: s.tunnels_remove(a["id"])),
        _tool("tunnel_start", "Iniciar tunnel (T1)",
              {"id": {"type": "string", "required": True}},
              lambda a: s.tunnels_start(a["id"])),
        _tool("tunnel_stop", "Detener tunnel (T2)",
              {"id": {"type": "string", "required": True}},
              lambda a: s.tunnels_stop(a["id"])),
        _tool("tunnel_restart", "Reiniciar tunnel (T2)",
              {"id": {"type": "string", "required": True}},
              lambda a: s.tunnels_restart(a["id"])),
        _tool("tunnel_update", "Actualizar tunnel (T1)",
              {"id": {"type": "string", "required": True},
               "vps_id": {"type": "string"},
               "local": {"type": "string"},
               "remote": {"type": "array", "items": {"type": "string"}},
               "auto_start": {"type": "boolean"},
               "enabled": {"type": "boolean"}},
              lambda a: s.tunnels_update(a["id"],
                  vps_id=a.get("vps_id"), local=a.get("local"),
                  remote=a.get("remote"), auto_start=a.get("auto_start"),
                  enabled=a.get("enabled"))),
        _tool("vps_list", "Listar VPS (T3)",
              {}, lambda a: s.vps_list()),
        _tool("vps_add", "Agregar VPS (T3)",
              {"id": {"type": "string", "required": True},
               "host": {"type": "string", "required": True},
               "user": {"type": "string", "required": True},
               "port": {"type": "integer"},
               "identity_file": {"type": "string"}},
              lambda a: s.vps_add(a["id"], a["host"], a["user"],
                                  int(a.get("port", 22)),
                                  a.get("identity_file", ""))),
        _tool("vps_remove", "Eliminar VPS (T3; destructivo)",
              {"id": {"type": "string", "required": True}},
              lambda a: s.vps_remove(a["id"])),
        _tool("health_check", "Health checks de forwards/tunnels/VPS (M3)",
              {}, lambda a: s.health()),
        _tool("alert_list", "Listar alertas (M4)",
              {"state": {"type": "string", "enum": ["open", "resolved"]}},
              lambda a: s.alerts_list(a.get("state"))),
        _tool("alert_resolve", "Resolver alerta (M4)",
              {"id": {"type": "integer", "required": True}},
              lambda a: s.alerts_resolve(int(a["id"]))),
        _tool("schedule_list", "Listar tareas programadas (A3)",
              {}, lambda a: s.schedule_list()),
        _tool("schedule_add", "Programar tarea (A3)",
              {"name": {"type": "string", "required": True},
               "type": {"type": "string", "required": True,
                        "enum": ["tunnel_start", "tunnel_stop",
                                 "forwards_apply", "forwards_clear",
                                 "apply_profile", "snapshot_state"]},
               "time": {"type": "string", "required": True},
               "days": {"type": "string"},
               "tunnel": {"type": "string"},
               "profile": {"type": "string"}},
              lambda a: s.schedule_add(a["name"], a["type"], a["time"],
                                       a.get("days", ""),
                                       a.get("tunnel"), a.get("profile"))),
        _tool("schedule_remove", "Eliminar tarea programada (A3)",
              {"id": {"type": "string", "required": True}},
              lambda a: s.schedule_remove(a["id"])),
        _tool("profile_list", "Listar perfiles de exposicion (A2)",
              {}, lambda a: s.profile_list()),
        _tool("profile_apply", "Aplicar perfil (A2)",
              {"name": {"type": "string", "required": True}},
              lambda a: s.profile_apply(a["name"])),
        _tool("profile_capture", "Capturar perfil del estado actual (A2)",
              {"name": {"type": "string", "required": True},
               "description": {"type": "string"}},
              lambda a: s.profile_capture(a["name"], a.get("description", ""))),
        _tool("maintenance_on", "Activar modo mantenimiento (F15/A8; destructivo)",
              {}, lambda a: s.maintenance_on()),
        _tool("maintenance_off", "Desactivar modo mantenimiento (F15/A8)",
              {}, lambda a: s.maintenance_off()),
        _tool("maintenance_status", "Estado del mantenimiento (F15/A8)",
              {}, lambda a: s.maintenance_status()),
        _tool("drift_check", "Config vs realidad: diferencias (F13)",
              {}, lambda a: s.drift_check()),
        _tool("doctor", "Detector de problemas del entorno (U8)",
              {}, lambda a: s.doctor()),
        _tool("wsl_distros", "Listar distros WSL con estado (Running/Stopped)",
              {}, lambda a: s.wsl_distros_list()),
        _tool("wsl_exec",
              "Enviar un comando a la terminal (bash) de una distro WSL y "
              "recibir su salida. command se ejecuta via bash -lc; devuelve "
              "stdout/stderr/exit_code. Usa comandos no interactivos.",
              {"distro": {"type": "string", "required": True},
               "command": {"type": "string", "required": True},
               "timeout": {"type": "number"}},
              lambda a: s.wsl_exec(a["distro"], a["command"],
                                   float(a.get("timeout", 120)))),
        _tool("distro_list_available",
              "Catalogo de distros WSL disponibles para instalar "
              "(wsl --list --online).",
              {}, lambda a: s.distros_available()),
        _tool("distro_create",
              "Crear/instalar una distro WSL desde el catalogo "
              "(wsl --install -d <name>). custom_name la registra con otro "
              "nombre para poder instalar el mismo SO varias veces.",
              {"name": {"type": "string", "required": True},
               "custom_name": {"type": "string"},
               "no_launch": {"type": "boolean"}},
              lambda a: s.distro_create(
                  a["name"], custom_name=a.get("custom_name", ""),
                  no_launch=bool(a.get("no_launch", True)))),
        _tool("distro_clone",
              "Clonar una distro WSL existente con un nombre nuevo "
              "(export + import). Puede tardar varios minutos.",
              {"name": {"type": "string", "required": True},
               "new_name": {"type": "string", "required": True}},
              lambda a: s.distro_clone(a["name"], a["new_name"])),
        _tool("distro_export",
              "Exportar una distro WSL a un archivo .tar "
              "(wsl --export). Puede tardar varios minutos.",
              {"name": {"type": "string", "required": True},
               "target": {"type": "string", "required": True}},
              lambda a: s.distro_export(a["name"], a["target"])),
        _tool("distro_import",
              "Importar un archivo .tar como distro WSL nueva "
              "(wsl --import). install_dir opcional "
              "(por defecto %LOCALAPPDATA%\\WSL\\<name>).",
              {"source": {"type": "string", "required": True},
               "name": {"type": "string", "required": True},
               "install_dir": {"type": "string"}},
              lambda a: s.distro_import(a["source"], a["name"],
                                        a.get("install_dir", ""))),
    ]


class McpServer:
    def __init__(
        self,
        service: AppService | None = None,
        tools: list[dict] | None = None,
        token: str | None = None,
    ) -> None:
        self.service = service or AppService()
        self.tools = tools if tools is not None else build_tools(self.service)
        self.token = token if token is not None \
            else os.environ.get("PORT_FORWARDER_TOKEN") or ""
        self.rate_limiter = RateLimiter()

    # -- protocolo -----------------------------------------------------------------

    def handle(self, msg: dict[str, Any]) -> dict[str, Any] | None:
        """Procesa un mensaje JSON-RPC; None = notificacion (sin respuesta)."""
        method = msg.get("method")
        msg_id = msg.get("id")
        params = msg.get("params") or {}

        if method == "initialize":
            return {
                "jsonrpc": "2.0", "id": msg_id,
                "result": {
                    "protocolVersion": PROTOCOL_VERSION,
                    "capabilities": {"tools": {"listChanged": False}},
                    "serverInfo": {"name": "port-forwarder",
                                   "version": __version__},
                },
            }
        if method == "notifications/initialized":
            return None
        if method == "ping":
            return {"jsonrpc": "2.0", "id": msg_id, "result": {}}
        if method == "tools/list":
            public = [{k: t[k] for k in ("name", "description", "inputSchema")}
                      for t in self.tools]
            return {"jsonrpc": "2.0", "id": msg_id,
                    "result": {"tools": public}}
        if method == "tools/call":
            name = params.get("name", "")
            arguments = params.get("arguments") or {}
            if self.token:
                blocked, remaining = self.rate_limiter.is_blocked("mcp")
                if blocked:
                    return self._error(msg_id, -32001,
                                       f"demasiados intentos, espera {int(remaining)}s")
                provided = arguments.get("token") or \
                    (arguments.get("_meta") or {}).get("token")
                if provided != self.token:
                    self.rate_limiter.record_failure("mcp")
                    blocked, remaining = self.rate_limiter.is_blocked("mcp")
                    if blocked:
                        return self._error(msg_id, -32001,
                                           f"demasiados intentos, espera {int(remaining)}s")
                    return self._error(msg_id, -32001,
                                       "token invalido (PORT_FORWARDER_TOKEN)")
                self.rate_limiter.record_success("mcp")
            tool = next((t for t in self.tools if t["name"] == name), None)
            if tool is None:
                return self._error(msg_id, -32602, f"tool desconocida: {name}")
            try:
                result = tool["handler"](arguments)
            except (KeyError, TypeError, ValueError) as e:
                return self._error(msg_id, -32602, f"argumentos invalidos: {e}")
            except Exception as e:
                log.exception("tool %s fallo", name)
                return self._error(msg_id, -32603, str(e))
            is_error = isinstance(result, dict) and result.get("ok") is False
            return {
                "jsonrpc": "2.0", "id": msg_id,
                "result": {
                    "content": [{
                        "type": "text",
                        "text": json.dumps(result, ensure_ascii=False,
                                           default=str),
                    }],
                    "isError": is_error,
                },
            }
        return self._error(msg_id, -32601, f"metodo desconocido: {method}")

    @staticmethod
    def _error(msg_id: Any, code: int, message: str) -> dict[str, Any]:
        return {"jsonrpc": "2.0", "id": msg_id,
                "error": {"code": code, "message": message}}

    # -- loop stdio ----------------------------------------------------------------

    def serve(self, stdin=None, stdout=None) -> int:
        stdin = stdin or sys.stdin
        stdout = stdout or sys.stdout
        log.info("MCP stdio listo (token %s)",
                 "requerido" if self.token else "no configurado")
        for line in stdin:
            line = line.strip()
            if not line:
                continue
            try:
                msg = json.loads(line)
            except ValueError:
                continue
            response = self.handle(msg)
            if response is not None:
                stdout.write(json.dumps(response, ensure_ascii=False) + "\n")
                stdout.flush()
        return 0

    # -- self-test -------------------------------------------------------------------

    def selftest(self) -> list[dict[str, Any]]:
        """Handshake completo con un cliente virtual (para 'mcp test')."""
        results: list[dict[str, Any]] = []
        r = self.handle({"jsonrpc": "2.0", "id": 1, "method": "initialize",
                         "params": {"protocolVersion": PROTOCOL_VERSION,
                                    "clientInfo": {"name": "selftest"}}})
        results.append({"step": "initialize", "ok": r is not None
                        and "result" in r})
        assert self.handle({"jsonrpc": "2.0",
                            "method": "notifications/initialized"}) is None
        r = self.handle({"jsonrpc": "2.0", "id": 2, "method": "tools/list"})
        n_tools = len(r["result"]["tools"]) if r else 0
        results.append({"step": "tools/list", "ok": n_tools > 0,
                        "tools": n_tools})
        args = {"token": self.token} if self.token else {}
        r = self.handle({"jsonrpc": "2.0", "id": 3, "method": "tools/call",
                         "params": {"name": "status", "arguments": args}})
        results.append({"step": "tools/call status", "ok": r is not None
                        and "result" in r})
        r = self.handle({"jsonrpc": "2.0", "id": 4, "method": "tools/call",
                         "params": {"name": "no-existe", "arguments": args}})
        results.append({"step": "tool desconocida", "ok": r is not None
                        and "error" in r})
        return results


class McpHttpServer:
    """Transporte HTTP del MCP: JSON-RPC 2.0 por POST /mcp.

    Lo arranca el supervisor cuando mcp.enabled=true y mcp.transport=http
    (Ajustes del panel/GUI). Autenticacion: si hay token, todo POST exige
    'Authorization: Bearer <token>'. Solo escucha en 127.0.0.1; la salida a
    Internet es por el tunnel mcp-to-vps (local 8796 -> VPS:55872).
    """

    def __init__(self, service: "AppService | None" = None,
                 host: str = "127.0.0.1", port: int = 8796,
                 token: str = "", expose_exec: bool = True) -> None:
        self.mcp = McpServer(service, token="")  # el bearer se valida en el borde
        # C-1: interruptor de la herramienta peligrosa (RCE en distros).
        # Filtrada de self.tools: no aparece en tools/list y tools/call la
        # rechaza como "tool desconocida" (unica fuente de verdad).
        self.expose_exec = bool(expose_exec)
        if not self.expose_exec:
            self.mcp.tools = [t for t in self.mcp.tools
                              if t.get("name") != "wsl_exec"]
        self.bearer = token or ""
        self.host = host
        self.port = port
        self.running = False
        self._httpd = None
        self._thread: threading.Thread | None = None

    def start(self) -> None:
        from http.server import BaseHTTPRequestHandler

        from wsl_port.vendor.port_forwarder.utils.http_server import (
            BoundedThreadingHTTPServer,
        )

        outer = self

        class _Handler(BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

            def log_message(self, fmt, *args):  # silenciar access log
                log.debug("mcp-http " + fmt, *args)

            def _send(self, code: int, obj: dict) -> None:
                body = json.dumps(obj, ensure_ascii=False).encode("utf-8")
                self.send_response(code)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.send_header("X-Content-Type-Options", "nosniff")
                self.send_header("Cache-Control", "no-store")
                self.end_headers()
                self.wfile.write(body)

            def _authed(self) -> bool:
                if not outer.bearer:
                    return True
                return self.headers.get("Authorization", "") == f"Bearer {outer.bearer}"

            def do_GET(self) -> None:
                path = self.path.split("?", 1)[0]
                if path in ("/health", "/mcp/health"):
                    self._send(200, {"ok": True, "server": "port-forwarder-mcp",
                                     "tools": len(outer.mcp.tools)})
                    return
                self._send(404, {"error": "usa POST /mcp"})

            def do_POST(self) -> None:
                path = self.path.split("?", 1)[0]
                if path not in ("/mcp", "/mcp/", "/"):
                    self._send(404, {"error": "endpoint: POST /mcp"})
                    return
                if not self._authed():
                    self._send(401, {"error": "token invalido "
                                  "(Authorization: Bearer <token>)"})
                    return
                try:
                    length = int(self.headers.get("Content-Length") or 0)
                    if length <= 0 or length > 4 * 1024 * 1024:
                        self._send(400, {"error": "body requerido (max 4MB)"})
                        return
                    msg = json.loads(self.rfile.read(length).decode("utf-8"))
                except (ValueError, UnicodeDecodeError):
                    self._send(400, {"error": "JSON invalido"})
                    return
                try:
                    resp = outer.mcp.handle(msg)
                except Exception as e:  # noqa: BLE001
                    log.exception("mcp-http handle fallo")
                    self._send(500, {"error": str(e)})
                    return
                if resp is None:  # notificacion: ACK vacio
                    self._send(200, {"ok": True})
                    return
                self._send(200, resp)

        self._httpd = BoundedThreadingHTTPServer((self.host, self.port), _Handler)
        if self.port == 0:
            self.port = self._httpd.server_address[1]
        self.running = True
        self._thread = threading.Thread(
            target=self._httpd.serve_forever, name="mcp-http", daemon=True)
        self._thread.start()
        log.info("MCP HTTP en http://%s:%s/mcp (token %s)",
                 self.host, self.port,
                 "requerido" if self.bearer else "no configurado")

    def stop(self) -> None:
        self.running = False
        if self._httpd is not None:
            self._httpd.shutdown()
            self._httpd.server_close()
            self._httpd = None
        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=5)
        log.info("MCP HTTP detenido")
