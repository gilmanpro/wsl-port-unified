"""Servidor del panel web integrado wsl-port + API JSON estilo /api/v1.

Endpoints:
  GET  /                      -> dashboard HTML (estilo GUI)
  GET  /ws                    -> WebSocket: estado en tiempo real + terminal WSL
     cliente -> {type: term_start|term_cmd|term_stop, distro?, cmd?}
     servidor -> {type: term_status|term_out|term_exit, ...}
  GET  /api/v1/state          -> estado completo (supervisor + metricas)
  GET  /api/v1/events         -> journal reciente (SQLite)
  GET  /api/v1/alerts         -> alertas abiertas/recientes
  GET  /api/v1/health         -> health check
  GET  /api/v1/vps            -> VPS registrados
  GET  /api/v1/distros        -> lista distros WSL
  GET  /api/v1/distro/<name>/metrics -> metricas de una distro
  GET  /api/v1/distro/<name>/export -> exportar distro (descarga tar)
  POST /api/v1/distro/import  -> importar distro (subida tar)
  POST /api/v1/distro/<name>/<op> -> start|stop|restart|delete
  POST /api/v1/distro/create  -> crear distro (desde catalogo)
  POST /api/v1/forwards/apply -> reaplicar forwards
  POST /api/v1/forwards/clear -> limpiar todos
  POST /api/v1/forwards/add   -> crear forward
  POST /api/v1/forwards/remove/<id> -> eliminar forward
  POST /api/v1/tunnels/<id>/<op> -> start|stop|restart
  POST /api/v1/tunnels/add    -> crear tunnel
  POST /api/v1/tunnels/remove/<id> -> eliminar tunnel
  POST /api/v1/vps/add        -> registrar VPS
  POST /api/v1/vps/remove/<id> -> eliminar VPS
  POST /api/v1/publish        -> publicar servicio en Internet (1 clic)
  POST /api/v1/unpublish/<tunnel_id> -> detener publicacion

Auth OBLIGATORIA: el panel exige 'Authorization: Bearer <token>' en /api/*
(el token se configura en Ajustes de la GUI o con 'secrets set web_panel_token').
"""

from __future__ import annotations

import base64
import hashlib
import json
import logging
import socket
import struct
import threading
import time
from http.server import BaseHTTPRequestHandler
from typing import Any
from urllib.parse import parse_qs, urlparse

from wsl_port.vendor.port_forwarder.core.config import Bind, Forward, HealthCheck, Tunnel, TunnelHealthGate, Vps
from wsl_port.vendor.port_forwarder.core.event_bus import bus
from wsl_port.vendor.port_forwarder.core.metrics_store import MetricsStore
from wsl_port.vendor.port_forwarder.core.supervisor import Supervisor
from wsl_port.vendor.port_forwarder.utils.http_server import BoundedThreadingHTTPServer

log = logging.getLogger("wsl-port.web")

DEFAULT_PORT = 8780
DEFAULT_BIND = "127.0.0.1"

LOGIN_MAX_ATTEMPTS = 5
LOGIN_WINDOW = 300
LOGIN_BLOCK_TIME = 900


class RateLimiter:
    """Contador por IP con ventana deslizante y bloqueo temporal (thread-safe)."""

    def __init__(self, max_attempts: int = LOGIN_MAX_ATTEMPTS,
                 window: float = LOGIN_WINDOW, block_time: float = LOGIN_BLOCK_TIME) -> None:
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
            # limpiar bloqueo expirado
            if key in self._blocked_until and now >= until:
                del self._blocked_until[key]
                self._attempts.pop(key, None)
            # limpiar intentos fuera de ventana
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
                log.warning("rate limit: %s bloqueado %.0fs tras %d fallos", key, self.block_time, len(lst))

    def record_success(self, key: str) -> None:
        with self._lock:
            self._attempts.pop(key, None)
            self._blocked_until.pop(key, None)

    def remaining(self, key: str) -> int:
        with self._lock:
            lst = self._attempts.get(key, [])
            now = time.time()
            lst = [t for t in lst if now - t < self.window]
            return max(0, self.max_attempts - len(lst))


def _json(data: Any) -> tuple[bytes, int]:
    body = json.dumps(data, ensure_ascii=False, default=str).encode("utf-8")
    return body, 200


# -- WebSocket: lock global de envio (evita entrelazar frames de hilos) ----

_WS_SEND_MU = threading.Lock()

CREATE_NO_WINDOW = 0x08000000


def _decode_wsl_bytes(data: bytes) -> str:
    """Decodifica salida cruda de wsl.exe/bash (UTF-8 o UTF-16-LE)."""
    if not data:
        return ""
    if data.startswith(b"\xff\xfe") or data.startswith(b"\xfe\xff"):
        try:
            return data.decode("utf-16")
        except (UnicodeDecodeError, UnicodeError):
            pass
    try:
        s = data.decode("utf-8")
        if "\x00" in s:
            return data.decode("utf-16-le", errors="replace")
        return s
    except UnicodeDecodeError:
        return data.decode("utf-16-le", errors="replace")


class WslTerminal:
    """Sesion de terminal WSL sobre WebSocket.

    Mantiene un `bash -i` persistente por conexion (wsl.exe -d <distro>).
    Cada comando se ejecuta seguido de un sentinel `echo __WSPORT_<n>_EXIT_$?__`
    para delimitar la salida y reportar el codigo de salida. No usa PTY (no hay
    ConPTY en stdlib): programas interactivos a pantalla completa (vim, top)
    no funcionan, pero el resto de la shell si (cd, env, pipes, history).
    """

    _nonce_seq = 0
    _nonce_mu = threading.Lock()

    def __init__(self, distro: str, send: Any) -> None:
        self.distro = distro
        self._send = send  # callable(dict) -> envia JSON al cliente
        with WslTerminal._nonce_mu:
            WslTerminal._nonce_seq += 1
            self._nonce = f"{WslTerminal._nonce_seq:04x}{int(time.time()) % 0xFFFF:x}"
        self.proc = None
        self._thread: threading.Thread | None = None
        self._lock = threading.Lock()
        self.dead = False
        self.ready = False

    # -- ciclo de vida ------------------------------------------------------

    def start(self) -> str | None:
        """Arranca bash en la distro. Devuelve error o None si OK."""
        import subprocess
        if self.proc is not None:
            return None
        try:
            self.proc = subprocess.Popen(
                ["wsl.exe", "-d", self.distro, "--",
                 "bash", "--noediting", "--norc", "--noprofile", "-i"],
                stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT, creationflags=CREATE_NO_WINDOW,
            )
        except Exception as e:
            return f"no se pudo abrir terminal en '{self.distro}': {e}"
        self._thread = threading.Thread(
            target=self._reader, name=f"wsl-term-{self.distro}", daemon=True)
        self._thread.start()
        # wsl.exe hereda el cwd de Windows; forzar el home de la distro
        # (cd "$HOME"; si no existe, raiz /) antes de dar la terminal por lista.
        # El READY incluye el pwd final para mostrarlo en la UI.
        self._write(f'cd "$HOME" 2>/dev/null || cd /; '
                    f'PS1=""; PS2=""; echo __WSPORT_{self._nonce}_READY__$(pwd)')
        return None

    def stop(self) -> None:
        if self.proc is None:
            self.dead = True
            return
        self.dead = True
        try:
            import subprocess
            subprocess.run(
                ["taskkill", "/F", "/T", "/PID", str(self.proc.pid)],
                capture_output=True, timeout=5,
                creationflags=CREATE_NO_WINDOW,
            )
        except Exception:
            try:
                self.proc.kill()
            except Exception:
                pass

    # -- E/S ------------------------------------------------------------------

    def _write(self, line: str) -> bool:
        if self.proc is None or self.dead:
            return False
        try:
            with self._lock:
                self.proc.stdin.write((line + "\n").encode("utf-8"))
                self.proc.stdin.flush()
            return True
        except Exception:
            self.dead = True
            return False

    def submit(self, cmd: str) -> None:
        """Envia una linea de comando + sentinel de terminacion."""
        if self.dead:
            self._send({"type": "term_status", "state": "closed",
                        "message": "terminal cerrada, vuelve a abrirla"})
            return
        for part in str(cmd).split("\n"):
            if not self._write(part):
                break
            if part.strip() != "":
                self._write(f"echo __WSPORT_{self._nonce}_EXIT_$?__")

    def _reader(self) -> None:
        ready_sent = False
        prefix_exit = f"__WSPORT_{self._nonce}_EXIT_"
        prefix_ready = f"__WSPORT_{self._nonce}_READY__"
        try:
            for raw in self.proc.stdout:
                line = _decode_wsl_bytes(raw)
                if not ready_sent:
                    if prefix_ready in line:
                        ready_sent = True
                        self.ready = True
                        idx_r = line.find(prefix_ready)
                        cwd = line[idx_r + len(prefix_ready):].strip()
                        self._send({"type": "term_status", "state": "running",
                                    "distro": self.distro, "cwd": cwd})
                    continue
                idx = line.find(prefix_exit)
                if idx != -1:
                    if idx > 0:
                        self._send({"type": "term_out",
                                    "data": line[:idx] + "\n"})
                    code = line[idx + len(prefix_exit):].strip()
                    try:
                        code_n = int(code.split("_")[0])
                    except ValueError:
                        code_n = -1
                    self._send({"type": "term_exit", "code": code_n})
                else:
                    self._send({"type": "term_out", "data": line})
        except Exception:
            pass
        self.dead = True
        self._send({"type": "term_status", "state": "closed",
                    "message": f"terminal de '{self.distro}' finalizada"})


# -- CSP nonce (H4): nonce aleatorio por request para <script>/<style> ----

import secrets as _web_secrets

def _nonce() -> str:
    return _web_secrets.token_urlsafe(16)

class PanelHandler(BaseHTTPRequestHandler):
    panel: "WebPanel"  # inyectado por WebPanel.start (clase dinámica)

    # -- helpers -------------------------------------------------------------

    def _html_augment(self, html: str, nonce: str) -> str:
        """Inyecta el nonce CSP en <script>/<style> inline del HTML."""
        html = html.replace("<script>", f'<script nonce="{nonce}">')
        html = html.replace("<style>", f'<style nonce="{nonce}">')
        return html

    def _csp(self, nonce: str) -> str:
        # H4: sin 'unsafe-inline' en script-src (mitiga XSS); estilos inline
        # se permiten (no son vector de XSS en ningun navegador moderno).
        return (
            "default-src 'self'; "
            f"script-src 'self' 'nonce-{nonce}'; "
            "style-src 'self' 'unsafe-inline'; "
            "img-src 'self' data:; "
            "frame-ancestors 'none'; base-uri 'none'; form-action 'self'"
        )

    def _send(self, body: bytes | str, status: int = 200, ctype: str = "application/json") -> None:
        if isinstance(body, str):
            body = body.encode("utf-8")
        nonce = _nonce()
        # Inyectar nonce en HTML con estilos/scripts inline
        html_text = body.decode("utf-8", errors="ignore")
        if ctype.startswith("text/html") and "<script" in html_text:
            body = self._html_augment(html_text, nonce).encode("utf-8")
        try:
            self.send_response(status)
            self.send_header("Content-Type", f"{ctype}; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            # Defensa H2/M1: headers de seguridad en todas las respuestas.
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("X-Frame-Options", "DENY")
            self.send_header("Referrer-Policy", "no-referrer")
            self.send_header("Content-Security-Policy", self._csp(nonce))
            self.end_headers()
            if body:
                self.wfile.write(body)
        except (ConnectionResetError, BrokenPipeError, OSError):
            pass

    # -- CSRF (H1): las mutaciones exigen Origin/Referer del mismo host. ----

    def _same_origin(self, url: str) -> bool:
        try:
            parsed = urlparse(url)
        except ValueError:
            return False
        origin_netloc = parsed.netloc
        host = self.headers.get("Host", "")
        if not origin_netloc or not host:
            return False
        return origin_netloc.lower() == host.lower()

    def _csrf_ok(self) -> bool:
        origin = self.headers.get("Origin")
        if origin:
            return self._same_origin(origin)
        referer = self.headers.get("Referer")
        if referer:
            return self._same_origin(referer)
        # Sin Origin ni Referer no es un navegador (curl/script/API):
        # no hay riesgo de CSRF, permitir (la auth Bearer sigue obligatoria).
        return True

    def _authed(self) -> bool:
        token = self.panel.token
        if not token:
            return True
        auth = self.headers.get("Authorization", "")
        if auth == f"Bearer {token}":
            return True
        # Cookie de sesion (login via /login)
        cookie = self.headers.get("Cookie", "")
        if f"pf_token={token}" in cookie:
            return True
        return False

    def _deny(self, status: int = 401, msg: str = "no autorizado") -> None:
        self._send(json.dumps({"ok": False, "error": msg},
                              ensure_ascii=False).encode("utf-8"), status)

    def _client_ip(self) -> str:
        try:
            return self.client_address[0] if self.client_address else "unknown"
        except Exception:
            return "unknown"

    def _rate_limited(self) -> bool:
        """Si el IP esta bloqueado, responde 429 y devuelve True."""
        blocked, remaining = self.panel.rate_limiter.is_blocked(self._client_ip())
        if blocked:
            body = json.dumps(
                {"ok": False, "error": f"demasiados intentos, espera {int(remaining)}s"},
                ensure_ascii=False,
            ).encode("utf-8")
            self.send_response(429)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Retry-After", str(int(remaining)))
            self.send_header("X-RateLimit-Remaining", "0")
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            self.wfile.write(body)
            return True
        return False

    def _handle_login(self) -> None:
        """POST /api/v1/login — valida token con rate limiting."""
        if self._rate_limited():
            return
        length = int(self.headers.get("Content-Length") or 0)
        try:
            raw = self.rfile.read(length) if length else b""
            body = json.loads(raw.decode("utf-8")) if raw.strip() else {}
        except (ValueError, json.JSONDecodeError):
            self._deny(400, "body JSON invalido")
            return
        token = str(body.get("token") or body.get("password") or "").strip()
        ip = self._client_ip()
        if token and token == self.panel.token:
            self.panel.rate_limiter.record_success(ip)
            body_b, _ = _json({"ok": True, "message": "login correcto"})
            self.send_response(200)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Content-Length", str(len(body_b)))
            # Cookie de sesion para que GET / funcione sin Bearer header
            cookie_flags = "Path=/; HttpOnly; SameSite=Strict"
            if self.headers.get("X-Forwarded-Proto", "").lower() == "https":
                cookie_flags += "; Secure"
            self.send_header("Set-Cookie", f"pf_token={token}; {cookie_flags}")
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            self.wfile.write(body_b)
            log.info("login ok desde %s", ip)
            return
        else:
            self.panel.rate_limiter.record_failure(ip)
            blocked, remaining = self.panel.rate_limiter.is_blocked(ip)
            if blocked:
                body_b, _ = _json({"ok": False, "error": f"demasiados intentos, espera {int(remaining)}s"})
                self.send_response(429)
                self.send_header("Content-Type", "application/json; charset=utf-8")
                self.send_header("Content-Length", str(len(body_b)))
                self.send_header("Retry-After", str(int(remaining)))
                self.send_header("X-RateLimit-Remaining", "0")
                self.send_header("Cache-Control", "no-store")
                self.end_headers()
                self.wfile.write(body_b)
            else:
                remaining = self.panel.rate_limiter.remaining(ip)
                body_b, _ = _json({"ok": False, "error": "token invalido"})
                self.send_response(401)
                self.send_header("Content-Type", "application/json; charset=utf-8")
                self.send_header("Content-Length", str(len(body_b)))
                self.send_header("X-RateLimit-Remaining", str(remaining))
                self.send_header("Cache-Control", "no-store")
                self.end_headers()
                self.wfile.write(body_b)

    def log_message(self, fmt: str, *args: Any) -> None:
        log.debug(fmt, *args)

    # -- rutas ----------------------------------------------------------------

    def _ws_handshake(self) -> socket.socket | None:
        """Upgrade a WebSocket si el cliente lo pide. Devuelve el socket crudo o None."""
        log.info("WS handshake desde %s path=%s", self._client_ip(), self.path)
        key = self.headers.get("Sec-WebSocket-Key", "")
        if not key:
            log.warning("WS sin Sec-WebSocket-Key")
            return None
        # Validar token via cookie, Authorization header, o query string (para WS del navegador)
        cookie = self.headers.get("Cookie", "")
        token_ck = ""
        for part in cookie.split(";"):
            if "pf_token=" in part:
                token_ck = part.split("pf_token=", 1)[1].strip()
                break
        # Query string token (navegador no puede enviar headers custom en WebSocket)
        parsed_qs = urlparse(self.path)
        qs_token = ""
        for kv in (parsed_qs.query or "").split("&"):
            if kv.startswith("token="):
                qs_token = kv.split("=", 1)[1]
                break
        provided = token_ck or qs_token or self.headers.get("Authorization", "").removeprefix("Bearer ").strip()
        if self.panel.token and provided != self.panel.token:
            # No autorizado para WS
            self.send_response(401)
            self.send_header("Content-Length", "0")
            self.end_headers()
            return None
        accept = base64.b64encode(hashlib.sha1((key + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11").encode()).digest()).decode()
        self.send_response(101, "Switching Protocols")
        self.send_header("Upgrade", "websocket")
        self.send_header("Connection", "Upgrade")
        self.send_header("Sec-WebSocket-Accept", accept)
        self.end_headers()
        return self.request

    @staticmethod
    def _recv_exact(sock: socket.socket, n: int) -> bytes | None:
        buf = b""
        while len(buf) < n:
            try:
                chunk = sock.recv(n - len(buf))
            except socket.timeout:
                raise
            except Exception:
                return None
            if not chunk:
                return None
            buf += chunk
        return buf

    def _ws_read_frame(self, sock: socket.socket) -> tuple[int, bytes] | None:
        """Lee un frame WebSocket (con desencapsulado de mask). None = cerrar."""
        header = self._recv_exact(sock, 2)
        if not header:
            return None
        opcode = header[0] & 0x0F
        masked = header[1] & 0x80
        length = header[1] & 0x7F
        if length == 126:
            ext = self._recv_exact(sock, 2)
            if not ext:
                return None
            length = struct.unpack("!H", ext)[0]
        elif length == 127:
            ext = self._recv_exact(sock, 8)
            if not ext:
                return None
            length = struct.unpack("!Q", ext)[0]
        if length > 1 << 20:  # 1 MB max por frame
            return None
        mask = b""
        if masked:
            mask = self._recv_exact(sock, 4)
            if mask is None:
                return None
        payload = self._recv_exact(sock, length) if length else b""
        if payload is None:
            return None
        if masked and mask:
            payload = bytes(b ^ mask[i % 4] for i, b in enumerate(payload))
        return opcode, payload

    def _ws_serve(self, sock: socket.socket) -> None:
        """Loop WebSocket: estado inicial + terminal WSL (term_* por frame texto)."""
        panel = self.panel
        with panel._ws_lock:
            panel.ws_clients.add(sock)

        def send(obj: dict) -> None:
            try:
                data = json.dumps(obj, ensure_ascii=False).encode("utf-8")
                panel._ws_send(sock, data)
            except Exception:
                pass

        term: WslTerminal | None = None
        try:
            # Estado inicial
            try:
                state = panel.state()
                send({"type": "state", "data": state})
            except Exception:
                pass
            sock.settimeout(30)
            while panel.running:
                try:
                    frame = self._ws_read_frame(sock)
                except socket.timeout:
                    # Ping de keepalive + chequear que la terminal siga viva
                    send({"type": "ping"})
                    continue
                except Exception:
                    break
                if frame is None:
                    break
                opcode, payload = frame
                if opcode == 0x8:  # close
                    break
                if opcode == 0x9:  # ping -> pong
                    try:
                        sock.sendall(b"\x8A\x00")
                    except Exception:
                        break
                    continue
                if opcode in (0x1, 0x2) and payload:  # texto/binario: JSON
                    try:
                        msg = json.loads(payload.decode("utf-8"))
                    except (ValueError, UnicodeDecodeError):
                        continue
                    if not isinstance(msg, dict):
                        continue
                    mtype = msg.get("type")
                    if mtype == "term_start":
                        if term is not None:
                            term.stop()
                        distro = str(msg.get("distro") or "").strip()
                        if not distro:
                            send({"type": "term_status", "state": "error",
                                  "message": "distro requerida"})
                            continue
                        term = WslTerminal(distro, send)
                        err = term.start()
                        if err:
                            send({"type": "term_status", "state": "error",
                                  "message": err})
                            term = None
                    elif mtype == "term_cmd":
                        if term is None or term.dead:
                            send({"type": "term_status", "state": "closed",
                                  "message": "abre la terminal primero"})
                        else:
                            term.submit(str(msg.get("cmd") or ""))
                    elif mtype == "term_stop":
                        if term is not None:
                            term.stop()
                            term = None
                        send({"type": "term_status", "state": "closed",
                              "message": "terminal cerrada"})
                # opcodes restantes (continuation, pong) se ignoran
        finally:
            if term is not None:
                try:
                    term.stop()
                except Exception:
                    pass
            with panel._ws_lock:
                panel.ws_clients.discard(sock)
            try:
                sock.close()
            except Exception:
                pass

    def do_GET(self) -> None:
        try:
            self._do_GET_inner()
        except (ConnectionResetError, BrokenPipeError, OSError):
            pass
        except Exception:
            log.exception("GET %s fallo", getattr(self, 'path', '?'))

    def _do_GET_inner(self) -> None:
        parsed = urlparse(self.path)
        path = parsed.path
        # WebSocket upgrade
        if path == "/ws":
            sock = self._ws_handshake()
            if sock is not None:
                self._ws_serve(sock)
            return
        if path == "/login":
            self._send(LOGIN_HTML, 200, "text/html")
            return
        if path == "/":
            if self.panel.token and not self._authed():
                self._send(LOGIN_HTML, 200, "text/html")
                return
            self._send(self.panel.dashboard_html, 200, "text/html")
            return
        if not path.startswith("/api/"):
            self._deny(404, "no encontrado")
            return
        if not self._authed():
            if self._rate_limited():
                return
            self.panel.rate_limiter.record_failure(self._client_ip())
            blocked, remaining = self.panel.rate_limiter.is_blocked(self._client_ip())
            if blocked:
                body, _ = _json({"ok": False, "error": f"demasiados intentos, espera {int(remaining)}s"})
                self.send_response(429)
                self.send_header("Content-Type", "application/json; charset=utf-8")
                self.send_header("Content-Length", str(len(body)))
                self.send_header("Retry-After", str(int(remaining)))
                self.send_header("X-RateLimit-Remaining", "0")
                self.send_header("Cache-Control", "no-store")
                self.end_headers()
                self.wfile.write(body)
                return
            remaining = self.panel.rate_limiter.remaining(self._client_ip())
            body, _ = _json({"ok": False, "error": "no autorizado"})
            self.send_response(401)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.send_header("X-RateLimit-Remaining", str(remaining))
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            self.wfile.write(body)
            return
        # exito: limpiar contador
        self.panel.rate_limiter.record_success(self._client_ip())
        try:
            if path == "/api/v1/state":
                self._send(*_json(self.panel.state()))
            elif path == "/api/v1/events":
                limit = int(parse_qs(parsed.query).get("limit", ["50"])[0])
                self._send(*_json(self.panel.events(limit)))
            elif path == "/api/v1/alerts":
                self._send(*_json(self.panel.alerts()))
            elif path == "/api/v1/health":
                self._send(*_json(self.panel.health()))
            elif path == "/api/v1/vps":
                self._send(*_json(self.panel.vps_list()))
            elif path == "/api/v1/distros":
                self._send(*_json(self.panel.distros_list()))
            elif path == "/api/v1/keepalive":
                self._send(*_json(self.panel.keepalive_status()))
            elif path == "/api/v1/mcp/settings":
                store = self.panel.supervisor.store
                cfg = store.cfg.mcp
                vps_list = [
                    {"id": v.id, "host": v.host, "user": v.user, "port": v.port}
                    for v in store.cfg.vps_list
                ]
                mcp_http = getattr(self.panel.supervisor, "_mcp_http", None)
                response = {
                    "ok": True,
                    "http_running": bool(mcp_http and mcp_http.running),
                    "http_port": mcp_http.port if mcp_http else None,
                    "settings": {
                        "enabled": cfg.enabled,
                        "transport": cfg.transport,
                        "port": cfg.port,
                        "token_required": cfg.token_required,
                        "token": cfg.token,
                        "expose_exec": bool(getattr(cfg, "expose_exec", True)),
                        "vps_export_enabled": cfg.vps_export_enabled,
                        "vps_target_port": cfg.vps_target_port,
                        "vps_target_host": cfg.vps_target_host
                    },
                    "vps_list": vps_list
                }
                self._send(*_json(response))
            elif path.startswith("/api/v1/distro/") and path.endswith("/export"):
                parts = [p for p in path.split("/") if p]
                if len(parts) == 5 and parts[3] != "import":
                    self._handle_export(parts[3])
                else:
                    self._deny(404, "no encontrado")
            elif path.startswith("/api/v1/distro/") and path.endswith("/metrics"):
                parts = [p for p in path.split("/") if p]
                if len(parts) == 5:
                    self._send(*_json(self.panel._distro_metrics(parts[3])))
                else:
                    self._deny(404, "no encontrado")
            elif path.startswith("/api/v1/tunnels/") and path.endswith("/log"):
                parts = [p for p in path.split("/") if p]
                if len(parts) == 5:
                    self._send(*_json(self.panel.tunnel_log(parts[3])))
                else:
                    self._deny(404, "no encontrado")
            elif path.startswith("/api/v1/tunnels/") and path.endswith("/diag"):
                parts = [p for p in path.split("/") if p]
                if len(parts) == 5:
                    self._send(*_json(self.panel.tunnel_diag(parts[3])))
                else:
                    self._deny(404, "no encontrado")
            else:
                self._deny(404, "no encontrado")
        except Exception as e:
            log.exception("GET %s fallo", path)
            body, _ = _json({"ok": False, "error": str(e)})
            self._send(body, 500)

    def do_POST(self) -> None:
        try:
            self._do_POST_inner()
        except (ConnectionResetError, BrokenPipeError, OSError):
            pass
        except Exception:
            log.exception("POST %s fallo", getattr(self, 'path', '?'))

    def _do_POST_inner(self) -> None:
        parsed = urlparse(self.path)
        path = parsed.path
        if not path.startswith("/api/"):
            self._deny(404, "no encontrado")
            return
        # Login no requiere auth previa (es el login mismo)
        if path == "/api/v1/login":
            self._handle_login()
            return
        if not self._csrf_ok():
            self._deny(403, "origen no permitido (CSRF)")
            return
        if not self._authed():
            if self._rate_limited():
                return
            self.panel.rate_limiter.record_failure(self._client_ip())
            blocked, remaining = self.panel.rate_limiter.is_blocked(self._client_ip())
            if blocked:
                body, _ = _json({"ok": False, "error": f"demasiados intentos, espera {int(remaining)}s"})
                self.send_response(429)
                self.send_header("Content-Type", "application/json; charset=utf-8")
                self.send_header("Content-Length", str(len(body)))
                self.send_header("Retry-After", str(int(remaining)))
                self.send_header("X-RateLimit-Remaining", "0")
                self.send_header("Cache-Control", "no-store")
                self.end_headers()
                self.wfile.write(body)
                return
            remaining = self.panel.rate_limiter.remaining(self._client_ip())
            body, _ = _json({"ok": False, "error": "no autorizado"})
            self.send_response(401)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.send_header("X-RateLimit-Remaining", str(remaining))
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            self.wfile.write(body)
            return
        self.panel.rate_limiter.record_success(self._client_ip())

        # Import distro (multipart upload)
        if path == "/api/v1/distro/import":
            self._handle_import()
            return

        body: dict[str, Any] = {}
        try:
            length = int(self.headers.get("Content-Length") or 0)
            if length > 0:
                raw = self.rfile.read(length)
                if raw.strip():
                    body = json.loads(raw.decode("utf-8"))
        except (ValueError, json.JSONDecodeError):
            self._deny(400, "body JSON invalido")
            return
        try:
            result = self.panel.action(path, body)
            self._send(*_json(result))
        except Exception as e:
            log.exception("POST %s fallo", path)
            body, _ = _json({"ok": False, "error": str(e)})
            self._send(body, 500)

    def _handle_export(self, name: str) -> None:
        """Stream wsl --export as a tar download."""
        import subprocess
        import tempfile
        import os

        # Pre-check: si WSL no responde en 3s, devolver error rapido
        try:
            probe = subprocess.run(
                ["wsl.exe", "--list", "--verbose"],
                capture_output=True, timeout=3,
                creationflags=0x08000000,
            )
            if probe.returncode != 0:
                self._send(*_json({"ok": False, "error": "WSL no responde"}))
                return
        except subprocess.TimeoutExpired:
            self._send(*_json({"ok": False, "error": "WSL no responde (timeout)"}))
            return
        except Exception as e:
            self._send(*_json({"ok": False, "error": str(e)}))
            return

        tmp = tempfile.NamedTemporaryFile(suffix=".tar", delete=False)
        tmp_path = tmp.name
        tmp.close()

        try:
            proc = subprocess.run(
                ["wsl.exe", "--export", name, tmp_path],
                capture_output=True, timeout=600,
                creationflags=0x08000000
            )
            if proc.returncode != 0:
                error = proc.stderr.decode("utf-8", errors="replace").strip()
                if not error:
                    error = proc.stdout.decode("utf-8", errors="replace").strip()
                self._send(*_json({"ok": False, "error": f"export fallo: {error}"}))
                return

            file_size = os.path.getsize(tmp_path)
            self.send_response(200)
            self.send_header("Content-Type", "application/x-tar")
            self.send_header("Content-Disposition", f'attachment; filename="{name}.tar"')
            self.send_header("Content-Length", str(file_size))
            self.send_header("Cache-Control", "no-store")
            self.end_headers()

            with open(tmp_path, "rb") as f:
                while chunk := f.read(65536):
                    self.wfile.write(chunk)

        except subprocess.TimeoutExpired:
            self._send(*_json({"ok": False, "error": "export timeout (600s)"}))
        except Exception as e:
            self._send(*_json({"ok": False, "error": str(e)}))
        finally:
            try:
                os.unlink(tmp_path)
            except OSError:
                pass

    def _handle_import(self) -> None:
        """Stream multipart upload a disco y corre wsl --import."""
        import subprocess
        import tempfile
        import os

        # Pre-check: si WSL no responde en 3s, devolver error rapido
        try:
            probe = subprocess.run(
                ["wsl.exe", "--list", "--verbose"],
                capture_output=True, timeout=3,
                creationflags=0x08000000,
            )
            if probe.returncode != 0:
                self._send(*_json({"ok": False, "error": "WSL no responde"}))
                return
        except subprocess.TimeoutExpired:
            self._send(*_json({"ok": False, "error": "WSL no responde (timeout)"}))
            return
        except Exception as e:
            self._send(*_json({"ok": False, "error": str(e)}))
            return

        content_type = self.headers.get("Content-Type", "")
        if "multipart/form-data" not in content_type:
            self._send(*_json({"ok": False, "error": "Content-Type debe ser multipart/form-data"}))
            return

        boundary = None
        for part in content_type.split(";"):
            part = part.strip()
            if part.startswith("boundary="):
                boundary = part[9:].strip().strip('"')
                break
        if not boundary:
            self._send(*_json({"ok": False, "error": "boundary no encontrado"}))
            return

        content_length = int(self.headers.get("Content-Length", 0))
        if content_length <= 0:
            self._send(*_json({"ok": False, "error": "Content-Length requerido"}))
            return
        if content_length > 10 * 1024 * 1024 * 1024:  # 10GB max
            self._send(*_json({"ok": False, "error": "archivo demasiado grande (max 10GB)"}))
            return

        # 1) Stream body a archivo temporal en disco (no en RAM)
        raw_fd, raw_path = tempfile.mkstemp(suffix=".body")
        os.close(raw_fd)
        try:
            with open(raw_path, "wb") as out:
                remaining = content_length
                while remaining > 0:
                    chunk = self.rfile.read(min(262144, remaining))
                    if not chunk:
                        break
                    out.write(chunk)
                    remaining -= len(chunk)

            # 2) Parse multipart desde el archivo
            boundary_bytes = ("--" + boundary).encode()
            with open(raw_path, "rb") as rf:
                raw = rf.read()
            parts = raw.split(boundary_bytes)

            name = None
            install_dir = None
            tar_data = None
            for part in parts:
                if b"Content-Disposition" not in part:
                    continue
                header_end = part.find(b"\r\n\r\n")
                if header_end == -1:
                    continue
                headers_raw = part[:header_end].decode("utf-8", errors="replace")
                body_raw = part[header_end + 4:]
                if body_raw.endswith(b"\r\n"):
                    body_raw = body_raw[:-2]

                if 'name="name"' in headers_raw:
                    name = body_raw.decode("utf-8", errors="replace").strip()
                elif 'name="install_dir"' in headers_raw:
                    install_dir = body_raw.decode("utf-8", errors="replace").strip()
                elif 'name="file"' in headers_raw:
                    tar_data = body_raw

            if not name:
                self._send(*_json({"ok": False, "error": "name requerido"}))
                return
            if not tar_data:
                self._send(*_json({"ok": False, "error": "file (tar) requerido"}))
                return
            if not install_dir:
                install_dir = os.path.join(os.environ.get("LOCALAPPDATA", ""), "WSL", name)

            # 3) Escribir el tar a disco y correr wsl --import
            tar_path = None
            try:
                tar_fd, tar_path = tempfile.mkstemp(suffix=".tar")
                with os.fdopen(tar_fd, "wb") as tf:
                    tf.write(tar_data)

                proc = subprocess.run(
                    ["wsl.exe", "--import", name, install_dir, tar_path],
                    capture_output=True, timeout=600,
                    creationflags=0x08000000
                )
                # wsl --import puede mostrar warnings de .wslconfig en stderr pero tener returncode 0
                if proc.returncode != 0:
                    error = proc.stderr.decode("utf-16", errors="replace").strip()
                    if not error:
                        error = proc.stdout.decode("utf-16", errors="replace").strip()
                    # Filtrar warnings de .wslconfig no reconocidos (no son fatales)
                    error_lines = [l for l in error.split('\n') if 'desconocida' not in l.lower()]
                    if error_lines:
                        self._send(*_json({"ok": False, "error": f"import fallo: {error_lines[0][:200]}"}))
                        return
                    # Si solo hay warnings, continuar
                self.panel.metrics.record_event("web_distro_import", distro=name)
                self._send(*_json({"ok": True, "message": f"distro '{name}' importada correctamente"}))
            finally:
                if tar_path:
                    try:
                        os.unlink(tar_path)
                    except OSError:
                        pass
        finally:
            try:
                os.unlink(raw_path)
            except OSError:
                pass


class WebPanel:
    """Servidor web + supervisor asociado (mismos providers que CLI/GUI)."""

    def __init__(
        self,
        supervisor: Supervisor,
        port: int = DEFAULT_PORT,
        bind: str = DEFAULT_BIND,
        token: str = "",
        metrics: MetricsStore | None = None,
        dashboard_html: str | None = None,
    ) -> None:
        self.supervisor = supervisor
        self.port = port
        self.bind = bind
        # H-1: sin token el panel quedaria fail-open (_authed devuelve True).
        # Nunca: generar uno efimero fuerte y mostrarlo en el log para que el
        # operador lo copie desde Ajustes (o defina el suyo).
        self.token_generated = not token
        if not token:
            import secrets as _secrets

            token = _secrets.token_urlsafe(24)
            log.warning("web_panel sin token: generado uno efimero: %s "
                        "(definelo en Ajustes para uso permanente)", token)
        self.token = token
        self.metrics = metrics or supervisor.metrics
        self.dashboard_html = dashboard_html or DASHBOARD_HTML
        self.rate_limiter = RateLimiter()
        self._httpd: ThreadingHTTPServer | None = None
        self._thread: threading.Thread | None = None
        self.running = False
        self._ws_lock = threading.Lock()
        self.ws_clients: set = set()

    # -- ciclo de vida ---------------------------------------------------------

    def start(self) -> None:
        if self.running:
            return
        handler = type("PanelHandlerT", (PanelHandler,), {"panel": self})
        try:
            self._httpd = BoundedThreadingHTTPServer((self.bind, self.port), handler)
        except OSError as e:
            raise RuntimeError(
                f"no se pudo abrir {self.bind}:{self.port} ({e}). "
                "Revisa que el puerto este libre o cambia ui.web_panel_port."
            ) from e
        if self.port == 0:  # puerto efimero (tests)
            self.port = self._httpd.server_address[1]
        self.running = True
        self._thread = threading.Thread(
            target=self._httpd.serve_forever, name="web-panel", daemon=True
        )
        self._thread.start()
        # WebSocket broadcast loop
        self._ws_thread = threading.Thread(target=self._ws_broadcast_loop, name="web-ws-broadcast", daemon=True)
        self._ws_thread.start()
        log.info("panel web en http://%s:%s", self.bind, self.port)

    def stop(self) -> None:
        self.running = False
        # Cerrar WebSockets
        if hasattr(self, 'ws_clients'):
            with self._ws_lock:
                for ws in list(self.ws_clients):
                    try:
                        ws.close()
                    except Exception:
                        pass
                self.ws_clients.clear()
        if self._httpd:
            self._httpd.shutdown()
            self._httpd.server_close()
            self._httpd = None
        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=5)
        log.info("panel web detenido")

    def broadcast_ws(self, msg: dict) -> None:
        data = __import__("json").dumps(msg, ensure_ascii=False).encode("utf-8")
        dead = []
        with self._ws_lock:
            for ws in list(self.ws_clients):
                try:
                    self._ws_send(ws, data)
                except Exception:
                    dead.append(ws)
            for ws in dead:
                self.ws_clients.discard(ws)

    def _ws_broadcast_loop(self) -> None:
        while self.running:
            import time as _t
            _t.sleep(3)
            if not self.running or not getattr(self, 'ws_clients', None) or not self.ws_clients:
                continue
            try:
                state = self.state()
                self.broadcast_ws({"type": "state", "data": state})
            except Exception:
                pass

    @staticmethod
    def _ws_send(sock, data: bytes) -> None:
        import struct
        try:
            frame = bytearray()
            frame.append(0x81)
            length = len(data)
            if length < 126:
                frame.append(length)
            elif length < 65536:
                frame.append(126)
                frame.extend(struct.pack("!H", length))
            else:
                frame.append(127)
                frame.extend(struct.pack("!Q", length))
            frame.extend(data)
            # Lock global: broadcast + terminal comparten sockets; sendall
            # concurrentios entrelazarian frames.
            with _WS_SEND_MU:
                sock.sendall(frame)
        except (ConnectionResetError, BrokenPipeError, OSError):
            pass

    def status(self) -> dict[str, Any]:
        return {
            "running": self.running,
            "url": f"http://{self.bind}:{self.port}",
            "bind": self.bind,
            "port": self.port,
            "auth_required": bool(self.token),
            "supervisor_running": self.supervisor.running,
        }

    # -- datos -------------------------------------------------------------------

    @staticmethod
    def _parse_bind(text: Any, what: str) -> Bind:
        if not isinstance(text, str) or ":" not in text:
            raise ValueError(f"{what} debe ser host:puerto (ej. 0.0.0.0:80)")
        host, port = text.rsplit(":", 1)
        try:
            port = int(port)
        except ValueError:
            raise ValueError(f"{what}: puerto invalido '{port}'")
        if not host:
            raise ValueError(f"{what}: falta el host")
        return Bind(host=host, port=port)

    def state(self) -> dict[str, Any]:
        st = self.supervisor.status()
        distros = self._get_wsl_distros()
        vps_list = [
            {"id": v.id, "host": v.host, "user": v.user, "port": v.port}
            for v in self.supervisor.store.cfg.vps_list
        ]
        uptime: dict[str, Any] = {}
        traffic: dict[str, Any] = {}
        for t in st.get("tunnels", []):
            uptime[t["id"]] = self.metrics.tunnel_uptime_summary(t["id"])
            tun = self.supervisor.store.get_tunnel(t["id"])
            if tun is not None:
                try:
                    tf = self.supervisor.ssh.traffic_snapshot(tun)
                    if tf:
                        traffic[t["id"]] = tf
                except Exception:  # noqa: BLE001
                    pass
        st["distros"] = distros
        return {
            "ok": True,
            "status": st,
            "vps": vps_list,
            "distros": distros,
            "uptime": uptime,
            "traffic": traffic,
            "alerts": self.metrics.list_alerts(state="open", limit=20),
            "ts": time.time(),
        }

    def _get_wsl_distros(self) -> list[dict]:
        """Lista distros WSL via wsl.exe -l -v (timeout corto, no cuelga)."""
        distros = []
        try:
            import subprocess
            proc = subprocess.run(
                ["wsl.exe", "--list", "--verbose"],
                capture_output=True, timeout=5,
                creationflags=0x08000000,
            )
            if proc.returncode == 0:
                output = self._decode_wsl(proc.stdout)
                for line in output.splitlines():
                    line = line.strip()
                    if not line or "NAME" in line.upper() or "---" in line:
                        continue
                    if line.startswith("*"):
                        line = line[1:].strip()
                    parts = [p for p in line.split() if p]
                    if len(parts) >= 3:
                        name, state, ver = parts[0], parts[1], parts[2]
                    elif len(parts) == 2:
                        name, state, ver = parts[0], parts[1], "?"
                    else:
                        continue
                    distros.append({
                        "name": name, "state": state,
                        "version": ver, "ip": None,
                        "running": state.lower() == "running",
                    })
        except Exception:
            pass
        ka = getattr(self.supervisor, "keepalive", None)
        if ka is not None:
            try:
                info = ka.status()
            except Exception:  # noqa: BLE001
                info = {}
            for d in distros:
                d["auto_revive"] = bool(
                    info.get("enabled")
                    and not d["name"].lower().startswith("docker-desktop")
                    and d["name"] not in (info.get("stopped_by_user") or []))
        return distros

    def events(self, limit: int = 50) -> dict[str, Any]:
        return {"ok": True, "events": self.metrics.list_events(limit=limit)}

    def alerts(self) -> dict[str, Any]:
        return {"ok": True, "alerts": self.metrics.list_alerts(limit=50)}

    def health(self) -> dict[str, Any]:
        from wsl_port.vendor.port_forwarder.providers.ssh_tunnel_provider import SshTunnelProvider

        store = self.supervisor.store
        ssh = SshTunnelProvider(ssh_exe=store.cfg.windows.ssh_exe or None,
                                autossh_exe=store.cfg.windows.autossh_exe or None)
        data: dict[str, Any] = {"forwards": [], "tunnels": [], "vps": []}
        for f in store.cfg.forwards:
            ok = self.supervisor.netsh.test_connection(f.listen_port, 2.0)
            data["forwards"].append({"id": f.id, "listen_port": f.listen_port,
                                     "reachable": ok})
        for t in store.cfg.tunnels:
            alive = self.supervisor.ssh.is_alive(t)
            data["tunnels"].append({"id": t.id, "alive": alive})
            vps = store.get_vps(t.vps_id)
            if vps:
                data["vps"].append({"id": vps.id, "host": vps.host,
                                    "latency_ms": ssh.latency(t, vps)})
        return {"ok": True, "health": data}

    def vps_list(self) -> dict[str, Any]:
        return {
            "ok": True,
            "vps": [
                {"id": v.id, "host": v.host, "user": v.user, "port": v.port}
                for v in self.supervisor.store.cfg.vps_list
            ],
        }

    def distros_list(self) -> dict[str, Any]:
        """Lista distros WSL via wsl.exe -l -v (timeout corto, no cuelga)."""
        distros = self._get_wsl_distros()
        ka = getattr(self.supervisor, "keepalive", None)
        info = ka.status() if ka is not None else {}
        for d in distros:
            d["auto_revive"] = bool(
                info.get("enabled")
                and not d["name"].lower().startswith("docker-desktop")
                and d["name"] not in (info.get("stopped_by_user") or []))
        return {"ok": True, "distros": distros, "keepalive": info}

    def keepalive_status(self) -> dict[str, Any]:
        ka = getattr(self.supervisor, "keepalive", None)
        if ka is None:
            return {"ok": False, "error": "keepalive no disponible"}
        return {"ok": True, "keepalive": ka.status()}

    MCP_TUNNEL_ID = "mcp-to-vps"

    def _sync_mcp_export(self) -> dict[str, Any]:
        """Mantiene el tunel mcp-to-vps sincronizado con cfg.mcp.

        Con export activado: el tunel debe apuntar EXACTAMENTE
        127.0.0.1:<puerto MCP> -> <vps destino>:<puerto VPS>; si algo cambio
        (puerto, VPS, destino) se detiene el proceso ssh viejo, se reemplaza
        la config y se arranca. Con export desactivado: se detiene y elimina.
        Idempotente: si ya esta igual y vivo, no hace nada.
        """
        store = self.supervisor.store
        cfg = store.cfg.mcp
        try:
            existing = store.get_tunnel(self.MCP_TUNNEL_ID)
            if not (cfg.vps_export_enabled and cfg.vps_target_host):
                if existing is not None:
                    try:
                        self.supervisor.ssh.stop(existing)
                    except Exception:  # noqa: BLE001
                        pass
                    store.cfg.tunnels = [
                        t for t in store.cfg.tunnels
                        if t.id != self.MCP_TUNNEL_ID]
                    store.save()
                    self.metrics.record_event("web_mcp_export_off")
                return {"ok": True, "message": "Configuración MCP aplicada",
                        "tunnel": ("eliminado" if existing
                                   else "sin export")}
            vps = store.get_vps(cfg.vps_target_host)
            if not vps:
                return {"ok": False,
                        "error": f"VPS '{cfg.vps_target_host}' no existe"}
            changed = (existing is None
                       or existing.vps_id != cfg.vps_target_host
                       or existing.local_bind.port != cfg.port
                       or [b.port for b in existing.remote_binds]
                       != [cfg.vps_target_port])
            if existing is not None and changed:
                try:
                    self.supervisor.ssh.stop(existing)
                except Exception:  # noqa: BLE001
                    pass
                store.cfg.tunnels = [t for t in store.cfg.tunnels
                                     if t.id != self.MCP_TUNNEL_ID]
            tun = Tunnel(
                id=self.MCP_TUNNEL_ID, type="ssh", enabled=True,
                vps_id=cfg.vps_target_host,
                local_bind=Bind(host="127.0.0.1", port=cfg.port),
                remote_binds=[Bind(host="0.0.0.0", port=cfg.vps_target_port)],
                auto_start=True, health_gate=TunnelHealthGate(enabled=True),
            )
            if existing is None or changed:
                store.cfg.tunnels.append(tun)
                store.save()
            warning = ""
            if changed or not self.supervisor.ssh.is_alive(tun):
                try:
                    self.supervisor.ssh.start(tun, vps)
                    if changed:
                        self.metrics.record_event(
                            "web_mcp_export_apply", vps=vps.id,
                            local_port=cfg.port,
                            remote_port=cfg.vps_target_port)
                except Exception as e:  # el supervisor reintenta solo
                    warning = f"tunnel no arranco: {e}"
            r: dict[str, Any] = {"ok": True,
                                 "message": "Configuración MCP aplicada",
                                 "tunnel": self.MCP_TUNNEL_ID,
                                 "local": f"127.0.0.1:{cfg.port}",
                                 "public": f"{vps.host}:{cfg.vps_target_port}"}
            if warning:
                r["warning"] = warning
            return r
        except Exception as e:  # noqa: BLE001
            return {"ok": False,
                    "error": f"Error aplicando configuración MCP: {str(e)}"}

    def tunnel_log(self, tunnel_id: str) -> dict[str, Any]:
        """Tail del log ssh/autossh del tunnel (diagnostico de fallos)."""
        store = self.supervisor.store
        if store.get_tunnel(tunnel_id) is None:
            return {"ok": False, "error": f"tunnel '{tunnel_id}' no existe"}
        logf = self.supervisor.ssh._logfile(tunnel_id)
        tail = self.supervisor.ssh.read_log_tail(tunnel_id, max_bytes=16384)
        return {
            "ok": True,
            "tunnel_id": tunnel_id,
            "path": str(logf),
            "log": tail[-16000:],
        }

    def tunnel_diag(self, tunnel_id: str) -> dict[str, Any]:
        """Razon por la que el tunnel no esta arriba + estado actual."""
        store = self.supervisor.store
        tun = store.get_tunnel(tunnel_id)
        if tun is None:
            return {"ok": False, "error": f"tunnel '{tunnel_id}' no existe"}
        alive = self.supervisor.ssh.is_alive(tun)
        reason = None
        if not alive:
            reason = self.supervisor.tunnel_reason.get(tunnel_id) or \
                self.supervisor.ssh.failure_reason(tun)
        vps = store.get_vps(tun.vps_id)
        return {
            "ok": True,
            "tunnel_id": tunnel_id,
            "alive": alive,
            "state": self.supervisor.tunnel_state.get(tunnel_id),
            "reason": reason,
            "vps_exists": vps is not None,
            "vps": ({"host": vps.host, "user": vps.user, "port": vps.port}
                    if vps else None),
            "local": tun.ssh_dest,
            "gate_ok": self.supervisor.ssh._gate_ok(tun),
        }

    @staticmethod
    def _decode_wsl(data: bytes) -> str:
        """Decodifica salida de wsl.exe (UTF-16-LE con/sin BOM)."""
        if not data:
            return ""
        if data.startswith(b"\xff\xfe") or data.startswith(b"\xfe\xff"):
            try:
                return data.decode("utf-16")
            except (UnicodeDecodeError, UnicodeError):
                pass
        try:
            s = data.decode("utf-8")
            if "\x00" in s:
                return data.decode("utf-16-le", errors="replace")
            return s
        except UnicodeDecodeError:
            return data.decode("utf-16-le", errors="replace")

    # -- acciones -------------------------------------------------------------------

    def action(self, path: str, body: dict[str, Any] | None = None) -> dict[str, Any]:
        """Ejecuta una accion POST; registra en SQLite (journal, 13.2)."""
        body = body or {}
        store = self.supervisor.store
        parts = [p for p in path.split("/") if p]
        if parts[:3] == ["api", "v1", "forwards"]:
            if len(parts) == 3 or parts[3] == "apply":
                self.supervisor.run_once()
                return {"ok": True, "message": "forwards reaplicados"}
            if parts[3] == "clear":
                results = self.supervisor.netsh.clear_all()
                failed = [r for r in results if not r.ok]
                return {"ok": not failed,
                        "message": "forwards limpiados" if not failed
                        else "hubo fallos al limpiar"}
            if parts[3] == "add":
                fwd = Forward(
                    id=str(body.get("id", "")).strip(),
                    listen_port=int(body.get("listen_port") or 0),
                    wsl_distro=str(body.get("distro", "")).strip(),
                    wsl_port=int(body.get("wsl_port") or 0),
                    protocol=str(body.get("protocol", "tcp")),
                    auto_apply=bool(body.get("auto_apply", True)),
                    health_check=HealthCheck(enabled=bool(body.get("health_check", True))),
                )
                if not fwd.id or fwd.listen_port <= 0 or fwd.wsl_port <= 0:
                    return {"ok": False, "error": "id, listen_port y wsl_port son obligatorios"}
                try:
                    from wsl_port import core as _core
                    conflict = _core._wsl_port_conflict(fwd.wsl_port, fwd.wsl_distro)
                except Exception:  # noqa: BLE001 - el guard nunca debe romper
                    conflict = None
                if conflict:
                    return {"ok": False, "error": conflict}
                store.add_forward(fwd)
                self.metrics.record_event("web_forward_add", forward_id=fwd.id)
                return {"ok": True, "message": f"forward '{fwd.id}' creado"}
            if parts[3] == "remove" and len(parts) == 5:
                store.remove_forward(parts[4])
                self.metrics.record_event("web_forward_remove", forward_id=parts[4])
                return {"ok": True, "message": f"forward '{parts[4]}' eliminado"}
        if parts[:3] == ["api", "v1", "tunnels"]:
            if len(parts) == 4 and parts[3] == "add":
                remotes = body.get("remotes") or body.get("remote") or []
                if isinstance(remotes, str):
                    remotes = [r.strip() for r in remotes.split(",") if r.strip()]
                if not isinstance(remotes, list) or not remotes:
                    return {"ok": False, "error": "remotes requerido (lista host:puerto)"}
                tun = Tunnel(
                    id=str(body.get("id", "")).strip(),
                    type=str(body.get("type", "ssh")).strip() or "ssh",
                    enabled=bool(body.get("enabled", True)),
                    vps_id=str(body.get("vps_id", "")).strip(),
                    local_bind=self._parse_bind(body.get("local"), "local"),
                    remote_binds=[self._parse_bind(r, "remote") for r in remotes],
                    auto_start=bool(body.get("auto_start", True)),
                    keepalive_interval=int(body.get("keepalive_interval") or 30),
                    keepalive_count=int(body.get("keepalive_count") or 3),
                    health_gate=TunnelHealthGate(enabled=bool(body.get("health_gate", True))),
                )
                if not tun.id or not tun.vps_id:
                    return {"ok": False, "error": "id y vps_id son obligatorios"}
                if store.get_vps(tun.vps_id) is None:
                    return {"ok": False, "error": f"vps '{tun.vps_id}' no existe"}
                store.add_tunnel(tun)
                self.metrics.record_event("web_tunnel_add", tunnel_id=tun.id)
                if tun.auto_start:
                    try:
                        self.supervisor.ssh.start(tun, store.get_vps(tun.vps_id))
                    except Exception as e:  # noqa: BLE001
                        return {"ok": True, "warning": str(e),
                                "message": f"tunnel '{tun.id}' creado pero no arranco"}
                return {"ok": True, "message": f"tunnel '{tun.id}' creado"}
            if len(parts) == 5 and parts[4] == "remove":
                tun = store.get_tunnel(parts[3])
                if tun is None:
                    return {"ok": False, "error": f"tunnel '{parts[3]}' no existe"}
                try:
                    self.supervisor.ssh.stop(tun)
                except Exception:  # noqa: BLE001
                    pass
                store.remove_tunnel(parts[3])
                self.metrics.record_event("web_tunnel_remove", tunnel_id=parts[3])
                return {"ok": True, "message": f"tunnel '{parts[3]}' eliminado"}
            if len(parts) == 5:
                tun_id, op = parts[3], parts[4]
                tun = store.get_tunnel(tun_id)
                if not tun:
                    return {"ok": False, "error": f"tunnel '{tun_id}' no existe"}
                vps = store.get_vps(tun.vps_id)
                def _set_manual_stop(val):
                    if bool(getattr(tun, "manual_stop", False)) != val:
                        tun.manual_stop = val
                        try:
                            store.save()
                        except Exception:  # noqa: BLE001
                            pass
                if op == "start":
                    if not self.supervisor.ssh.is_alive(tun):
                        self.supervisor.ssh.start(tun, vps)
                    _set_manual_stop(False)
                    return {"ok": True, "message": f"{tun_id} iniciado"}
                if op == "stop":
                    self.supervisor.ssh.stop(tun)
                    _set_manual_stop(True)
                    return {"ok": True, "message": f"{tun_id} detenido"}
                if op == "restart":
                    _set_manual_stop(False)
                    self.supervisor.ssh.restart(tun, vps)
                    return {"ok": True, "message": f"{tun_id} reiniciado"}
                if op == "update":
                    allowed = ("vps_id", "auto_start", "enabled")
                    changes = {}
                    for key in allowed:
                        if key in body:
                            changes[key] = body[key]
                    if "local" in body:
                        lb = self._parse_bind(body["local"], "local")
                        changes["local_bind"] = lb
                    if "remote" in body:
                        remotes = body["remote"]
                        if isinstance(remotes, str):
                            remotes = [r.strip() for r in remotes.split(",") if r.strip()]
                        changes["remote_binds"] = [self._parse_bind(r, "remote") for r in remotes]
                    if changes:
                        store.update_tunnel(tun_id, **changes)
                        # Reactivar el tunnel implica quitar el stop manual
                        if changes.get("enabled") is True or changes.get("auto_start") is True:
                            t2 = store.get_tunnel(tun_id)
                            if t2 is not None and getattr(t2, "manual_stop", False):
                                t2.manual_stop = False
                                try:
                                    store.save()
                                except Exception:  # noqa: BLE001
                                    pass
                        self.metrics.record_event("web_tunnel_update", tunnel_id=tun_id)
                    return {"ok": True, "message": f"{tun_id} actualizado"}
                if op == "edit":
                    try:
                        vps_id = str(body.get("vps_id", tun.vps_id)).strip()
                        local = body.get("local", "")
                        remote_list = body.get("remote") or body.get("remotes") or []
                        if isinstance(remote_list, str):
                            remote_list = [r.strip() for r in remote_list.split(",") if r.strip()]
                        auto_start = bool(body.get("auto_start", tun.auto_start))
                        enabled = bool(body.get("enabled", tun.enabled))
                        health_gate_enabled = bool(body.get("health_gate", tun.health_gate.enabled))
                        keepalive_interval = int(body.get("keepalive_interval") or tun.keepalive_interval)
                        keepalive_count = int(body.get("keepalive_count") or tun.keepalive_count)
                        tun_type = str(body.get("type", tun.type)).strip() or tun.type

                        vps = store.get_vps(vps_id)
                        if not vps:
                            return {"ok": False, "error": f"vps '{vps_id}' no existe"}
                        lb = self._parse_bind(local, "local") if local else tun.local_bind
                        remote_binds = [self._parse_bind(r, "remote") for r in remote_list] if remote_list else tun.remote_binds
                        hg = TunnelHealthGate(enabled=health_gate_enabled)

                        tun.id = tun_id
                        tun.type = tun_type
                        tun.vps_id = vps_id
                        tun.local_bind = lb
                        tun.remote_binds = remote_binds
                        tun.auto_start = auto_start
                        tun.enabled = enabled
                        tun.keepalive_interval = keepalive_interval
                        tun.keepalive_count = keepalive_count
                        tun.health_gate = hg
                        store.save()
                        self.metrics.record_event("web_tunnel_edit", tunnel_id=tun_id)
                    except Exception as e:
                        return {"ok": False, "error": str(e)}
                    return {"ok": True, "message": f"{tun_id} editado"}
        if parts[:3] == ["api", "v1", "vps"]:
            if len(parts) == 4 and parts[3] == "add":
                vps = Vps(
                    id=str(body.get("id", "")).strip(),
                    host=str(body.get("host", "")).strip(),
                    user=str(body.get("user", "")).strip(),
                    port=int(body.get("port") or 22),
                    identity_file=str(body.get("identity_file", "")).strip(),
                    password=str(body.get("password", "")),
                )
                if not vps.id or not vps.host or not vps.user:
                    return {"ok": False, "error": "id, host y user son obligatorios"}
                store.add_vps(vps)
                self.metrics.record_event("web_vps_add", vps=vps.id)
                return {"ok": True, "message": f"vps '{vps.id}' registrado"}
            if len(parts) == 5 and parts[3] == "remove":
                store.remove_vps(parts[4])
                self.metrics.record_event("web_vps_remove", vps=parts[4])
                return {"ok": True, "message": f"vps '{parts[4]}' eliminado"}
            if len(parts) == 5 and parts[3] == "edit":
                try:
                    vps_id = parts[4]
                    vps = store.get_vps(vps_id)
                    if not vps:
                        return {"ok": False, "error": f"vps '{vps_id}' no existe"}
                    host = str(body.get("host", vps.host)).strip()
                    user = str(body.get("user", vps.user)).strip()
                    port = int(body.get("port") or vps.port)
                    identity_file = str(body.get("identity_file", vps.identity_file)).strip()
                    password = body.get("password", "")
                    vps.id = vps_id
                    vps.host = host
                    vps.user = user
                    vps.port = port
                    vps.identity_file = identity_file
                    vps.password = password
                    store.save()
                    self.metrics.record_event("web_vps_edit", vps=vps_id)
                except Exception as e:
                    return {"ok": False, "error": str(e)}
                return {"ok": True, "message": f"vps '{vps_id}' editado"}
        # Distros WSL: start/stop/restart/delete/export/import
        if parts[:3] == ["api", "v1", "distro"]:
            if len(parts) == 4 and parts[3] == "available":
                import subprocess
                try:
                    proc = subprocess.run(
                        ['wsl.exe', '--list', '--online'],
                        capture_output=True, timeout=30,
                        creationflags=0x08000000
                    )
                    output = proc.stdout.decode('utf-16-le', errors='replace').strip()
                    lines = []
                    for l in output.splitlines():
                        l = l.strip()
                        if not l or l.startswith('NAME') or l.startswith('Instalar') or l.startswith('A continu') or l.startswith('-'):
                            continue
                        # Extract the distro name (first token before spaces)
                        parts = l.split()
                        if parts:
                            name = parts[0]
                            if '.' not in name and name not in ('NAME', 'FRIENDLY', 'LISTA'):
                                lines.append(name)
                    if not lines:
                        lines = ['Ubuntu', 'Debian', 'kali-linux', 'openSUSE-42', 'Ubuntu-20.04', 'Ubuntu-22.04', 'Ubuntu-24.04']
                    return {'ok': True, 'distros': lines}
                except Exception as e:
                    return {'ok': True, 'distros': ['Ubuntu', 'Debian', 'kali-linux', 'openSUSE-42', 'Ubuntu-20.04', 'Ubuntu-22.04', 'Ubuntu-24.04']}
            if len(parts) == 4 and parts[3] == "create":
                name = str(body.get("name") or "").strip()
                if not name:
                    return {"ok": False, "error": "name es obligatorio"}
                self.metrics.record_event("web_distro_create", distro=name)
                return self._distro_create(name)
            if len(parts) == 5 and parts[4] == "metrics":
                return self._distro_metrics(parts[3])
            if len(parts) == 5 and parts[4] in ("start", "stop", "restart", "delete"):
                name, op = parts[3], parts[4]
                self.metrics.record_event("web_distro_" + op, distro=name)
                return self._distro_action(name, op)
            if len(parts) == 5 and parts[4] == "keepalive":
                name = parts[3]
                ka = getattr(self.supervisor, "keepalive", None)
                if ka is None:
                    return {"ok": False, "error": "keepalive no disponible"}
                if bool(body.get("exempt")):
                    ka.mark_user_stop(name)
                    ka.kill_holder(name)
                    self.metrics.record_event("web_keepalive_exempt",
                                              distro=name, on=True)
                else:
                    ka.protect(name)
                    self.metrics.record_event("web_keepalive_exempt",
                                              distro=name, on=False)
                return {"ok": True, "keepalive": ka.status()}
            if len(parts) == 4 and parts[3] == "start-all":
                from wsl_port import core
                self.metrics.record_event("web_distro_start_all")
                return core.start_all()
            if len(parts) == 4 and parts[3] == "shutdown-all":
                from wsl_port import core
                self.metrics.record_event("web_distro_shutdown_all")
                return core.shutdown_all()
        # Publish / Unpublish
        if parts[:3] == ["api", "v1", "publish"]:
            distro = str(body.get("distro") or "").strip()
            wsl_port = int(body.get("wsl_port") or 0)
            vps_id = str(body.get("vps_id") or "").strip()
            public_port = int(body.get("public_port") or 0)
            if not distro or not wsl_port or not vps_id or not public_port:
                return {"ok": False, "error": "distro, wsl_port, vps_id y public_port son obligatorios"}
            tunnel_name = str(body.get("tunnel_name") or "").strip()
            return self._do_publish(distro, wsl_port, vps_id, public_port, tunnel_name=tunnel_name)
        if parts[:3] == ["api", "v1", "unpublish"] and len(parts) == 4:
            return self._do_unpublish(parts[3])
        if parts[:3] == ["api", "v1", "mcp"]:
            if len(parts) == 4 and parts[3] == "settings":
                # Guardar la configuración MCP (solo POST)
                try:
                    import secrets as _secrets
                    from wsl_port.vendor.port_forwarder.core.config import Mcp
                    generated_token = False
                    token_in = str(body.get("token", ""))
                    vps_export_enabled = bool(body.get("vps_export_enabled", False))
                    token_required = bool(body.get("token_required", True))
                    # H2: si el MCP se exporta a un VPS (exposición pública),
                    # exigir token obligatorio y generarlo si está vacío.
                    if vps_export_enabled:
                        token_required = True
                        if not token_in.strip():
                            token_in = _secrets.token_urlsafe(32)
                            generated_token = True
                    new_cfg = Mcp(
                        enabled=bool(body.get("enabled", False)),
                        transport=str(body.get("transport", "stdio")),
                        port=int(body.get("port", 8796)),
                        token_required=token_required,
                        token=str(token_in).strip(),
                        expose_exec=bool(body.get("expose_exec", True)),
                        vps_export_enabled=vps_export_enabled,
                        vps_target_port=int(body.get("vps_target_port", 55872)),
                        vps_target_host=str(body.get("vps_target_host", ""))
                    )
                    
                    # Validar que el VPS seleccionado exista si la exportación está habilitada
                    if new_cfg.vps_export_enabled and new_cfg.vps_target_host:
                        target_vps = store.get_vps(new_cfg.vps_target_host)
                        if not target_vps:
                            return {"ok": False, "error": f"VPS '{new_cfg.vps_target_host}' no existe"}
                    
                    # Actualizar la configuración
                    store.cfg.mcp = new_cfg
                    store.save()
                    # arrancar/parar el servidor MCP HTTP al instante
                    try:
                        self.supervisor._sync_mcp_http()
                    except Exception as e:  # noqa: BLE001
                        log.warning("sync mcp http tras guardado fallo: %s", e)
                    # y mantener el tunel mcp-to-vps coherente con la config
                    exp = self._sync_mcp_export()
                    if generated_token:
                        return {"ok": True, "message": "Configuración MCP guardada",
                                "token": new_cfg.token,
                                "export": exp,
                                "warning": "Token MCP autogenerado (exposición al VPS exige token)"}
                    return {"ok": True, "message": "Configuración MCP guardada",
                            "export": exp}
                except Exception as e:
                    return {"ok": False, "error": f"Error guardando configuración MCP: {str(e)}"}
            if len(parts) == 4 and parts[3] == "apply":
                result = self._sync_mcp_export()
                try:
                    self.supervisor._sync_mcp_http()
                except Exception as e:  # noqa: BLE001
                    log.warning("sync mcp http tras apply fallo: %s", e)
                result["mcp_http_running"] = bool(
                    getattr(self.supervisor, "_mcp_http", None)
                    and self.supervisor._mcp_http.running)
                return result
        if parts[:3] == ["api", "v1", "keepalive"]:
            ka = getattr(self.supervisor, "keepalive", None)
            if ka is None:
                return {"ok": False, "error": "keepalive no disponible"}
            enabled = bool(body.get("enabled", True))
            store.cfg.keepalive.enabled = enabled
            store.save()
            self.metrics.record_event("web_keepalive_toggle", enabled=enabled)
            if enabled:
                ka.kick()
            else:
                ka.release_all()
            return {"ok": True, "keepalive": ka.status()}
        if parts[:3] == ["api", "v1", "maintenance"]:
            if len(parts) == 4 and parts[3] == "on":
                store.cfg.maintenance.active = True
                store.save()
                return {"ok": True, "message": "Modo mantenimiento activado"}
            if len(parts) == 4 and parts[3] == "off":
                store.cfg.maintenance.active = False
                store.save()
                return {"ok": True, "message": "Modo mantenimiento desactivado"}
            if len(parts) == 4 and parts[3] == "status":
                return {"ok": True, "active": store.cfg.maintenance.active}
        return {"ok": False, "error": f"accion desconocida: {path}"}

    def _distro_action(self, name: str, op: str) -> dict[str, Any]:
        """Ejecuta wsl.exe start/stop/restart/delete sobre una distro."""
        import subprocess

        def _run(cmd: list[str], timeout: float = 20) -> tuple[int, str]:
            try:
                p = subprocess.run(cmd, capture_output=True, timeout=timeout,
                                   creationflags=0x08000000)
                err = (p.stderr or p.stdout or b"").decode("utf-8", "replace").strip()
                return p.returncode, err
            except subprocess.TimeoutExpired:
                return -1, f"timeout tras {timeout}s"

        verbs = {"start": "iniciada", "stop": "detenida", "restart": "reiniciada", "delete": "eliminada"}
        ka = getattr(self.supervisor, "keepalive", None)
        try:
            if op == "start":
                if ka is not None:
                    ka.mark_user_start(name)  # boton tacito: volver a proteger
                rc, err = _run(["wsl.exe", "-d", name, "--", "true"])
            elif op == "stop":
                # PARADA TACITA POR BOTON: unicas excepciones que el
                # watchdog keepalive respeta (no revive las paradas aqui).
                if ka is not None:
                    ka.mark_user_stop(name)
                    ka.kill_holder(name)
                rc, err = _run(["wsl.exe", "--terminate", name], timeout=15)
                if rc != 0 and ka is not None:
                    ka.mark_user_start(name)  # no se detuvo: sigue protegida
            elif op == "restart":
                if ka is not None:
                    ka.mark_user_start(name)
                    ka.kill_holder(name)
                _run(["wsl.exe", "--terminate", name], timeout=15)
                rc, err = _run(["wsl.exe", "-d", name, "--", "true"])
            elif op == "delete":
                rc, err = _run(["wsl.exe", "--unregister", name], timeout=60)
                if rc == 0:
                    if ka is not None:
                        ka.kill_holder(name)
                        ka.mark_user_start(name)  # limpiar exclusiones
                    self.metrics.record_event("web_distro_delete", distro=name)
                    return {"ok": True, "message": f"distro '{name}' eliminada"}
            else:
                return {"ok": False, "error": f"operacion desconocida: {op}"}
            if rc != 0:
                return {"ok": False, "error": f"fallo al {op} '{name}': {err or 'error'}"}
            return {"ok": True, "message": f"distro '{name}' {verbs.get(op, op)}"}
        except Exception as e:
            return {"ok": False, "error": str(e)}

    def _distro_create(self, name: str) -> dict[str, Any]:
        """Instala una distro WSL desde el catalogo."""
        import subprocess
        try:
            proc = subprocess.run(
                ["wsl.exe", "--install", "-d", name],
                capture_output=True, timeout=300,
                creationflags=0x08000000
            )
            if proc.returncode == 0:
                self.metrics.record_event("web_distro_create", distro=name)
                return {"ok": True, "message": f"distro '{name}' instalada"}
            err = proc.stderr.decode("utf-8", "replace").strip()
            return {"ok": False, "error": f"fallo al instalar '{name}': {err or 'error'}"}
        except subprocess.TimeoutExpired:
            return {"ok": False, "error": f"timeout al instalar '{name}' (5 min)"}
        except Exception as e:
            return {"ok": False, "error": str(e)}

    def _distro_metrics(self, name: str) -> dict[str, Any]:
        """Obtiene metricas de una distro WSL."""
        try:
            import subprocess
            proc = subprocess.run(
                ["wsl.exe", "-d", name, "--", "cat", "/proc/meminfo"],
                capture_output=True, timeout=5, creationflags=0x08000000
            )
            if proc.returncode != 0:
                return {"ok": False, "error": "distro no disponible"}
            lines = proc.stdout.decode("utf-8", errors="replace").splitlines()
            mem = {}
            for line in lines:
                if ":" in line:
                    k, v = line.split(":", 1)
                    mem[k.strip()] = v.strip()
            total_kb = int(mem.get("MemTotal", "0").split()[0])
            avail_kb = int(mem.get("MemAvailable", "0").split()[0])
            used_kb = total_kb - avail_kb
            return {
                "ok": True, "name": name,
                "ram_total_mb": total_kb // 1024,
                "ram_used_mb": used_kb // 1024,
                "ram_percent": round(used_kb / total_kb * 100, 1) if total_kb else 0,
            }
        except Exception as e:
            return {"ok": False, "error": str(e)}
    def _do_publish(self, distro: str, wsl_port: int, vps_id: str, public_port: int, tunnel_name: str = '') -> dict[str, Any]:
        """Publica un servicio WSL en Internet via VPS (1 clic)."""
        try:
            from wsl_port.vendor.wsl_manager.utils.subprocess_async import run as wsl_run
            r = wsl_run(["wsl.exe", "-d", distro, "hostname", "-I"], timeout=5, breaker=False)
            if not r.ok:
                return {"ok": False, "error": "WSL no responde"}
            ip = r.output.strip().split()[0] if r.output.strip() else None
            if ip and ip.startswith("169.254"):
                return {"ok": False, "error": "IP de distro no disponible"}
            store = self.supervisor.store
            vps = store.get_vps(vps_id)
            if not vps:
                return {"ok": False, "error": f"VPS '{vps_id}' no existe"}
            try:
                from wsl_port import core as _core
                conflict = _core._wsl_port_conflict(wsl_port, distro)
            except Exception:  # noqa: BLE001 - el guard nunca debe romper
                conflict = None
            if conflict:
                return {"ok": False, "error": conflict}
            tid = tunnel_name.strip() if tunnel_name and tunnel_name.strip() else f"pub-{distro.lower().replace(' ', '-')}-{wsl_port}"
            existing = store.get_tunnel(tid)
            if not existing:
                tun = Tunnel(
                    id=tid, type="ssh", enabled=True, vps_id=vps_id,
                    local_bind=Bind(host="127.0.0.1", port=wsl_port),
                    remote_binds=[Bind(host="0.0.0.0", port=public_port)],
                    auto_start=True, health_gate=TunnelHealthGate(enabled=True),
                )
                store.add_tunnel(tun)
                self.metrics.record_event("web_publish", distro=distro, tunnel_id=tid)
            self.supervisor.ssh.start(tun, vps)
            return {
                "ok": True, "tunnel_id": tid,
                "local": f"127.0.0.1:{wsl_port}",
                "public_url": f"http://{vps.host}:{public_port}",
                "vps_id": vps_id,
            }
        except Exception as e:
            return {"ok": False, "error": str(e)}

    def _do_unpublish(self, tunnel_id: str) -> dict[str, Any]:
        """Detiene y elimina un tunnel publicado."""
        try:
            store = self.supervisor.store
            tun = store.get_tunnel(tunnel_id)
            if tun:
                self.supervisor.ssh.stop(tun)
            store.remove_tunnel(tunnel_id)
            self.metrics.record_event("web_unpublish", tunnel_id=tunnel_id)
            return {"ok": True, "message": f"tunnel '{tunnel_id}' eliminado"}
        except Exception as e:
            return {"ok": False, "error": str(e)}


def start_panel(
    supervisor: Supervisor,
    port: int = DEFAULT_PORT,
    bind: str = DEFAULT_BIND,
    token: str = "",
) -> WebPanel:
    """Helper: construye y arranca el panel."""
    panel = WebPanel(supervisor, port=port, bind=bind, token=token)
    panel.start()
    return panel


DASHBOARD_HTML = r"""<!DOCTYPE html>
<html lang="es">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>wsl-port — WSL + Port Forwarding</title>
<style>
  :root { --bg:#0f1419; --card:#1a2130; --card2:#1e2738; --line:#2d3748; --text:#e6edf3; --muted:#8b95a5; --accent:#00d4ff; --ok:#00c853; --warn:#ff9100; --err:#ff1744; --info:#2196f3; }
  * { box-sizing:border-box; }
  body { margin:0; font-family:'Segoe UI',system-ui,sans-serif; background:var(--bg); color:var(--text); min-height:100vh; display:flex; flex-direction:column; }
  .header { display:flex; align-items:center; padding:12px 20px; gap:12px; border-bottom:1px solid var(--line); background:linear-gradient(180deg,#161d27 0%,var(--bg) 100%); }
  .header h1 { font-size:18px; margin:0; color:var(--accent); font-weight:600; letter-spacing:-.02em; }
  .header .sub { color:var(--muted); font-size:12px; }
  .header .status { margin-left:auto; color:var(--muted); font-size:11px; display:flex; align-items:center; gap:8px; }
  .ws-status { display:inline-block; width:8px; height:8px; border-radius:50%; }
  .ws-on { background:var(--ok); box-shadow:0 0 6px var(--ok); }
  .ws-off { background:var(--err); }
  .tabs { display:flex; gap:2px; padding:8px 12px 0; background:var(--bg); border-bottom:1px solid var(--line); }
  .tab { padding:8px 16px; border:0; background:transparent; color:var(--muted); cursor:pointer; font-size:13px; border-radius:6px 6px 0 0; transition:all .15s; }
  .tab.active { background:var(--card); color:var(--accent); border:1px solid var(--line); border-bottom:1px solid var(--card); margin-bottom:-1px; font-weight:500; }
  .tab:hover { color:var(--text); background:var(--card2); }
  .tab-content { display:none; padding:14px; flex:1; overflow-y:auto; }
  .tab-content.active { display:block; }
  .card { background:var(--card); border:1px solid var(--line); border-radius:10px; padding:14px; margin-bottom:14px; box-shadow:0 2px 8px rgba(0,0,0,.2); }
  .card h2 { font-size:12px; margin:0 0 10px; color:var(--muted); text-transform:uppercase; letter-spacing:.08em; font-weight:600; }
  table { width:100%; border-collapse:collapse; font-size:13px; }
  th,td { text-align:left; padding:7px 10px; border-bottom:1px solid var(--line); }
  th { color:var(--muted); font-weight:600; font-size:11px; text-transform:uppercase; letter-spacing:.05em; }
  tr:hover { background:rgba(255,255,255,.03); }
  .badge { display:inline-block; padding:2px 8px; border-radius:20px; font-size:11px; font-weight:500; }
  .badge-ok { background:rgba(0,200,83,.15); color:var(--ok); }
  .badge-warn { background:rgba(255,145,0,.15); color:var(--warn); }
  .badge-err { background:rgba(255,23,68,.15); color:var(--err); }
  .badge-info { background:rgba(33,150,243,.15); color:var(--info); }
  .badge-running { background:rgba(0,200,83,.15); color:var(--ok); }
  .badge-stopped { background:rgba(255,23,68,.15); color:var(--err); }
  .ka-chip { cursor:pointer; padding:2px 10px; border-radius:20px; font-size:11px; font-weight:600; user-select:none; }
  .ka-chip.on { background:rgba(0,200,83,.15); color:var(--ok); }
  .ka-chip.off { background:rgba(158,158,158,.18); color:#9e9e9e; }
  .muted { color:var(--muted); }
  .accent { color:var(--accent); }
  .text-sm { font-size:12px; }
  button { background:#2563eb; border:0; color:#fff; padding:6px 12px; border-radius:6px; cursor:pointer; font-size:12px; font-weight:500; transition:all .15s; }
  button:hover { filter:brightness(1.2); transform:translateY(-1px); }
  button:active { transform:translateY(0); }
  button:disabled { opacity:.5; cursor:not-allowed; transform:none; }
  button.danger { background:var(--err); }
  button.success { background:var(--ok); }
  button.warn { background:var(--warn); color:#000; }
  button.outline { background:transparent; border:1px solid var(--line); color:var(--text); }
  button.outline:hover { background:var(--card2); }
  input, select { padding:6px 10px; border-radius:6px; border:1px solid var(--line); background:var(--bg); color:var(--text); font-size:12px; }
  input:focus, select:focus { outline:none; border-color:var(--accent); box-shadow:0 0 0 2px rgba(0,212,255,.15); }
  .pw-wrap { position:relative; display:inline-flex; align-items:center; }
  .pw-wrap > input { padding-right:32px; }
  .dialog .pw-wrap { width:100%; }
  .dialog .pw-wrap > input { flex:1; }
  .pw-eye { position:absolute; right:4px; background:transparent !important; border:0; color:var(--muted); padding:2px; display:flex; align-items:center; cursor:pointer; width:auto; line-height:0; }
  .pw-eye:hover { color:var(--accent); filter:none; transform:none; }
  .pw-eye svg { width:16px; height:16px; }
  .form { display:flex; gap:8px; flex-wrap:wrap; margin-top:8px; align-items:center; }
  .form label { color:var(--muted); font-size:12px; font-weight:500; }
  .toolbar { display:flex; gap:6px; flex-wrap:wrap; margin-bottom:10px; }
  .separator { height:1px; background:var(--line); margin:12px 0; }
  #activity { text-align:center; padding:8px; font-size:13px; font-weight:600; min-height:24px; border-radius:6px; margin-bottom:8px; transition:opacity .3s; }
  #activity.info { color:var(--info); background:rgba(33,150,243,.1); }
  #activity.success { color:var(--ok); background:rgba(0,200,83,.1); }
  #activity.warning { color:var(--warn); background:rgba(255,145,0,.1); }
  #activity.error { color:var(--err); background:rgba(255,23,68,.1); }
  #activity:empty { display:none; }
  #statusbar { display:flex; justify-content:space-between; padding:8px 20px; font-size:11px; color:var(--muted); border-top:1px solid var(--line); background:var(--card); margin-top:auto; }
  #toast { position:fixed; bottom:20px; right:20px; background:var(--card); padding:8px 12px; border-radius:6px; font-size:11px; opacity:0; transition:opacity .3s,transform .3s; max-width:280px; box-shadow:0 4px 20px rgba(0,0,0,.4); border-left:3px solid var(--info); z-index:1000; transform:translateY(20px); }
  #toast.show { opacity:1; transform:translateY(0); }
  #toast.ok { border-left-color:var(--ok); }
  #toast.err { border-left-color:var(--err); }
  #toast.warn { border-left-color:var(--warn); }
  #events { font-family:ui-monospace,Consolas,monospace; font-size:11px; max-height:200px; overflow-y:auto; background:var(--bg); border-radius:6px; padding:8px; }
  #events div { padding:3px 0; border-bottom:1px dashed var(--line); }
  #events div:last-child { border-bottom:none; }
  tr.selected { background:rgba(0,212,255,.12) !important; }
  tr { cursor:pointer; transition:background .1s; }
  .dialog-overlay { position:fixed; inset:0; background:rgba(0,0,0,.6); display:flex; align-items:center; justify-content:center; z-index:500; }
  .dialog { background:var(--card); border:1px solid var(--line); border-radius:12px; padding:20px; min-width:320px; max-width:480px; box-shadow:0 8px 32px rgba(0,0,0,.5); }
  .dialog h3 { margin:0 0 12px; font-size:15px; color:var(--text); }
  .dialog .row { margin-bottom:10px; }
  .dialog .row label { display:block; font-size:12px; color:var(--muted); margin-bottom:4px; }
  .dialog .row input, .dialog .row select { width:100%; }
  .dialog .btns { display:flex; gap:8px; justify-content:flex-end; margin-top:16px; }
  .empty-state { text-align:center; padding:32px; color:var(--muted); font-size:13px; }
  .modal-overlay { position:fixed; inset:0; background:rgba(0,0,0,.65); display:flex; align-items:center; justify-content:center; z-index:600; }
  .modal { background:var(--card); border:1px solid var(--line); border-radius:12px; padding:20px; width:600px; max-width:94vw; max-height:92vh; overflow-y:auto; box-shadow:0 8px 32px rgba(0,0,0,.5); }
  .modal h3 { margin:0 0 14px; font-size:15px; color:var(--text); }
  .modal .grid { display:grid; grid-template-columns:160px 1fr; gap:8px 10px; align-items:center; font-size:12px; }
  .modal .grid>label { color:var(--muted); text-align:right; font-weight:500; }
  .modal .grid input, .modal .grid select { width:100%; }
  .modal .grid .span { grid-column:2; }
  .modal .rem-row { display:flex; gap:6px; margin-bottom:6px; }
  .modal .btns { display:flex; gap:8px; justify-content:flex-end; margin-top:16px; }
  #term-out { height:420px; overflow-y:auto; background:#0b0f14; color:#d4d4d4; font-family:ui-monospace,Consolas,monospace; font-size:12px; line-height:1.45; white-space:pre-wrap; word-break:break-all; margin:0; padding:8px; border-radius:6px; border:1px solid var(--line); }
  .tun-err { color:var(--err); font-size:11px; max-width:280px; white-space:normal; line-height:1.3; margin-top:2px; }
  .log-box { background:#0b0f14; border:1px solid var(--line); border-radius:6px; padding:8px; font-family:ui-monospace,Consolas,monospace; font-size:11px; color:#d4d4d4; max-height:300px; overflow-y:auto; white-space:pre-wrap; word-break:break-all; }
  .diag-reason { color:var(--err); font-size:13px; font-weight:600; margin:8px 0; line-height:1.4; }
  .diag-ok { color:var(--ok); font-size:13px; font-weight:600; margin:8px 0; }
  .metric-bar { height:6px; background:var(--line); border-radius:3px; overflow:hidden; margin-top:4px; }
  .metric-bar-fill { height:100%; background:linear-gradient(90deg,var(--ok),var(--warn)); border-radius:3px; transition:width .3s; }
  .metric-bar-fill.hot { background:linear-gradient(90deg,var(--warn),var(--err)); }
</style>
</head>
<body>
<div class="header">
  <h1>wsl-port</h1><span class="sub">WSL + Port Forwarding</span>
  <span class="status">
    <span id="header-status">cargando...</span>
    <span class="ws-status ws-off" id="ws-dot" title="WebSocket"></span>
    <button class="outline" data-cmd="logout" style="padding:3px 10px;font-size:11px;margin-left:8px;">Cerrar sesion</button>
  </span>
</div>
<div class="tabs">
  <button class="tab active" data-cmd="showTab:distros"> Distros WSL </button>
  <button class="tab" data-cmd="showTab:publicar"> Publicar en Internet </button>
  <button class="tab" data-cmd="showTab:terminal"> Terminal WSL </button>
  <button class="tab" data-cmd="showTab:vps"> VPS </button>
  <button class="tab" data-cmd="showTab:tunnels"> Tunnels SSH </button>
  <button class="tab" data-cmd="showTab:forwards"> Forwards </button>
  <button class="tab" data-cmd="showTab:logs"> Logs </button>
  <button class="tab" data-cmd="showTab:ajustes"> Ajustes </button>
</div>
<div id="tab-distros" class="tab-content active">
  <div id="activity"></div>
  <div class="toolbar">
    <button class="success" data-cmd="refresh">Refrescar</button>
    <button data-cmd="distroActionSel:start">Iniciar</button>
    <button class="warn" data-cmd="distroActionSel:stop">Detener</button>
    <button data-cmd="distroActionSel:restart">Reiniciar</button>
    <button class="success outline" data-cmd="startAllDistros">Encender todo</button>
    <button class="danger outline" data-cmd="shutdownAllDistros">Apagar todo WSL</button>
    <button class="outline" data-cmd="toggleKeepaliveAll" id="ka-all-btn">Auto-revivir: ...</button>
    <button data-cmd="showMetricsSel">Metricas</button>
    <button class="success outline" data-cmd="showCreateDistro">Crear...</button>
    <button class="danger outline" data-cmd="deleteDistroSel">Eliminar</button>
  </div>
  <div class="card">
    <table><thead><tr><th>Distro</th><th>Estado</th><th>IP</th><th>Version</th><th title="Si cae se revive sola (solo el boton Detener la excluye)">Auto-revivir</th></tr></thead><tbody id="distro-body"></tbody></table>
  </div>
  <div class="card"><h2>Exportar / Importar</h2>
    <div class="form"><button data-cmd="exportDistroSel">Exportar seleccionada</button><span class="muted text-sm">Descarga .tar de la distro seleccionada</span></div>
    <div class="separator"></div>
    <div class="form"><label>Importar:</label><input id="imp-name" placeholder="nombre distro" style="width:130px"><input id="imp-file" type="file" accept=".tar"><button data-cmd="importDistro">Subir .tar</button></div>
  </div>
</div>
<div id="tab-publicar" class="tab-content">
  <div id="activity"></div>
  <div class="card">
    <h2>Publicar en Internet (1 clic)</h2>
    <p class="muted text-sm" style="margin:8px 0 12px;">Publica un servicio WSL en Internet via tu VPS. Ej: puerto 9000 de Debian → http://TU-VPS:18097</p>
    <div class="form"><label>Distro:</label><select id="pub-distro"></select></div>
    <div class="form"><label>Puerto WSL:</label><input id="pub-wslport" value="9000" style="width:80px"></div>
    <div class="form"><label>VPS:</label><select id="pub-vps"></select></div>
    <div class="form"><label>Puerto publico:</label><input id="pub-port" value="18097" style="width:80px"></div>
    <div class="form"><label>Nombre tunnel:</label><input id="pub-name" placeholder="auto" style="width:150px"></div>
    <div class="separator"></div>
    <div class="toolbar">
      <button class="success" data-cmd="doPublish">Publicar</button>
      <button class="danger" data-cmd="doUnpublish">Detener publicacion</button>
    </div>
    <div id="pub-result" class="muted text-sm" style="margin-top:10px;"></div>
  </div>
</div>
<div id="tab-terminal" class="tab-content">
  <div class="toolbar" style="align-items:center;">
    <label class="muted text-sm">Distro:</label><select id="term-distro"></select>
    <button class="success" data-cmd="termOpen">Abrir terminal</button>
    <button class="danger outline" data-cmd="termClose">Cerrar</button>
    <span id="term-state" class="muted text-sm">cerrada</span>
    <span class="muted text-sm" style="margin-left:auto;">bash persistente · sin soporte de apps a pantalla completa (vim/top)</span>
  </div>
  <div class="card" style="padding:6px;">
    <pre id="term-out" readonly></pre>
    <div class="form" style="margin-top:6px;align-items:center;">
      <span class="accent" style="font-family:ui-monospace,Consolas,monospace;">$</span>
      <input id="term-in" style="flex:1;font-family:ui-monospace,Consolas,monospace;" placeholder="comando... (Enter para enviar, ↑↓ historial)" disabled autocomplete="off">
    </div>
  </div>
</div>
<div id="tab-vps" class="tab-content">
  <div class="toolbar">
    <button class="success" data-cmd="refresh">Refrescar</button>
    <button data-cmd="toggleVpsForm">Nuevo VPS...</button>
    <button class="outline" data-cmd="toggleVpsEditForm">Editar VPS...</button>
    <button class="danger outline" data-cmd="deleteVpsSel">Eliminar VPS</button>
  </div>
  <div id="vps-form-panel" class="card" style="display:none;">
    <h2>Nuevo VPS</h2>
    <div class="form" style="flex-direction:column;gap:8px;">
      <div class="form"><label style="width:120px">ID:</label><input id="vps-id" placeholder="mi-vps" style="width:200px"></div>
      <div class="form"><label style="width:120px">Host / IP:</label><input id="vps-host" placeholder="1.2.3.4" style="width:200px"></div>
      <div class="form"><label style="width:120px">Usuario SSH:</label><input id="vps-user" value="debian" style="width:150px"></div>
      <div class="form"><label style="width:120px">Puerto SSH:</label><input id="vps-port" type="number" value="22" style="width:80px"></div>
      <div class="form"><label style="width:120px">Password:</label><span class="pw-wrap"><input id="vps-pass" type="password" placeholder="(opcional)" style="width:200px"></span></div>
      <div class="form"><button class="success" data-cmd="submitVpsForm">Registrar VPS</button><button class="outline" data-cmd="toggleVpsForm">Cancelar</button></div>
    </div>
  </div>
  <div id="vps-edit-panel" class="card" style="display:none;">
    <h2>Editar VPS</h2>
    <div class="form" style="flex-direction:column;gap:8px;">
      <div class="form"><label style="width:120px">Host / IP:</label><input id="vps-ehost" style="width:200px"></div>
      <div class="form"><label style="width:120px">Usuario SSH:</label><input id="vps-euser" style="width:150px"></div>
      <div class="form"><label style="width:120px">Puerto SSH:</label><input id="vps-eport" type="number" style="width:80px"></div>
      <div class="form"><label style="width:120px">Password:</label><span class="pw-wrap"><input id="vps-epass" type="password" placeholder="(dejar vacio = no cambiar)" style="width:200px"></span></div>
      <div class="form"><button class="success" data-cmd="submitVpsEdit">Guardar</button><button class="outline" data-cmd="toggleVpsEditForm">Cancelar</button></div>
    </div>
  </div>
  <div class="card"><h2>Servidores VPS</h2><table><thead><tr><th>VPS</th><th>Host</th><th>Usuario</th><th>Puerto</th></tr></thead><tbody id="vps-body"></tbody></table></div>
</div>
<div id="tab-tunnels" class="tab-content">
  <div id="activity"></div>
  <div class="toolbar">
    <button class="success" data-cmd="refresh">Refrescar</button>
    <button data-cmd="openTunForm">Nuevo Tunnel...</button>
    <button class="outline" data-cmd="openTunEdit">Editar...</button>
    <button class="warn outline" data-cmd="tunDiagSel">Diagnosticar</button>
    <button data-cmd="tunnelActionSel:start">Iniciar</button>
    <button class="warn" data-cmd="tunnelActionSel:stop">Detener</button>
    <button class="danger outline" data-cmd="deleteTunnelSel">Eliminar</button>
  </div>
  <div class="card"><h2>Tunnels SSH (al VPS)</h2><table><thead><tr><th>ID</th><th>Tipo</th><th>VPS</th><th>Local</th><th>Remoto</th><th>Estado</th></tr></thead><tbody id="tun-body"></tbody></table></div>
</div>
<div id="tab-forwards" class="tab-content">
  <div id="activity"></div>
  <div class="toolbar">
    <button class="success" data-cmd="refresh">Refrescar</button>
    <button data-cmd="toggleFwdForm">Nuevo Forward...</button>
    <button data-cmd="post:/api/v1/forwards/apply">Reaplicar todos</button>
    <button class="danger outline" data-cmd="deleteForwardSel">Eliminar</button>
    <button class="danger outline" data-cmd="clearAllForwards">Limpiar todos</button>
  </div>
  <div id="fwd-form-panel" class="card" style="display:none;">
    <h2>Nuevo Forward</h2>
    <div class="form" style="flex-direction:column;gap:8px;">
      <div class="form"><label style="width:120px">ID:</label><input id="fwd-id" placeholder="mi-forward" style="width:200px"></div>
      <div class="form"><label style="width:120px">Puerto listen:</label><input id="fwd-listen" type="number" value="8080" style="width:100px"></div>
      <div class="form"><label style="width:120px">Distro:</label><select id="fwd-distro"></select></div>
      <div class="form"><label style="width:120px">Puerto WSL:</label><input id="fwd-wslport" type="number" value="9000" style="width:100px"></div>
      <div class="form"><label style="width:120px">Protocolo:</label><select id="fwd-proto"><option value="tcp">TCP</option><option value="udp">UDP</option></select></div>
      <div class="form"><button class="success" data-cmd="submitFwdForm">Crear Forward</button><button class="outline" data-cmd="toggleFwdForm">Cancelar</button></div>
    </div>
  </div>
  <div class="card"><table><thead><tr><th>ID</th><th>Listen</th><th>Distro</th><th>WSL Port</th><th>Proto</th><th>Estado</th></tr></thead><tbody id="fwd-body"></tbody></table></div>
</div>
<div id="tab-logs" class="tab-content">
  <div class="toolbar"><button class="success" data-cmd="refreshEvents">Refrescar logs</button><span class="muted text-sm">Eventos en vivo via WebSocket</span></div>
  <div class="card"><div id="events" class="empty-state">Sin eventos</div></div>
  <div class="card"><h2>Alertas</h2><table><thead><tr><th>Severidad</th><th>Mensaje</th></tr></thead><tbody id="alert-body"></tbody></table></div>
</div>
<div id="tab-ajustes" class="tab-content">
  <div class="card">
    <h2>Ajustes MCP</h2>
    <div id="mcp-status" class="text-sm" style="margin:2px 0 10px;"></div>
    <div class="form">
      <div class="row">
        <label><input type="checkbox" id="mcp-enabled"> Habilitar MCP</label>
      </div>
      <div class="row">
        <label for="mcp-transport">Transporte:</label>
        <select id="mcp-transport">
          <option value="stdio">Stdio</option>
          <option value="http">HTTP</option>
        </select>
      </div>
      <div class="row">
        <label for="mcp-port">Puerto MCP:</label>
        <input id="mcp-port" type="number" min="1" max="65535" value="8796">
      </div>
      <div class="row">
        <label><input type="checkbox" id="mcp-token-required"> Requerir token</label>
      </div>
      <div class="row">
        <label><input type="checkbox" id="mcp-expose-exec"> Exponer <code>wsl_exec</code> <span style="color:var(--err)">(ejecuta comandos como root en tus distros — RCE)</span></label>
      </div>
      <div class="row">
        <label for="mcp-token">Token MCP:</label>
        <input id="mcp-token" type="text" placeholder="dejar vacío para generar nuevo">
        <button data-cmd="generateMcptoken">Generar</button>
        <button data-cmd="copyMcptoken">Copiar</button>
      </div>
    </div>
    <div class="separator"></div>
    <h2>Exportación MCP al VPS</h2>
    <div class="form">
      <div class="row">
        <label><input type="checkbox" id="mcp-vps-export-enabled"> Exportar MCP al VPS</label>
      </div>
      <div class="row">
        <label for="mcp-vps-target-host">Host VPS destino:</label>
        <select id="mcp-vps-target-host">
          <option value="">Seleccionar VPS...</option>
        </select>
      </div>
      <div class="row">
        <label for="mcp-vps-target-port">Puerto VPS destino:</label>
        <input id="mcp-vps-target-port" type="number" min="1" max="65535" value="55872">
      </div>
      <div class="row">
        <button class="success" data-cmd="saveMcpSettings">Guardar Configuración</button>
        <button class="outline" data-cmd="applyMcpSettings">Aplicar Configuración</button>
      </div>
    </div>
  </div>
</div>
<div id="toast"></div>
<div id="ws-indicator" style="position:fixed;bottom:8px;left:8px;width:8px;height:8px;border-radius:50%;background:var(--err);z-index:999;"></div>
<div id="statusbar"><span id="sub">conectando...</span><span id="ws-status"></span></div>
<script>
let TOKEN = localStorage.getItem('pf_token') || '';
// H4: CSP nonce bloquea los onclick inline; se rebindan por delegacion.
// Solo se invocan funciones globales conocidas con un argumento simple.
document.addEventListener('click', function(e){
  const chip = e.target && e.target.closest ? e.target.closest('.ka-chip') : null;
  if(chip){ kaChipToggle(chip.dataset.ka, chip.classList.contains('off')); return; }
  const el = e.target && e.target.closest ? e.target.closest('[data-cmd]') : null;
  if(!el) return;
  const spec = el.getAttribute('data-cmd') || '';
  const idx = spec.indexOf(':');
  const name = idx === -1 ? spec : spec.slice(0, idx);
  const arg = idx === -1 ? '' : spec.slice(idx + 1);
  if(name === 'post'){ window.post(arg); return; }
  const fn = window[name];
  if(typeof fn === 'function'){ fn(arg); }
});
function bindCmdEvents(){
  document.querySelectorAll('[onclick]').forEach(function(el){
    const code = (el.getAttribute('onclick')||'').trim();
    const m = code.match(/^([a-zA-Z_][\w]*)\((?:"([^"]*)"|'([^']*)')?\)$/);
    let spec = code;
    if(m){ const nm = m[1]; const a = m[2] !== undefined ? m[2] : m[3]; spec = (a === undefined) ? nm : nm + ':' + a; }
    el.removeAttribute('onclick');
    el.setAttribute('data-cmd', spec);
  });
}
async function clearAllForwards(){ if(await showConfirm('Limpiar forwards','Limpiar TODOS los forwards?')) post('/api/v1/forwards/clear', 'Limpiando forwards...'); }
function esc(v){ const d=document.createElement('div'); d.textContent=(v===null||v===undefined)?'':String(v); return d.innerHTML.replace(/"/g,'&quot;'); }
const EYE_SVG='<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"/><circle cx="12" cy="12" r="3"/></svg>';
const EYE_OFF_SVG='<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M17.94 17.94A10.07 10.07 0 0 1 12 20c-7 0-11-8-11-8a18.45 18.45 0 0 1 5.06-5.94M9.9 4.24A9.12 9.12 0 0 1 12 4c7 0 11 8 11 8a18.5 18.5 0 0 1-2.16 3.19"/><path d="M14.12 14.12a3 3 0 1 1-4.24-4.24"/><line x1="1" y1="1" x2="23" y2="23"/></svg>';
function decoratePw(root){
  (root||document).querySelectorAll('.pw-wrap > input[type=password]').forEach(function(inp){
    const w=inp.parentElement;
    if(w.querySelector('.pw-eye')) return;
    const b=document.createElement('button');
    b.type='button'; b.className='pw-eye'; b.title='Mostrar'; b.innerHTML=EYE_SVG;
    b.onclick=function(){
      const show=inp.type==='password';
      inp.type=show?'text':'password';
      b.innerHTML=show?EYE_OFF_SVG:EYE_SVG;
      b.title=show?'Ocultar':'Mostrar';
    };
    w.appendChild(b);
  });
}
function showDialog(title, fields, onOk){
  const overlay = document.createElement('div');
  overlay.className = 'dialog-overlay';
  let html = '<div class="dialog"><h3>' + esc(title) + '</h3>';
  for(const f of fields){
    html += '<div class="row"><label>' + esc(f.label) + ':</label>';
    if(f.type === 'select'){
      html += '<select id="dlg-' + f.id + '">';
      for(const o of (f.options||[])) html += '<option value="' + esc(o.value) + '">' + esc(o.text) + '</option>';
      html += '</select>';
    } else if(f.type === 'password'){
      html += '<span class="pw-wrap"><input id="dlg-' + f.id + '" type="password" value="' + esc(f.value||'') + '"></span>';
    } else if(f.type === 'number'){
      html += '<input id="dlg-' + f.id + '" type="number" value="' + esc(f.value||'0') + '" min="1">';
    } else {
      html += '<input id="dlg-' + f.id + '" type="text" value="' + esc(f.value||'') + '" placeholder="' + esc(f.placeholder||'') + '">';
    }
    html += '</div>';
  }
  html += '<div class="btns"><button class="outline" id="dlg-cancel">Cancelar</button><button class="success" id="dlg-ok">Aceptar</button></div></div>';
  overlay.innerHTML = html;
  document.body.appendChild(overlay);
  decoratePw(overlay);
  overlay.querySelector('#dlg-cancel').onclick = ()=> overlay.remove();
  overlay.querySelector('#dlg-ok').onclick = ()=>{
    const vals = {};
    for(const f of fields){ vals[f.id] = document.getElementById('dlg-'+f.id).value; }
    overlay.remove();
    onOk(vals);
  };
  overlay.addEventListener('click', e=>{ if(e.target===overlay) overlay.remove(); });
}
function showConfirm(title, msg){
  return new Promise(resolve=>{
    const ov=document.createElement('div');
    ov.className='dialog-overlay';
    ov.innerHTML='<div class="dialog"><h3>'+esc(title)+'</h3><p style="color:var(--text);font-size:13px;margin:0 0 16px;line-height:1.4">'+esc(msg)+'</p><div class="btns"><button class="outline" id="cf-cancel">Cancelar</button><button class="danger" id="cf-ok">Confirmar</button></div></div>';
    document.body.appendChild(ov);
    ov.querySelector('#cf-cancel').onclick=()=>{ov.remove();resolve(false);};
    ov.querySelector('#cf-ok').onclick=()=>{ov.remove();resolve(true);};
    ov.addEventListener('click',e=>{if(e.target===ov){ov.remove();resolve(false);}});
  });
}
function logout(){ localStorage.removeItem('pf_token'); document.cookie='pf_token=; Path=/; Max-Age=0; SameSite=Strict'; window.location.href='/login'; }
function badge(s){
  const cls=(s==='ok'||s==='running'||s==='up')?'badge-ok':(s==='paused'||s==='waiting'||s==='stopped')?'badge-warn':(s==='error'||s==='down')?'badge-err':'badge-info';
  return '<span class="badge '+cls+'">'+esc(s)+'</span>';
}
let toastTimer=null;
function toast(msg, kind){
  const t=document.getElementById('toast');
  t.textContent=msg; t.className=kind||'';
  clearTimeout(toastTimer);
  requestAnimationFrame(()=>{ t.classList.add('show'); });
  toastTimer=setTimeout(()=>{ t.classList.remove('show'); }, 4000);
}
function activity(msg, kind){
  const a=document.getElementById('activity');
  a.textContent=msg; a.className=kind||'info';
  if(msg) setTimeout(()=>{ a.textContent=''; a.className=''; }, 5000);
}
async function api(path, opts={}){
  const headers = Object.assign({'Content-Type':'application/json'}, opts.headers||{});
  if(TOKEN) headers['Authorization']='Bearer '+TOKEN;
  const r = await fetch(path, Object.assign({headers}, opts));
  if(r.status===401){ window.location.href='/login'; throw new Error('No autorizado'); }
  if(r.status===429){ const d=await r.clone().json().catch(()=>({})); toast(d.error||'Demasiados intentos','err'); throw new Error(d.error||'Rate limited'); }
  return r.json();
}
async function post(path, label){ const msg=label||'Procesando...'; activity(msg,'info'); const d=await api(path,{method:'POST'}); const k=d.ok===false?'err':'ok'; activity(d.message||d.error||'Hecho',k); toast(d.message||d.error||'ok',k); refresh(); return d; }
async function postJson(path, body, label){ const msg=label||'Procesando...'; activity(msg,'info'); const d=await api(path,{method:'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify(body)}); const k=d.ok===false?'err':'ok'; activity(d.message||d.error||'Hecho',k); toast(d.message||d.error||'ok',k); refresh(); return d; }
function showTab(id){ document.querySelectorAll('.tab').forEach(t=>t.classList.remove('active')); document.querySelectorAll('.tab-content').forEach(c=>c.classList.remove('active')); document.querySelector(`[data-cmd="showTab:${id}"]`).classList.add('active'); document.getElementById('tab-'+id).classList.add('active'); localStorage.setItem('wslport-tab', id); if(id==='ajustes') loadMcpSettings(); }
(function(){ bindCmdEvents(); const t=localStorage.getItem('wslport-tab'); if(t) showTab(t); })();
function makeSelectable(tbodyId){ document.getElementById(tbodyId).addEventListener('click', e=>{ const tr=e.target.closest('tr'); if(!tr||!tr.dataset.id) return; tr.parentElement.querySelectorAll('tr').forEach(r=>r.classList.remove('selected')); tr.classList.add('selected'); }); }
['distro-body','tun-body','vps-body','fwd-body'].forEach(makeSelectable);
function renderDistros(list, ka){
  KA=ka||KA||{}; const btn=document.getElementById('ka-all-btn'); if(btn){ const on=KA.enabled!==false; btn.textContent='Auto-revivir: '+(on?'ON':'OFF'); btn.className=on?'success outline':'danger outline'; }
  const b=document.getElementById('distro-body'); b.innerHTML='';
  const sel=document.getElementById('pub-distro'); if(sel){ const cur=sel.value; sel.innerHTML=''; list.forEach(d=>{const o=document.createElement('option');o.value=d.name;o.textContent=d.name;sel.appendChild(o);}); if(cur) sel.value=cur; else if(list[0]) sel.value=list[0].name; }
  const fSel=document.getElementById('fwd-distro'); if(fSel){ const cur=fSel.value; fSel.innerHTML=''; list.forEach(d=>{const o=document.createElement('option');o.value=d.name;o.textContent=d.name;sel.appendChild(o);}); if(cur) sel.value=cur; }
  const tSel=document.getElementById('term-distro'); if(tSel){ const cur=sel.value; sel.innerHTML=''; list.forEach(d=>{const o=document.createElement('option');o.value=d.name;o.textContent=d.name+(d.running?'':' (apagada)');tSel.appendChild(o);}); if(cur&&list.some(d=>d.name===cur)) tSel.value=cur; }
  if(!list||!list.length){ b.innerHTML='<tr><td colspan=5 class="empty-state">sin distros (WSL no responde)</td></tr>'; return; }
  for(const d of list){
    const state=d.state==='Running'?'running':'stopped';
    const docker=d.name.toLowerCase().startsWith('docker-desktop');
    const chip=docker?'<span style="opacity:.4">n/a</span>':(d.auto_revive?'<span class="ka-chip on" data-ka="'+esc(d.name)+'" title="Protegida: si cae se revive sola. Clic para excluir">ON</span>':'<span class="ka-chip off" data-ka="'+esc(d.name)+'" title="Excluida (apagada por ti): NO se revive. Clic para proteger">OFF</span>');
    const tr=document.createElement('tr'); tr.dataset.id=d.name;
    tr.innerHTML='<td class="accent">'+esc(d.name)+'</td><td>'+badge(state)+'</td><td>'+esc(d.ip||'-')+'</td><td>'+esc(d.version)+'</td><td>'+chip+'</td>';
    b.appendChild(tr);
  }
}
async function kaChipToggle(name, wantAuto){ const r=await api('/api/v1/distro/'+encodeURIComponent(name)+'/keepalive',{method:'POST',headers:{Authorization:'Bearer '+TOKEN,'Content-Type':'application/json'},body:JSON.stringify({exempt:!wantAuto})}); if(r&&r.ok){ toast((wantAuto?'Protegida: ':'Excluida: ')+name+(wantAuto?' (se reavivara si cae)':' (quedara apagada si la detienes)'),'ok'); refresh(); } else toast((r&&r.error)||'error','err'); }
async function toggleKeepaliveAll(){ const en=!(KA&&KA.enabled!==false); const r=await api('/api/v1/keepalive',{method:'POST',headers:{Authorization:'Bearer '+TOKEN,'Content-Type':'application/json'},body:JSON.stringify({enabled:en})}); if(r&&r.ok){ toast('Auto-revivir global '+(en?'ACTIVADO':'DESACTIVADO'), en?'ok':'warn'); refresh(); } else toast((r&&r.error)||'error','err'); }
function distroActionSel(op){ const id=document.querySelector('#distro-body tr.selected'); if(!id){ toast('Selecciona una distro','warn'); return; } const name=id.dataset.id; const labels={start:'Iniciando '+name+'...',stop:'Deteniendo '+name+'...',restart:'Reiniciando '+name+'...',delete:'Eliminando '+name+'...'}; post('/api/v1/distro/'+encodeURIComponent(name)+'/'+op, labels[op]||op+' '+name+'...'); }
async function startAllDistros(){ if(!await showConfirm('Iniciar distros','Iniciar TODAS las distros WSL?')) return; post('/api/v1/distro/start-all', 'Iniciando todas las distros...'); }
async function shutdownAllDistros(){ if(!await showConfirm('Apagar WSL','Apagar TODAS las distros WSL y detener WSL completamente?')) return; post('/api/v1/distro/shutdown-all', 'Apagando WSL...'); }
function exportDistroSel(){ const sel=document.querySelector('#distro-body tr.selected'); if(!sel){ toast('Selecciona una distro','warn'); return; } exportDistro(sel.dataset.id); }
async function deleteDistroSel(){ const sel=document.querySelector('#distro-body tr.selected'); if(!sel){ toast('Selecciona una distro','warn'); return; } if(!await showConfirm('Eliminar distro','Eliminar distro '+sel.dataset.id+' y TODOS sus datos?')) return; post('/api/v1/distro/'+encodeURIComponent(sel.dataset.id)+'/delete', 'Eliminando distro...'); }
async function showMetricsSel(){ const sel=document.querySelector('#distro-body tr.selected'); if(!sel){ toast('Selecciona una distro','warn'); return; } const d=await api('/api/v1/distro/'+encodeURIComponent(sel.dataset.id)+'/metrics'); if(d.ok){ toast('RAM: '+d.ram_used_mb+'/'+d.ram_total_mb+' MB ('+d.ram_percent+'%)','ok'); } else toast(d.error||'Error al obtener metricas','err'); }
function showCreateDistro(){
  activity('Cargando distros disponibles...','info');
  api('/api/v1/distro/available',{method:'POST'}).then(d=>{
    activity('','');
    const distros = (d.ok && d.distros) ? d.distros : ['Ubuntu','Debian'];
    showDialog('Crear nueva distro WSL', [
      {id:'cd-name', label:'Distro a instalar', type:'select', options:distros.map(n=>({value:n,text:n}))},
    ], function(vals){
      const name = vals['cd-name'];
      if(!name){ toast('Selecciona una distro','err'); return; }
      activity('Instalando '+name+'... (puede tardar varios minutos)','info');
      toast('Instalando '+name+'... no cierres esta pagina','info');
      api('/api/v1/distro/create',{method:'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify({name})}).then(d=>{
        activity(d.message||d.error, d.ok?'success':'error'); 
        toast(d.message||d.error, d.ok?'ok':'err');
        refresh();
      });
    });
  });
}
async function exportDistro(name){
  activity('Exportando '+name+'... (la descarga comenzara pronto)','info');
  try{
    const r=await fetch('/api/v1/distro/'+encodeURIComponent(name)+'/export',{headers:{Authorization:'Bearer '+TOKEN}});
    if(!r.ok){ 
      let errMsg = 'HTTP ' + r.status;
      try { const d = await r.json(); errMsg = d.error || errMsg; } catch(e){}
      throw new Error(errMsg); 
    }
    const ct = r.headers.get('content-type') || '';
    if(ct.includes('application/json')){
      const d = await r.json();
      if(!d.ok) throw new Error(d.error || 'Error desconocido');
      throw new Error('Respuesta inesperada');
    }
    const blob=await r.blob();
    const url=URL.createObjectURL(blob);
    const a=document.createElement('a');
    a.href=url; a.download=name+'.tar';
    a.style.display='none';
    document.body.appendChild(a); 
    a.click(); 
    setTimeout(()=>{ a.remove(); URL.revokeObjectURL(url); }, 1000);
    activity('Exportacion completada - revisa descargas','success');
    toast('Descarga de '+name+'.tar iniciada','ok');
  }catch(e){ activity('Error exportando: '+e.message,'error'); toast('Error: '+e.message,'err'); }
}
async function importDistro(){
  const file=document.getElementById('imp-file').files[0]; const name=document.getElementById('imp-name').value.trim();
  if(!file){ toast('Selecciona .tar','err'); return; }
  if(!name){ toast('Nombre requerido','err'); return; }
  const fd=new FormData(); fd.append('name',name); fd.append('install_dir',''); fd.append('file',file);
  const sizeMB = (file.size/1024/1024).toFixed(0);
  activity('Importando '+name+' ('+sizeMB+' MB) — esto puede tardar varios minutos...','info');
  toast('Importando '+name+'... espera mientras se procesa','info');
  try{
    const r=await fetch('/api/v1/distro/import',{method:'POST', headers:{Authorization:'Bearer '+TOKEN}, body:fd});
    const d=await r.json();
    if(d.ok){
      activity(d.message+' — refrescando lista de distros...','success');
      toast(d.message,'ok');
      await refresh();
      // Auto-select la nueva distro para monitorizar
      setTimeout(()=>{
        const rows=document.querySelectorAll('#distro-body tr');
        for(const tr of rows){ if(tr.dataset.id===name){ tr.classList.add('selected'); tr.scrollIntoView({behavior:'smooth'}); break; } }
      },500);
    } else {
      activity('Error: '+d.error,'error');
      toast('Error: '+d.error,'err');
    }
  }catch(e){ activity('Error: '+e.message,'error'); toast('Error de conexion: '+e.message,'err'); }
}
function doPublish(){
  const distro=document.getElementById('pub-distro').value, wslport=parseInt(document.getElementById('pub-wslport').value), vps=document.getElementById('pub-vps').value, pubport=parseInt(document.getElementById('pub-port').value);
  const tunName = document.getElementById('pub-name').value.trim();
  if(!distro||!vps||!wslport||!pubport){ toast('Completa todos los campos','err'); return; }
  const payload = {distro, wsl_port:wslport, vps_id:vps, public_port:pubport};
  if(tunName) payload.tunnel_name = tunName;
  postJson('/api/v1/publish', payload, 'Publicando...').then(d=>{
    if(d && d.ok && d.public_url){
      document.getElementById('pub-result').innerHTML='Publicado: <span class="accent">'+d.public_url+'</span><br><span class="muted text-sm">Tunnel: '+esc(d.tunnel_id)+'</span>';
      activity('Publicado en '+d.public_url,'success');
    } else if(d && d.error){
      document.getElementById('pub-result').innerHTML='<span style="color:var(--err)">'+esc(d.error)+'</span>';
      activity('Error: '+d.error,'error');
    }
  }).catch(e=>{
    document.getElementById('pub-result').innerHTML='<span style="color:var(--err)">Error de conexion</span>';
    activity('Error de conexion: '+e.message,'error');
  });
}
function doUnpublish(){
  const distro=document.getElementById('pub-distro').value, wslport=parseInt(document.getElementById('pub-wslport').value);
  const tunName = document.getElementById('pub-name').value.trim();
  let tid;
  if(tunName) tid = tunName;
  else if(distro && wslport) tid = 'pub-'+distro.toLowerCase().replace(/[^a-z0-9]+/g,'-')+'-'+wslport;
  else { toast('Ingresa distro y puerto o nombre del tunnel','warn'); return; }
  activity('Deteniendo publicacion...','info');
  api('/api/v1/unpublish/'+encodeURIComponent(tid),{method:'POST'}).then(d=>{activity(d.message||'Eliminado','success'); refresh();});
}
function tunnelActionSel(op){ const sel=document.querySelector('#tun-body tr.selected'); if(!sel){ toast('Selecciona un tunnel','warn'); return; } const labels={start:'Iniciando tunnel...',stop:'Deteniendo tunnel...',restart:'Reiniciando tunnel...'}; post('/api/v1/tunnels/'+encodeURIComponent(sel.dataset.id)+'/'+op, labels[op]||'Procesando tunnel...'); }
async function deleteTunnelSel(){ const sel=document.querySelector('#tun-body tr.selected'); if(!sel){ toast('Selecciona un tunnel','warn'); return; } if(!await showConfirm('Eliminar tunnel','Eliminar tunnel '+sel.dataset.id+'?')) return; post('/api/v1/tunnels/'+encodeURIComponent(sel.dataset.id)+'/remove', 'Eliminando tunnel...'); }
/* ---- Tunnel modal (popup con todas las opciones) ---- */
let LAST_TUNNELS=[]; let KA={enabled:true, stopped_by_user:[]};
function openTunForm(){ tunDialog(null); }
function openTunEdit(){
  const sel=document.querySelector('#tun-body tr.selected');
  if(!sel){ toast('Selecciona un tunnel para editar','warn'); return; }
  const t=LAST_TUNNELS.find(x=>x.id===sel.dataset.id);
  tunDialog(t||{id:sel.dataset.id});
}
function tunDialog(t){
  document.getElementById('tun-modal')?.remove();
  const isNew=!t;
  const ov=document.createElement('div'); ov.className='modal-overlay'; ov.id='tun-modal';
  ov.innerHTML='<div class="modal"><h3>'+(isNew?'Nuevo Tunnel':'Editar Tunnel · '+esc(t.id))+'</h3>'
    +'<div class="grid">'
    +'<label>ID</label><input id="tm-id" value="'+esc(t&&t.id||'')+'" placeholder="mi-tunnel"'+(isNew?'':' readonly')+'>'
    +'<label>Tipo</label><select id="tm-type"><option value="ssh">SSH</option><option value="tailscale">Tailscale</option><option value="cloudflare">Cloudflare</option></select>'
    +'<label>VPS</label><select id="tm-vps"></select>'
    +'<label>Host local</label><input id="tm-lhost" value="127.0.0.1">'
    +'<label>Puerto local</label><input id="tm-lport" type="number" value="9000" min="1" max="65535">'
    +'<label>Remotos</label><div id="tm-remotes" class="span" style="grid-column:2;"></div>'
    +'<div></div><div class="span" style="grid-column:2;"><button class="outline" id="tm-addrem">+ Anadir remoto</button></div>'
    +'<label>Keepalive (seg)</label><input id="tm-kint" type="number" value="30" min="0">'
    +'<label>Keepalive max</label><input id="tm-kcnt" type="number" value="3" min="0">'
    +'<label>Opciones</label><div class="span" style="grid-column:2;display:flex;gap:14px;flex-wrap:wrap;">'
    +'<label style="color:var(--text)"><input type="checkbox" id="tm-autostart" checked> auto_start</label>'
    +'<label style="color:var(--text)"><input type="checkbox" id="tm-enabled" checked> enabled</label>'
    +'<label style="color:var(--text)"><input type="checkbox" id="tm-hgate" checked> health_gate</label></div>'
    +'</div>'
    +'<div class="btns"><button class="outline" id="tm-cancel">Cancelar</button><button class="success" id="tm-ok">'+(isNew?'Crear Tunnel':'Guardar cambios')+'</button></div>'
    +'</div>';
  document.body.appendChild(ov);
  ov.querySelector('#tm-cancel').onclick=()=>ov.remove();
  ov.addEventListener('click',e=>{ if(e.target===ov) ov.remove(); });
  api('/api/v1/vps').then(d=>{
    const sel=ov.querySelector('#tm-vps'); sel.innerHTML='';
    (d.vps||[]).forEach(v=>{ const o=document.createElement('option'); o.value=v.id; o.textContent=v.id+' ('+v.host+')'; sel.appendChild(o); });
    if(t&&t.vps_id) sel.value=t.vps_id;
  });
  if(!isNew){
    ov.querySelector('#tm-type').value=t.type||'ssh';
    const lp=(t.local||'127.0.0.1:9000').split(':');
    ov.querySelector('#tm-lhost').value=lp[0]||'127.0.0.1';
    ov.querySelector('#tm-lport').value=lp[1]||'';
    const rems=(t.remote&&t.remote.length)?t.remote:['0.0.0.0:'];
    rems.forEach(r=>{ const rp=(''+r).split(':'); addTunRemote(ov, rp[0]||'0.0.0.0', rp[1]||''); });
    if(t.keepalive_interval!=null) ov.querySelector('#tm-kint').value=t.keepalive_interval;
    if(t.keepalive_count!=null) ov.querySelector('#tm-kcnt').value=t.keepalive_count;
    ov.querySelector('#tm-autostart').checked=t.auto_start!==false;
    ov.querySelector('#tm-enabled').checked=t.enabled!==false;
    ov.querySelector('#tm-hgate').checked=t.health_gate!==false;
  } else {
    addTunRemote(ov,'0.0.0.0','18097');
  }
  ov.querySelector('#tm-addrem').onclick=()=>addTunRemote(ov,'0.0.0.0','');
  ov.querySelector('#tm-ok').onclick=()=>submitTunModal(ov, isNew?null:t.id);
}
function addTunRemote(ov, host, port){
  const div=document.createElement('div'); div.className='rem-row';
  div.innerHTML='<input placeholder="host" value="'+esc(host||'0.0.0.0')+'" style="flex:2"><input placeholder="puerto" type="number" value="'+esc(port||'')+'" style="flex:1" min="1" max="65535"><button class="danger outline" title="Quitar">x</button>';
  div.querySelector('button').onclick=()=>div.remove();
  ov.querySelector('#tm-remotes').appendChild(div);
}
function submitTunModal(ov, editId){
  const id=ov.querySelector('#tm-id').value.trim();
  const vps=ov.querySelector('#tm-vps').value;
  const lh=ov.querySelector('#tm-lhost').value.trim()||'127.0.0.1';
  const lp=ov.querySelector('#tm-lport').value.trim();
  const remotes=[...ov.querySelectorAll('#tm-remotes .rem-row')].map(r=>{
    const ins=r.querySelectorAll('input'); return {host:ins[0].value.trim(), port:ins[1].value.trim()};
  }).filter(r=>r.host&&r.port).map(r=>r.host+':'+r.port);
  const payload={
    id, vps_id:vps, type:ov.querySelector('#tm-type').value,
    local:lh+':'+lp, remotes,
    auto_start:ov.querySelector('#tm-autostart').checked,
    enabled:ov.querySelector('#tm-enabled').checked,
    health_gate:ov.querySelector('#tm-hgate').checked,
    keepalive_interval:parseInt(ov.querySelector('#tm-kint').value)||30,
    keepalive_count:parseInt(ov.querySelector('#tm-kcnt').value)||3,
  };
  if(!id||!vps||!lp){ toast('ID, VPS y puerto local son obligatorios','err'); return; }
  if(!remotes.length){ toast('Anade al menos un remoto host:puerto','err'); return; }
  if(editId) postJson('/api/v1/tunnels/'+encodeURIComponent(editId)+'/edit', payload, 'Guardando tunnel...');
  else postJson('/api/v1/tunnels/add', payload, 'Creando tunnel...');
  ov.remove();
}
/* ---- Diagnostico de tunnel caido ---- */
function tunDiagSel(){ const sel=document.querySelector('#tun-body tr.selected'); if(!sel){ toast('Selecciona un tunnel','warn'); return; } tunDiag(sel.dataset.id); }
async function tunDiag(id){
  activity('Diagnosticando '+id+'...','info');
  let d, l;
  try{ d=await api('/api/v1/tunnels/'+encodeURIComponent(id)+'/diag'); }catch(e){ return; }
  try{ l=await api('/api/v1/tunnels/'+encodeURIComponent(id)+'/log'); }catch(e){ l={ok:false}; }
  activity('','');
  if(!d.ok){ toast(d.error||'Error','err'); return; }
  const ov=document.createElement('div'); ov.className='modal-overlay'; ov.id='tun-diag-modal';
  let h='<div class="modal" style="width:640px;"><h3>Diagnostico · '+esc(id)+'</h3>';
  if(d.alive){ h+='<div class="diag-ok">✔ Tunnel arriba (state: '+esc(d.state||'running')+')</div>'; }
  else { h+='<div class="diag-reason">✖ Razon del fallo: '+esc(d.reason||d.state||'desconocida')+'</div>'; }
  h+='<div class="grid" style="display:grid;grid-template-columns:160px 1fr;gap:4px 10px;font-size:12px;">'
    +'<label style="color:var(--muted);text-align:right;">Estado</label><span>'+esc(d.state||'-')+'</span>'
    +'<label style="color:var(--muted);text-align:right;">VPS</label><span>'+(d.vps?(esc(d.vps.user)+'@'+esc(d.vps.host)+':'+esc(d.vps.port)):'<span style="color:var(--err)">no existe en config</span>')+'</span>'
    +'<label style="color:var(--muted);text-align:right;">Local</label><span>'+esc(d.local||'-')+'</span>'
    +'<label style="color:var(--muted);text-align:right;">Servicio local</label><span>'+(d.gate_ok?'<span style="color:var(--ok)">escuchando</span>':'<span style="color:var(--warn)">sin listener</span>')+'</span></div>';
  h+='<div style="margin-top:12px;font-size:12px;color:var(--muted);">Ultimo log: '+esc((l.ok&&l.path)||'(sin log)')+'</div>';
  h+='<div class="log-box" style="margin-top:6px;">'+esc((l.ok&&l.log&&l.log.trim())||'(vacio)')+'</div>';
  h+='<div class="btns"><button class="outline" id="td-close">Cerrar</button><button class="success" id="td-retry">Reintentar ahora</button></div></div>';
  ov.innerHTML=h;
  document.body.appendChild(ov);
  ov.querySelector('#td-close').onclick=()=>ov.remove();
  ov.addEventListener('click',e=>{ if(e.target===ov) ov.remove(); });
  ov.querySelector('#td-retry').onclick=()=>{ ov.remove();
    const tr=[...document.querySelectorAll('#tun-body tr')].find(r=>r.dataset.id===id);
    if(tr){ tr.parentElement.querySelectorAll('tr').forEach(r=>r.classList.remove('selected')); tr.classList.add('selected'); }
    post('/api/v1/tunnels/'+encodeURIComponent(id)+'/restart','Reiniciando '+id+'...'); };
}
/* ---- Terminal WSL via WebSocket ---- */
let TERM_ON=false; const termHist=[]; let termHistIdx=-1;
function termWsSend(obj){
  if(WS && WS.readyState===1){ WS.send(JSON.stringify(obj)); return true; }
  toast('WebSocket no conectado, espera a que este verde','err'); return false;
}
function termOut(txt){ const o=document.getElementById('term-out'); o.textContent+=txt; o.scrollTop=o.scrollHeight; }
function termSetState(txt, running){
  TERM_ON=!!running;
  document.getElementById('term-state').textContent=txt;
  document.getElementById('term-in').disabled=!running;
  if(running) document.getElementById('term-in').focus();
}
function termOpen(){
  const d=document.getElementById('term-distro').value;
  if(!d){ toast('Selecciona una distro','warn'); return; }
  document.getElementById('term-out').textContent='';
  termOut('$ abriendo terminal en '+d+'...\n');
  if(termWsSend({type:'term_start', distro:d})) termSetState('abriendo...', false);
}
function termClose(){ termWsSend({type:'term_stop'}); }
function termSubmit(){
  const inp=document.getElementById('term-in');
  const cmd=inp.value; if(!cmd.trim()) return;
  if(!termWsSend({type:'term_cmd', cmd})) return;
  termOut(cmd+'\n');
  termHist.push(cmd); termHistIdx=termHist.length;
  inp.value='';
}
document.getElementById('term-in').addEventListener('keydown', e=>{
  if(e.key==='Enter'){ e.preventDefault(); termSubmit(); }
  else if(e.key==='ArrowUp'){ e.preventDefault(); if(termHist.length){ termHistIdx=Math.max(0,termHistIdx-1); e.target.value=termHist[termHistIdx]||''; } }
  else if(e.key==='ArrowDown'){ e.preventDefault(); if(termHist.length){ termHistIdx=Math.min(termHist.length,termHistIdx+1); e.target.value=termHist[termHistIdx]||''; } }
});
/* ---- VPS inline forms ---- */
function toggleVpsForm(){
  const p=document.getElementById('vps-form-panel'); const v=p.style.display!=='none'; p.style.display=v?'none':'block';
  document.getElementById('vps-edit-panel').style.display='none';
}
function toggleVpsEditForm(){
  const sel=document.querySelector('#vps-body tr.selected');
  if(!sel){ toast('Selecciona un VPS para editar','warn'); return; }
  const p=document.getElementById('vps-edit-panel'); const v=p.style.display!=='none';
  if(v){ p.style.display='none'; return; }
  p.style.display='block';
  document.getElementById('vps-form-panel').style.display='none';
  const t=sel.dataset;
  document.getElementById('vps-ehost').value=t.host||'';
  document.getElementById('vps-euser').value=t.user||'debian';
  document.getElementById('vps-eport').value=t.port||'22';
  document.getElementById('vps-epass').value='';
}
function submitVpsForm(){
  const id=document.getElementById('vps-id').value.trim(), host=document.getElementById('vps-host').value.trim();
  const user=document.getElementById('vps-user').value.trim()||'debian', port=parseInt(document.getElementById('vps-port').value)||22;
  const pass=document.getElementById('vps-pass').value;
  if(!id||!host){ toast('ID y Host son obligatorios','err'); return; }
  postJson('/api/v1/vps/add',{id, host, user, port, password:pass}, 'Registrando VPS...');
  document.getElementById('vps-form-panel').style.display='none';
}
function submitVpsEdit(){
  const sel=document.querySelector('#vps-body tr.selected'); if(!sel) return;
  const host=document.getElementById('vps-ehost').value.trim();
  const user=document.getElementById('vps-euser').value.trim()||'debian';
  const port=parseInt(document.getElementById('vps-eport').value)||22;
  const pass=document.getElementById('vps-epass').value;
  if(!host){ toast('Host es obligatorio','err'); return; }
  postJson('/api/v1/vps/'+encodeURIComponent(sel.dataset.id)+'/edit',{host, user, port, password:pass}, 'Editando VPS...');
  document.getElementById('vps-edit-panel').style.display='none';
}
async function deleteVpsSel(){ const sel=document.querySelector('#vps-body tr.selected'); if(!sel){ toast('Selecciona un VPS','warn'); return; } if(!await showConfirm('Eliminar VPS','Eliminar VPS '+sel.dataset.id+'?')) return; post('/api/v1/vps/remove/'+encodeURIComponent(sel.dataset.id), 'Eliminando VPS...'); }
function toggleFwdForm(){
  const panel = document.getElementById('fwd-form-panel');
  const visible = panel.style.display !== 'none';
  panel.style.display = visible ? 'none' : 'block';
  if(!visible) populateFwdDistro();
}
function populateFwdDistro(){
  const sel = document.getElementById('fwd-distro');
  if(!sel) return;
  const cur = sel.value;
  api('/api/v1/state').then(d => {
    sel.innerHTML = '';
    (d.distros||[]).forEach(dd => {
      const o = document.createElement('option');
      o.value = dd.name; o.textContent = dd.name;
      sel.appendChild(o);
    });
    if(cur) sel.value = cur;
  });
}
function submitFwdForm(){
  const id = document.getElementById('fwd-id').value.trim();
  const listen = parseInt(document.getElementById('fwd-listen').value);
  const distro = document.getElementById('fwd-distro').value;
  const wslport = parseInt(document.getElementById('fwd-wslport').value);
  const proto = document.getElementById('fwd-proto').value;
  if(!id || !listen || !distro || !wslport){ toast('Completa todos los campos','err'); return; }
  postJson('/api/v1/forwards/add',{id, listen_port:listen, distro, wsl_port:wslport, protocol:proto, auto_apply:true}, 'Creando forward...');
  document.getElementById('fwd-form-panel').style.display = 'none';
}
function deleteForwardSel(){ const sel=document.querySelector('#fwd-body tr.selected'); if(!sel){ toast('Selecciona un forward','warn'); return; } post('/api/v1/forwards/remove/'+encodeURIComponent(sel.dataset.id), 'Eliminando forward...'); }
function renderForwards(list){ const b=document.getElementById('fwd-body'); b.innerHTML=''; if(!list||!list.length){ b.innerHTML='<tr><td colspan=6 class="empty-state">sin forwards</td></tr>'; return; } for(const f of list){ const tr=document.createElement('tr'); tr.dataset.id=f.id; tr.innerHTML='<td>'+esc(f.id)+'</td><td>:'+esc(f.listen_port)+'</td><td>'+esc(f.wsl_distro||'--')+'</td><td>:'+esc(f.wsl_port)+'</td><td>'+esc(f.protocol||'tcp')+'</td><td>'+badge(f.state)+'</td>'; b.appendChild(tr); } }
function renderTunnels(list){ LAST_TUNNELS=list||[]; const b=document.getElementById('tun-body'); b.innerHTML=''; if(!list||!list.length){ b.innerHTML='<tr><td colspan=6 class="empty-state">sin tunnels</td></tr>'; return; } for(const t of list){ const tr=document.createElement('tr'); tr.dataset.id=t.id; tr.dataset.vps=t.vps_id||''; tr.dataset.local=t.local||''; tr.dataset.remote=(t.remote||[]).join(', '); const err=(t.state!=='running'&&t.error)?'<div class="tun-err" title="'+esc(t.error)+'">✖ '+esc(t.error)+'</div>':''; tr.innerHTML='<td>'+esc(t.id)+'</td><td>'+esc(t.type||'ssh')+'</td><td>'+esc(t.vps_id||'--')+'</td><td>'+esc(t.local)+'</td><td>'+esc((t.remote||[]).join(', '))+'</td><td>'+badge(t.state)+err+'</td>'; b.appendChild(tr); } }
function renderVps(list){ const b=document.getElementById('vps-body'); b.innerHTML=''; const sel=document.getElementById('pub-vps'); if(sel){ const cur=sel.value; sel.innerHTML=''; list.forEach(v=>{const o=document.createElement('option');o.value=v.id;o.textContent=v.id;sel.appendChild(o);}); if(cur) sel.value=cur; else if(list[0]) sel.value=list[0].id; } if(!list||!list.length){ b.innerHTML='<tr><td colspan=4 class="empty-state">sin VPS</td></tr>'; return; } for(const v of list){ const tr=document.createElement('tr'); tr.dataset.id=v.id; tr.dataset.host=v.host; tr.dataset.user=v.user; tr.dataset.port=v.port; tr.innerHTML='<td>'+esc(v.id)+'</td><td>'+esc(v.host)+'</td><td>'+esc(v.user)+'</td><td>'+esc(v.port)+'</td>'; b.appendChild(tr); } }
function renderAlerts(list){ const b=document.getElementById('alert-body'); b.innerHTML=''; if(!list||!list.length){ b.innerHTML='<tr><td colspan=2 class="empty-state">sin alertas</td></tr>'; return; } for(const a of list){ const tr=document.createElement('tr'); tr.innerHTML='<td>'+badge(a.severity==='error'?'down':a.severity)+'</td><td>'+esc(a.message)+'</td>'; b.appendChild(tr); } }
function appendEvent(ev){ const d=document.getElementById('events'); const div=document.createElement('div'); div.textContent=new Date(ev.ts*1000).toLocaleTimeString()+' '+esc(ev.type)+(ev.detail?' '+esc(ev.detail):''); d.prepend(div); while(d.children.length>100) d.removeChild(d.lastChild); if(d.classList.contains('empty-state')) d.classList.remove('empty-state'); }
function renderEvents(list){ const d=document.getElementById('events'); d.innerHTML=''; if(!list||!list.length){ d.innerHTML='Sin eventos'; d.classList.add('empty-state'); return; } d.classList.remove('empty-state'); for(const e of list.slice().reverse()){ const div=document.createElement('div'); div.textContent=new Date(e.ts*1000).toLocaleTimeString()+' '+esc(e.type)+(e.detail?' '+esc(e.detail):''); d.appendChild(div); } }
function renderAll(data){
  const s=data.status||data;
  const distros=s.distros||[];
  const running=distros.filter(d=>d.running).length;
  const tunnelsrunning=(s.tunnels||[]).filter(t=>t.state==='running').length;
  document.getElementById('sub').textContent='distros: '+running+'/'+distros.length+' | tunnels: '+tunnelsrunning+'/'+(s.tunnels||[]).length+' | '+new Date().toLocaleTimeString();
  document.getElementById('header-status').textContent=s.wsl_hung?'WSL no responde':('distros '+running+'/'+distros.length+' · tuneles '+tunnelsrunning+'/'+(s.tunnels||[]).length);
  renderDistros(distros, s.keepalive||data.keepalive); renderForwards(s.forwards||[]); renderTunnels(s.tunnels||[]); renderAlerts(data.alerts||[]); if(data.vps) renderVps(data.vps);
}
async function refresh(){ try{ const d=await api('/api/v1/state'); if(!d.ok && d.error) throw new Error(d.error); renderAll(d); }catch(e){ if(!e.message.includes('No autorizado') && !e.message.includes('Rate limited')) document.getElementById('sub').textContent='error: '+e.message; } }
async function refreshEvents(){ try{ const d=await api('/api/v1/events?limit=50'); renderEvents(d.events||[]); }catch(e){} }
let WS=null; let wsTries=0;
function connectWS(){
  const proto=location.protocol==='https:'?'wss:':'ws:';
  const url=proto+'//'+location.host+'/ws?token='+encodeURIComponent(TOKEN);
  try{ WS=new WebSocket(url); }catch(e){ setTimeout(connectWS, 5000); return; }
  WS.onopen=()=>{ document.getElementById('ws-dot').className='ws-status ws-on'; document.getElementById('ws-status').textContent='WS'; document.getElementById('ws-indicator').style.background='var(--ok)'; wsTries=0; };
  WS.onclose=()=>{ document.getElementById('ws-dot').className='ws-status ws-off'; document.getElementById('ws-status').textContent=''; document.getElementById('ws-indicator').style.background='var(--err)'; WS=null; wsTries++; if(TERM_ON){ TERM_ON=false; termOut('\n! conexion perdida, terminal cerrada\n'); } termSetState('cerrada (sin WS)', false); setTimeout(connectWS, Math.min(3000*wsTries, 15000)); };
  WS.onerror=()=>{ try{WS.close();}catch(e){} };
  WS.onmessage=(e)=>{
    try{
      const msg=JSON.parse(e.data);
      if(msg.type==='state'){ renderAll(msg.data); }
      else if(msg.type==='event'){ appendEvent(msg.data); }
      else if(msg.type==='toast'){ toast(msg.message, msg.kind||'info'); activity(msg.message, msg.kind||'info'); }
      else if(msg.type==='refresh'){ refresh(); refreshEvents(); }
      else if(msg.type==='term_out'){ termOut(msg.data||''); }
      else if(msg.type==='term_exit'){ termOut('[exit '+msg.code+']\n'); }
      else if(msg.type==='term_status'){
        if(msg.state==='running'){ termSetState('terminal: '+(msg.distro||'')+(msg.cwd?' · '+msg.cwd:''), true); termOut('$ terminal lista en '+(msg.cwd||'/')+'\n'); }
        else { termSetState(msg.state==='error'?'error':'cerrada', false); if(msg.message) termOut('! '+msg.message+'\n'); }
      }
    }catch(err){}
  };
}
function renderMcpStatus(data){
  const st=document.getElementById('mcp-status'); if(!st) return;
  if (data.http_running) {
    st.innerHTML='<span style="color:var(--ok)">● Servidor MCP HTTP corriendo en 127.0.0.1:'+esc(String(data.http_port))+'/mcp</span>';
  } else if (data.settings && data.settings.enabled && (data.settings.transport||'stdio')==='http') {
    st.innerHTML='<span style="color:var(--err)">● MCP habilitado pero el servidor NO esta corriendo — pulsa "Aplicar Configuracion" o revisa que el puerto este libre</span>';
  } else {
    st.innerHTML='<span class="muted">● Servidor MCP detenido</span>';
  }
}
function loadMcpSettings() {
  api('/api/v1/mcp/settings').then(data => {
    if (data.ok) {
      renderMcpStatus(data);
      document.getElementById('mcp-enabled').checked = data.settings.enabled;
      document.getElementById('mcp-transport').value = data.settings.transport || 'stdio';
      document.getElementById('mcp-port').value = data.settings.port || 8796;
      document.getElementById('mcp-token-required').checked = data.settings.token_required;
      document.getElementById('mcp-expose-exec').checked = data.settings.expose_exec !== false;
      document.getElementById('mcp-token').value = data.settings.token || '';
      
      // Cargar configuración de exportación al VPS
      document.getElementById('mcp-vps-export-enabled').checked = data.settings.vps_export_enabled;
      document.getElementById('mcp-vps-target-port').value = data.settings.vps_target_port || 55872;
      
      // Actualizar lista de VPS en el selector
      const vpsSelector = document.getElementById('mcp-vps-target-host');
      vpsSelector.innerHTML = '<option value="">Seleccionar VPS...</option>';
      if (data.vps_list && Array.isArray(data.vps_list)) {
        data.vps_list.forEach(vps => {
          const option = document.createElement('option');
          option.value = vps.id;
          option.textContent = `${vps.id} (${vps.host}:${vps.port})`;
          vpsSelector.appendChild(option);
        });
        // Seleccionar el VPS actual si existe
        if (data.settings.vps_target_host) {
          vpsSelector.value = data.settings.vps_target_host;
        }
      }
    }
  }).catch(e => {
    console.error('Error cargando configuración MCP:', e);
    toast('Error cargando configuración MCP', 'err');
  });
}

function saveMcpSettings() {
  const settings = {
    enabled: document.getElementById('mcp-enabled').checked,
    transport: document.getElementById('mcp-transport').value,
    port: parseInt(document.getElementById('mcp-port').value),
    token_required: document.getElementById('mcp-token-required').checked,
    token: document.getElementById('mcp-token').value,
    expose_exec: document.getElementById('mcp-expose-exec').checked,
    vps_export_enabled: document.getElementById('mcp-vps-export-enabled').checked,
    vps_target_port: parseInt(document.getElementById('mcp-vps-target-port').value),
    vps_target_host: document.getElementById('mcp-vps-target-host').value
  };
  activity('Guardando...','info');
  api('/api/v1/mcp/settings',{method:'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify(settings)}).then(d=>{
    if (d.ok) {
      let msg = 'Configuración MCP guardada';
      if (d.export && d.export.public) msg += ' · túnel → ' + d.export.public;
      toast(msg, 'ok');
      activity(msg, 'success');
      if (d.export && d.export.warning) { toast(d.export.warning, 'warn'); activity(d.export.warning, 'warning'); }
    } else {
      toast('Error: ' + (d.error || 'guardando configuración'), 'err');
      activity('Error: ' + (d.error || 'guardando configuración'), 'error');
    }
    setTimeout(loadMcpSettings, 700);
    setTimeout(refresh, 2500);
  }).catch(e => {
    toast('Error guardando configuración: ' + e.message, 'err');
    activity('Error guardando configuración: ' + e.message, 'error');
  });
}

function applyMcpSettings() {
  activity('Aplicando...','info');
  api('/api/v1/mcp/apply',{method:'POST'}).then(d=>{
    if (d.ok) {
      let msg = 'Configuración MCP aplicada';
      if (d.mcp_http_running===false) msg += ' (servidor HTTP no corre)';
      if (d.public) msg += ' · público: ' + d.public;
      toast(msg + (d.warning? ' · '+d.warning : ''), d.warning?'warn':'ok');
      activity(msg, d.warning?'warning':'success');
    } else {
      toast('Error: ' + (d.error || 'aplicando configuración'), 'err');
      activity('Error: ' + (d.error || 'aplicando configuración'), 'error');
    }
    refresh();
    setTimeout(loadMcpSettings, 1200);
  }).catch(e => {
    toast('Error aplicando configuración: ' + e.message, 'err');
    activity('Error aplicando configuración: ' + e.message, 'error');
  });
}

function generateMcptoken() {
  // Generar token aleatorio de 32 caracteres
  const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
  let token = '';
  for (let i = 0; i < 32; i++) {
    token += chars.charAt(Math.floor(Math.random() * chars.length));
  }
  document.getElementById('mcp-token').value = token;
  toast('Token generado', 'ok');
}

function copyMcptoken() {
  const token = document.getElementById('mcp-token').value;
  if (!token) {
    toast('No hay token para copiar', 'warn');
    return;
  }
  navigator.clipboard.writeText(token).then(() => {
    toast('Token copiado al portapapeles', 'ok');
  }).catch(err => {
    toast('Error copiando token: ' + err, 'err');
  });
}

decoratePw(document);
setTimeout(connectWS, 400);
setTimeout(()=>{ if(!WS || WS.readyState!==1){ refresh(); refreshEvents(); }}, 3000);
setInterval(()=>{ if(!WS || WS.readyState!==1) refresh(); }, 15000);
setInterval(()=>{ if(!WS || WS.readyState!==1) refreshEvents(); }, 20000);
refresh(); refreshEvents();
</script>
</body>
</html>

"""

LOGIN_HTML = r"""<!DOCTYPE html>
<html lang="es">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Login - wsl-port</title>
<style>
  :root { --bg:#0f1419; --card:#1a2130; --card2:#1e2738; --line:#2d3748; --text:#e6edf3; --muted:#8b95a5; --accent:#00d4ff; --ok:#00c853; --warn:#ff9100; --err:#ff1744; --info:#2196f3; }
  * { box-sizing:border-box; }
  body { margin:0; font-family:'Segoe UI',system-ui,sans-serif; background:var(--bg); color:var(--text); min-height:100vh; display:flex; align-items:center; justify-content:center; padding:16px; }
  .card { background:var(--card); border:1px solid var(--line); border-radius:12px; padding:28px; width:100%; max-width:380px; box-shadow:0 8px 32px rgba(0,0,0,.4); }
  h1 { font-size:20px; margin:0 0 4px; color:var(--accent); font-weight:600; }
  .sub { color:var(--muted); font-size:13px; margin-bottom:20px; }
  input { width:100%; padding:10px 12px; border-radius:6px; border:1px solid var(--line); background:var(--bg); color:var(--text); font-size:14px; margin-bottom:14px; box-sizing:border-box; }
  input:focus { outline:none; border-color:var(--accent); box-shadow:0 0 0 3px rgba(0,212,255,.15); }
  .pw-wrap { position:relative; display:block; margin-bottom:14px; }
  .pw-wrap > input { padding-right:42px; margin-bottom:0; }
  .pw-eye { position:absolute; right:4px; top:50%; transform:translateY(-50%); width:auto !important; background:transparent !important; border:0; color:var(--muted); padding:6px; display:flex; align-items:center; line-height:0; }
  .pw-eye:hover { color:var(--accent); filter:none; transform:translateY(-50%); }
  .pw-eye svg { width:18px; height:18px; }
  button { width:100%; background:#2563eb; border:0; color:#fff; padding:10px 12px; border-radius:6px; cursor:pointer; font-size:14px; font-weight:500; transition:all .15s; }
  button:hover { filter:brightness(1.2); transform:translateY(-1px); }
  button:disabled { opacity:.5; cursor:not-allowed; transform:none; }
  #msg { font-size:13px; margin-top:12px; min-height:20px; text-align:center; }
  #msg.err { color:var(--err); }
  #msg.ok { color:var(--ok); }
  .logo { text-align:center; margin-bottom:16px; font-size:32px; }
</style>
</head>
<body>
<div class="card">
  <div class="logo">🌐</div>
  <h1>wsl-port</h1>
  <div class="sub">Panel web — introduce el token de acceso</div>
  <span class="pw-wrap"><input id="token" type="password" placeholder="Token" autocomplete="current-password"><button type="button" class="pw-eye" id="eye" title="Mostrar"></button></span>
  <button id="btn">Entrar</button>
  <div id="msg"></div>
</div>
<script>
function setMsg(text, cls){
  const el=document.getElementById('msg');
  el.textContent=text;
  el.className=cls||'';
}
const EYE_SVG='<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"/><circle cx="12" cy="12" r="3"/></svg>';
const EYE_OFF_SVG='<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M17.94 17.94A10.07 10.07 0 0 1 12 20c-7 0-11-8-11-8a18.45 18.45 0 0 1 5.06-5.94M9.9 4.24A9.12 9.12 0 0 1 12 4c7 0 11 8 11 8a18.5 18.5 0 0 1-2.16 3.19"/><path d="M14.12 14.12a3 3 0 1 1-4.24-4.24"/><line x1="1" y1="1" x2="23" y2="23"/></svg>';
(function(){
  const inp=document.getElementById('token'), eye=document.getElementById('eye');
  eye.innerHTML=EYE_SVG;
  eye.onclick=function(){
    const show=inp.type==='password';
    inp.type=show?'text':'password';
    eye.innerHTML=show?EYE_OFF_SVG:EYE_SVG;
    eye.title=show?'Ocultar':'Mostrar';
    inp.focus();
  };
})();
async function doLogin(){
  const token=document.getElementById('token').value.trim();
  if(!token){ setMsg('Introduce el token','err'); return; }
  const btn=document.getElementById('btn');
  btn.disabled=true;
  setMsg('Verificando...','');
  try{
    const r=await fetch('/api/v1/login', {method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify({token})});
    const d=await r.json();
    if(r.status===429){
      setMsg(d.error||'Demasiados intentos, espera','err');
      const retry=r.headers.get('Retry-After');
      if(retry) setMsg('Bloqueado '+retry+'s por demasiados intentos','err');
      btn.disabled=false;
      return;
    }
    if(!r.ok || !d.ok){
      const remaining=r.headers.get('X-RateLimit-Remaining');
      let msg=d.error||'Token invalido';
      if(remaining!==null) msg+=' ('+remaining+' intentos restantes)';
      setMsg(msg,'err');
      btn.disabled=false;
      return;
    }
    localStorage.setItem('pf_token', token);
    setMsg('Login correcto, redirigiendo...','ok');
    setTimeout(()=>{ window.location.href='/'; }, 600);
  }catch(e){
    setMsg('Error: '+e.message,'err');
    btn.disabled=false;
  }
}
document.getElementById('token').addEventListener('keydown', e=>{ if(e.key==='Enter') doLogin(); });
document.getElementById('btn').addEventListener('click', doLogin);
</script>
</body>
</html>
"""
