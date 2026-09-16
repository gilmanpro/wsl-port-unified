"""SshTunnelProvider: tunnels SSH reversos hacia VPS (seccion 9 del plan).

Comando (9.2, multi-puerto T4), con autossh si esta disponible:
  autossh -M 0 -N -T -o ServerAliveInterval=30 -o ServerAliveCountMax=3 \\
      -o TCPKeepAlive=yes -o ExitOnForwardFailure=yes -o ConnectTimeout=10 \\
      -R 0.0.0.0:80:127.0.0.1:3000 -R 0.0.0.0:443:127.0.0.1:3000 user@vps

- autossh se usa automaticamente si esta en el PATH (o si se indica
  `windows.autossh_exe`); si no, cae a `ssh` (mismo keepalive).
- start(): Popen sin ventana, stdout/stderr a archivo por tunnel en logs_dir.
- stop(): terminate -> kill; fallback: matar procesos ssh con el mismo
  patron de linea de comandos (tunnels huerfanos).
- is_alive(): proceso vivo + (opcional) health gate TCP al local_bind.
- Estado persistido en pidfile (data_dir/tunnels/<id>.pid).
"""

from __future__ import annotations

import os
import re
import shutil
import signal
import socket
import subprocess
import sys
import time
from pathlib import Path
from typing import Any

from wsl_port.vendor.port_forwarder.core.config import Tunnel, Vps
from wsl_port.vendor.port_forwarder.utils import subprocess_async as sp

_SSH_CMD_PATTERN = re.compile(r"-R\s+\S+:\d+:\S+:\d+")


class SshTunnelError(Exception):
    pass


class SshTunnelProvider:
    def __init__(
        self,
        ssh_exe: str | None = None,
        pid_dir: str | Path | None = None,
        log_dir: str | Path | None = None,
        autossh_exe: str | None = None,
        use_autossh: bool | None = None,
    ) -> None:
        import sys as _sys

        if ssh_exe is None:
            ssh_exe = (r"C:\Windows\System32\OpenSSH\ssh.exe"
                       if _sys.platform == "win32" else "ssh")
        self.ssh_exe = ssh_exe
        self.autossh_exe = (autossh_exe or "").strip()
        self.use_autossh = use_autossh  # None = auto-detectar
        from wsl_port.vendor.port_forwarder.utils import path as paths

        self.pid_dir = Path(pid_dir) if pid_dir else paths.data_dir() / "tunnels"
        self.pid_dir.mkdir(parents=True, exist_ok=True)
        self.log_dir = Path(log_dir) if log_dir else paths.logs_dir()
        self.log_dir.mkdir(parents=True, exist_ok=True)
        self._procs: dict[str, subprocess.Popen] = {}

    # -- autossh / ssh ---------------------------------------------------------

    def _autossh_bin(self) -> str | None:
        """Devuelve la ruta de autossh a usar, o None si no hay."""
        if self.autossh_exe:
            return self.autossh_exe
        found = shutil.which("autossh")
        return found

    def _use_autossh(self) -> bool:
        if self.use_autossh is not None:
            return bool(self.use_autossh)
        return self._autossh_bin() is not None

    # -- construccion del comando (visible para tests, 9.1) -------------------

    @staticmethod
    def _askpass_script() -> str:
        """Helper para autenticacion por CONTRASENA (SSH_ASKPASS).

        ssh no acepta la clave por linea de comandos; usa SSH_ASKPASS: un
        programa que imprime la contrasena. Windows: .cmd; Linux: .sh.
        """
        import stat
        import sys as _sys
        import tempfile

        tempdir = Path(tempfile.gettempdir())
        if _sys.platform == "win32":
            path = tempdir / "port-forwarder-askpass.cmd"
            if not path.exists():
                path.write_text(
                    "@echo off\r\necho %PF_ASKPASS_PW%\r\n", encoding="ascii"
                )
            return str(path)
        path = tempdir / "port-forwarder-askpass.sh"
        if not path.exists():
            path.write_text(
                "#!/bin/sh\nprintf '%s\\n' \"$PF_ASKPASS_PW\"\n",
                encoding="ascii",
            )
            path.chmod(stat.S_IRUSR | stat.S_IWUSR | stat.S_IXUSR)
        return str(path)

    def _password_env(self, vps: Vps) -> dict[str, str] | None:
        if not vps.password:
            return None
        return {
            "SSH_ASKPASS": self._askpass_script(),
            "SSH_ASKPASS_REQUIRE": "force",
            "PF_ASKPASS_PW": vps.password,
        }

    def build_command(self, tunnel: Tunnel, vps: Vps | None = None) -> list[str]:
        if tunnel.type != "ssh":
            raise SshTunnelError(
                f"tunnel '{tunnel.id}': tipo '{tunnel.type}' no soportado (P0: ssh)"
            )
        if vps is None:
            raise SshTunnelError(f"tunnel '{tunnel.id}': VPS desconocido")

        if self._use_autossh():
            cmd = [self._autossh_bin() or "autossh", "-M", "0"]
        else:
            cmd = [self.ssh_exe]
        cmd += [
            "-N",
            "-T",
            "-o", f"ServerAliveInterval={tunnel.keepalive_interval}",
            "-o", f"ServerAliveCountMax={tunnel.keepalive_count}",
            "-o", "TCPKeepAlive=yes",
            "-o", "ExitOnForwardFailure=yes",
            "-o", "StrictHostKeyChecking=accept-new",
            "-o", "ConnectTimeout=10",
        ]
        if vps.password:
            if vps.identity_file:
                cmd += ["-i", vps.identity_file]
                cmd += ["-o", "PreferredAuthentications=publickey,password,keyboard-interactive"]
            else:
                cmd += ["-o", "PreferredAuthentications=password,keyboard-interactive"]
        if tunnel.jump:  # multi-hop T10 (P2)
            cmd += ["-o", f"ProxyJump={tunnel.jump}"]
        for b in tunnel.remote_binds:
            cmd += ["-R", f"{b.host}:{b.port}:{tunnel.ssh_dest}"]
        cmd += [f"{vps.user}@{vps.host}", "-p", str(vps.port)]
        return cmd

    # -- ciclo de vida --------------------------------------------------------

    def _pidfile(self, tunnel_id: str) -> Path:
        return self.pid_dir / f"{tunnel_id}.pid"

    def _logfile(self, tunnel_id: str) -> Path:
        return self.log_dir / f"tunnel-{tunnel_id}.log"

    def start(self, tunnel: Tunnel, vps: Vps | None = None) -> subprocess.Popen:
        cmd = self.build_command(tunnel, vps)
        logf = open(self._logfile(tunnel.id), "ab", buffering=0)
        extra = self._password_env(vps) if vps is not None else None
        env = dict(os.environ, **(extra or {}))
        try:
            proc = subprocess.Popen(
                cmd,
                stdout=logf,
                stderr=logf,
                stdin=subprocess.DEVNULL,
                # DETACHED_PROCESS: desacopla el tunel de la consola del
                # proceso que lo lanza, para que siga vivo aunque el CLI
                # 'tunnels start' (o el supervisor) salga.
                creationflags=sp.DETACHED_PROCESS,
                env=env,
            )
        except OSError as e:
            logf.close()
            raise SshTunnelError(f"no se pudo lanzar ssh: {e}") from e
        self._procs[tunnel.id] = proc
        self._pidfile(tunnel.id).write_text(str(proc.pid), encoding="utf-8")
        return proc

    def stop(self, tunnel: Tunnel) -> None:
        proc = self._procs.pop(tunnel.id, None)
        pid = self._read_pid(tunnel.id)
        if proc is not None and proc.poll() is None:
            self._kill(proc)
        elif pid:
            # Proceso huerfano (supervisor reiniciado): matar por PID.
            try:
                os.kill(pid, signal.SIGTERM)
            except (OSError, SystemError):
                pass
        # Fallback: matar cualquier ssh con este patron -R (duplicados).
        self._kill_by_pattern(tunnel)
        self._pidfile(tunnel.id).unlink(missing_ok=True)

    def _kill(self, proc: subprocess.Popen) -> None:
        try:
            proc.terminate()
            proc.wait(timeout=5)
        except (subprocess.TimeoutExpired, OSError):
            try:
                proc.kill()
            except OSError:
                pass

    def _read_pid(self, tunnel_id: str) -> int | None:
        pf = self._pidfile(tunnel_id)
        if not pf.exists():
            return None
        try:
            return int(pf.read_text(encoding="utf-8").strip())
        except ValueError:
            return None

    def _cmd_matches(self, tunnel: Tunnel, cmdline: str) -> bool:
        """True si la linea de comandos tiene un -R de este tunnel
        (bind:rport:lhost:lport con rport remoto y lport local)."""
        if "-R " not in cmdline:
            return False
        rports = {b.port for b in tunnel.remote_binds}
        for m in re.finditer(r"-R\s+\S+", cmdline):
            spec = m.group(0).split(None, 1)[-1]
            parts = spec.split(":")
            if len(parts) >= 4:
                try:
                    rport = int(parts[1])
                    lport = int(parts[3])
                except ValueError:
                    continue
                if rport in rports and lport == tunnel.local_bind.port:
                    return True
        return False

    def _matching_ssh_pids(self, tunnel: Tunnel) -> list[int]:
        """PIDs de procesos ssh.exe vivos cuyo comando coincide con este
        tunnel (-R <local_port> + uno de los puertos remotos)."""
        try:
            proc = sp.run(
                ["powershell.exe", "-NoProfile", "-Command",
                 "Get-CimInstance Win32_Process -Filter \"Name='ssh.exe'\" | "
                 "Select-Object ProcessId,CommandLine | ConvertTo-Json -Compress"],
                timeout=30.0,
                check=False,
            )
        except OSError:
            return []
        if proc.returncode != 0 or not proc.stdout.strip():
            return []
        import json as _json

        try:
            data = _json.loads(proc.stdout)
        except _json.JSONDecodeError:
            return []
        items = data if isinstance(data, list) else [data]
        pids: list[int] = []
        for item in items:
            cl = str(item.get("CommandLine") or "")
            pid = item.get("ProcessId")
            if pid and self._cmd_matches(tunnel, cl):
                pids.append(int(pid))
        return pids

    def _kill_by_pattern(self, tunnel: Tunnel) -> None:
        """Mata procesos ssh.exe cuya linea de comandos contiene -R de este
        tunnel (destino local + uno de los puertos remotos)."""
        for pid in self._matching_ssh_pids(tunnel):
            try:
                os.kill(pid, signal.SIGTERM)
            except (OSError, ValueError, SystemError):
                pass

    # -- estado ---------------------------------------------------------------

    def is_process_alive(self, tunnel: Tunnel) -> bool:
        """Solo el proceso ssh (sin health gate). Evita que el supervisor
        relance un tunnel cuyo cliente esta vivo pero cuyo servicio local
        tarda en responder (esa carrera creaba ssh duplicados peleandose
        por el puerto remoto: flapping running/down)."""
        proc = self._procs.get(tunnel.id)
        if proc is not None:
            if proc.poll() is None:
                return True
            self._procs.pop(tunnel.id, None)
        pid = self._read_pid(tunnel.id)
        if pid is not None and self._pid_alive(pid):
            return True
        return bool(self._matching_ssh_pids(tunnel))

    def is_alive(self, tunnel: Tunnel) -> bool:
        """Proceso vivo (+ health gate del servicio local, T5)."""
        if not self.is_process_alive(tunnel):
            return False
        return self._gate_ok(tunnel)

    def _pid_alive(self, pid: int) -> bool:
        # Windows: os.kill(pid, 0) NO es fiable para comprobar vida (lanza
        # WinError 87 incluso para procesos vivos), lo que hacia que el
        # supervisor creyera muertos a tuneles sanos y los relanzara en
        # bucle (flapping). Usar la API nativa no-destructiva.
        if sys.platform == "win32":
            try:
                import ctypes
                from ctypes import wintypes

                PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
                STILL_ACTIVE = 259
                kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
                handle = kernel32.OpenProcess(
                    PROCESS_QUERY_LIMITED_INFORMATION, False, wintypes.DWORD(pid))
                if not handle:
                    return False  # proceso inexistente
                try:
                    code = wintypes.DWORD()
                    if kernel32.GetExitCodeProcess(
                            handle, ctypes.byref(code)):
                        return code.value == STILL_ACTIVE
                    return True
                finally:
                    kernel32.CloseHandle(wintypes.HANDLE(handle))
            except Exception:  # noqa: BLE001 - a lo seguro: no matar por dudoso
                return True
        try:
            os.kill(pid, 0)
            return True
        except (OSError, SystemError):
            return False

    def _gate_ok(self, tunnel: Tunnel) -> bool:
        """Health gate T5: test TCP al local_bind; sin servicio no cuenta vivo."""
        if not tunnel.health_gate.enabled:
            return True
        try:
            with socket.create_connection(
                (tunnel.local_bind.host, tunnel.local_bind.port), timeout=2.0
            ):
                return True
        except OSError:
            return False

    # -- diagnostico de fallos ----------------------------------------------------

    #: patrones (regex, razon) sobre el log ssh/autossh, en orden de prioridad
    _ERROR_PATTERNS: list[tuple[str, str]] = [
        (r"REMOTE HOST IDENTIFICATION HAS CHANGED",
         "el host key del VPS cambio (conflicto o MITM; borralo de known_hosts)"),
        (r"Host key verification failed",
         "host key del VPS no verificado"),
        (r"Permission denied \(publickey[^)]*\)",
         "autenticacion SSH rechazada: la clave/contrasena no es valida en el VPS"),
        (r"Too many authentication failures",
         "demasiados intentos de autenticacion SSH"),
        (r"Permission denied",
         "autenticacion SSH rechazada (clave o contrasena invalidas)"),
        (r"no matching (user auth|key exchange method|host key type|cipher)",
         "negociacion SSH fallida con el VPS (algoritmos incompatibles)"),
        (r"kex_exchange_identification",
         "intercambio de claves SSH fallido (kex)"),
        (r"Unable to negotiate",
         "negociacion SSH fallida con el VPS (algoritmos incompatibles)"),
        (r"bind [^\n]*Address already in use",
         "el puerto remoto ya esta en uso en el VPS"),
        (r"remote (port )?forwarding failed|Error: remote bind operation failed",
         "el VPS rechazo el reenvio del puerto remoto (revisa GatewayPorts en sshd)"),
        (r"Could not resolve hostname|Name or service not known|getaddrinfo",
         "no se puede resolver el host del VPS"),
        (r"Connection refused",
         "el VPS rechazo la conexion (puerto SSH cerrado o firewall)"),
        (r"(Connection|Operation) timed out|timed out connecting",
         "VPS inalcanzable (timeout de conexion)"),
        (r"Network is unreachable|No route to host",
         "sin ruta de red al VPS"),
        (r"Connection reset by peer",
         "el VPS cerro la conexion de golpe (fail2ban/firewall?)"),
        (r"Connection closed by",
         "el VPS cerro la conexion"),
        (r"banner exchange",
         "handshake SSH interrumpido (banner exchange)"),
        (r"Cannot open session|session open failed",
         "el VPS rechazo abrir la sesion SSH"),
    ]

    def read_log_tail(self, tunnel_id: str, max_bytes: int = 8192) -> str:
        """Ultimos bytes del log del tunnel (stdout+stderr de ssh/autossh)."""
        path = self._logfile(tunnel_id)
        try:
            with open(path, "rb") as f:
                f.seek(0, os.SEEK_END)
                size = f.tell()
                f.seek(max(0, size - max_bytes))
                data = f.read()
        except OSError:
            return ""
        return data.decode("utf-8", errors="replace")

    def classify_error(self, text: str) -> str:
        for pattern, reason in self._ERROR_PATTERNS:
            if re.search(pattern, text, re.IGNORECASE):
                return reason
        return ""

    def failure_reason(self, tunnel: Tunnel) -> str | None:
        """Razon legible por la que el tunnel no esta arriba.

        Distingue: proceso vivo pero health gate caido vs. proceso muerto
        (clasifica el tail del log ssh/autossh). None si no hay diagnostico.
        """
        proc = self._procs.get(tunnel.id)
        pid = self._read_pid(tunnel.id)
        proc_alive = (proc is not None and proc.poll() is None) or \
                     (pid is not None and self._pid_alive(pid))
        if proc_alive:
            if not self._gate_ok(tunnel):
                return (f"ssh vivo pero el servicio local {tunnel.ssh_dest} "
                        "no escucha (health gate)")
            return None
        tail = self.read_log_tail(tunnel.id)
        # solo la ultima "sesion" del log: tras cada arranque autossh/ssh
        # vuelven a escribir; clasificar sobre el tail reciente evita que un
        # error viejo tape uno nuevo.
        lines = [ln.strip() for ln in tail.splitlines() if ln.strip()]
        if lines:
            cls = self.classify_error("\n".join(lines[-40:]))
            if cls:
                return cls
            return lines[-1][:200]
        rc = proc.poll() if proc is not None else None
        if rc is not None:
            return f"proceso ssh terminado (exit {rc}), sin log"
        return "nunca se lanzo el tunnel (sin log ni proceso)"

    # -- trafico por tunnel ----------------------------------------------------

    def _traffic_file(self, tunnel_id: str) -> Path:
        return self.pid_dir / f"{tunnel_id}.traffic.json"

    def _vps_session_bytes(self, vps: Vps) -> tuple[int, int] | None:
        """(rx, tx) acumulados de las sesiones sshd del tunnel en el VPS.

        Windows no expone contadores de red por proceso, asi que se leen los
        bytes acumulados de la sesion SSH en el propio VPS (ss -tin), que es
        quien transporta todo el trafico del tunnel.
        """
        import re as _re

        extra = self._password_env(vps)
        env = dict(os.environ, **(extra or {}))
        script = f"ss -tin state established sport = :{vps.port} 2>/dev/null"
        cmd = [
            self.ssh_exe, "-p", str(vps.port),
            "-o", "StrictHostKeyChecking=accept-new",
            "-o", "ConnectTimeout=10",
            "-o", "PreferredAuthentications=password,keyboard-interactive",
            f"{vps.user}@{vps.host}", script,
        ]
        try:
            proc = sp.run(cmd, env=env, timeout=25.0, check=False)
        except OSError:
            return None
        out = proc.stdout or ""
        # La sesion del tunnel es la de MAYOR acumulado (las sesiones de
        # medicion son nuevas y diminutas): evita contar la propia consulta.
        best = None
        for m in _re.finditer(r"bytes_sent:(\d+)[^\n]*bytes_received:(\d+)", out):
            tx_b = int(m.group(1))
            rx_b = int(m.group(2))
            if best is None or (tx_b + rx_b) > (best[0] + best[1]):
                best = (rx_b, tx_b)
        if best is None or best == (0, 0):
            return None
        return best

    def traffic(self, tunnel: Tunnel, vps: Vps | None = None) -> dict | None:
        """Bytes acumulados del tunnel (persistidos) + velocidad actual (B/s).

        Se leen los bytes acumulados de la sesion SSH en el VPS (ss -tin) y se
        acumulan localmente entre muestras para el total y la velocidad.
        Persistido en data_dir/tunnels/<id>.traffic.json.
        """
        import json as _json
        import time as _time

        if vps is None:
            return None
        stats_path = self._traffic_file(tunnel.id)
        stats: dict = {
            "rx_total": 0, "tx_total": 0,
            "prev_vps_rx": 0, "prev_vps_tx": 0, "last_ts": None,
        }
        if stats_path.exists():
            try:
                stats.update(_json.loads(stats_path.read_text(encoding="utf-8")))
            except (OSError, ValueError):
                pass

        pair = self._vps_session_bytes(vps)
        if pair is None:
            try:
                stats_path.write_text(_json.dumps(stats), encoding="utf-8")
            except OSError:
                pass
            return {
                "rx_bytes": int(stats.get("rx_total", 0)),
                "tx_bytes": int(stats.get("tx_total", 0)),
                "rx_rate_bps": 0,
                "tx_rate_bps": 0,
            }

        rx, tx = pair
        prev_rx = int(stats.get("prev_vps_rx", 0))
        prev_tx = int(stats.get("prev_vps_tx", 0))
        now = _time.time()
        last = stats.get("last_ts")
        dt = (now - float(last)) if last else None

        # Delta respecto al muestreo anterior. Si la sesion se reinicio
        # (el acumulado cae), contar los bytes de la nueva sesion.
        d_rx = max(0, rx - prev_rx) if rx >= prev_rx else rx
        d_tx = max(0, tx - prev_tx) if tx >= prev_tx else tx

        stats["rx_total"] = int(stats.get("rx_total", 0)) + d_rx
        stats["tx_total"] = int(stats.get("tx_total", 0)) + d_tx
        rx_rate = int(d_rx / dt) if dt and dt > 0 else 0
        tx_rate = int(d_tx / dt) if dt and dt > 0 else 0
        stats["rx_rate_bps"] = rx_rate
        stats["tx_rate_bps"] = tx_rate
        stats["prev_vps_rx"] = rx
        stats["prev_vps_tx"] = tx
        stats["last_ts"] = now
        try:
            stats_path.write_text(_json.dumps(stats), encoding="utf-8")
        except OSError:
            pass
        return {
            "rx_bytes": int(stats["rx_total"]),
            "tx_bytes": int(stats["tx_total"]),
            "rx_rate_bps": rx_rate,
            "tx_rate_bps": tx_rate,
        }

    def traffic_snapshot(self, tunnel: Tunnel) -> dict | None:
        """Ultimo muestreo persistido del tunnel, SIN abrir SSH al VPS.

        El supervisor muestrea periodicamente (traffic()); las lecturas
        (status, panel web, GUI, wsl-port) usan este snapshot para no generar
        conexiones SSH en cada refresco.
        """
        import json as _json

        stats_path = self._traffic_file(tunnel.id)
        if not stats_path.exists():
            return None
        try:
            stats = _json.loads(stats_path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return None
        return {
            "rx_bytes": int(stats.get("rx_total", 0)),
            "tx_bytes": int(stats.get("tx_total", 0)),
            "rx_rate_bps": int(stats.get("rx_rate_bps", 0)),
            "tx_rate_bps": int(stats.get("tx_rate_bps", 0)),
        }

    def restart(self, tunnel: Tunnel, vps: Vps | None = None) -> subprocess.Popen:
        self.stop(tunnel)
        time.sleep(0.5)
        return self.start(tunnel, vps)

    def latency(self, tunnel: Tunnel, vps: Vps | None = None) -> float | None:
        """Latencia SSH al VPS (T6, P2): tiempo de handshake con -o BatchMode."""
        try:
            t0 = time.monotonic()
            sp.run(
                self.build_command(tunnel, vps)
                + ["-o", "BatchMode=yes", "-o", "ExitOnForwardFailure=no",
                   "true"],
                timeout=15.0,
                check=False,
            )
            return round((time.monotonic() - t0) * 1000, 1)
        except (OSError, subprocess.TimeoutExpired):
            return None
