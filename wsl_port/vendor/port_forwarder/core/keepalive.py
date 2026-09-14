"""WSL siempre vivo: las distros nunca se apagan salvo boton explicito, y si
caen se levantan solas.

Las 3 capas:
  1. .wslconfig -> [wsl2] vmIdleTimeout=-1 (que WSL jamas apague la VM por
     inactividad). Se garantiza con ensure_wslconfig() una vez por arranque.
  2. Sesion persistente por distro: un proceso 'wsl.exe -d X --exec sh -c
     "sleep infinity"' que mantiene una sesion abierta -> el contador de
     idle de WSL nunca llega a cero aunque nadie use la distro.
  3. Watchdog (ciclo del supervisor): cada check_interval segundos lista las
     distros; cualquier 'Stopped' que NO este en keepalive.stopped_by_user se
     revive (y se re-asegura su holder).

Regla de usuario: parada tacita por boton = mark_user_stop(); arrancar
(Iniciar / Reiniciar / Encender todo / toggle auto) = mark_user_start().
"""
from __future__ import annotations

import logging
import os
import re
import subprocess
import sys
import threading
import time
from pathlib import Path
from typing import Any

log = logging.getLogger("port-forwarder.keepalive")

CREATE_NO_WINDOW = 0x08000000 if sys.platform == "win32" else 0
EXCLUDE_PREFIXES = ("docker-desktop",)
HOLDER_TAG = "#wsl-port-keepalive"

_LINE_RE = re.compile(r"^(?P<name>\S+|\S.*?\S)\s{2,}(?P<state>\w[\w ]*?)\s+\d+$")


def parse_wsl_list(text: str) -> dict[str, str]:
    """Parsea 'wsl --list --verbose' -> {nombre: Running|Stopped|...}."""
    out: dict[str, str] = {}
    for raw in text.splitlines():
        line = raw.strip().lstrip("*").strip()
        if not line or line.upper().startswith(("NAME", "NOMBRE")):
            continue
        m = _LINE_RE.match(line)
        if m:
            state = m.group("state").strip()
            if state in ("Running", "Stopped", "Installing", "Pending"):
                out[m.group("name")] = state
    return out


def _wslconfig_path() -> Path:
    return Path(os.path.expanduser("~")) / ".wslconfig"


def ensure_wslconfig(path: Path | None = None) -> bool:
    """Garantiza [wsl2] vmIdleTimeout=-1 en .wslconfig. True si hubo cambio.

    Hace backup .wslconfig.bak-keepalive una sola vez. Respeta el resto.
    """
    p = path or _wslconfig_path()
    try:
        text = p.read_text(encoding="utf-8") if p.exists() else ""
    except OSError as e:
        log.warning("keepalive: no se pudo leer %s: %s", p, e)
        return False
    lines = text.splitlines()
    idx = next((i for i, l in enumerate(lines)
                if l.strip().lower() == "[wsl2]"), None)
    if idx is not None:
        end = next((j for j in range(idx + 1, len(lines))
                    if lines[j].strip().startswith("[")), len(lines))
        if any(re.match(r"^\s*vmidletimeout\s*=\s*-1\s*$", l, re.I)
               for l in lines[idx + 1:end]):
            return False  # ya esta bien
        for j in range(idx + 1, end):
            if re.match(r"^\s*vmidletimeout\s*=", lines[j], re.I):
                lines[j] = "vmIdleTimeout=-1"
                break
        else:
            lines.insert(idx + 1, "vmIdleTimeout=-1")
    else:
        if lines and lines[-1].strip():
            lines.append("")
        lines.extend(["[wsl2]", "vmIdleTimeout=-1"])

    new_text = "\n".join(lines) + "\n"
    if new_text == text:
        return False
    try:
        if p.exists() and not p.with_suffix(".wslconfig.bak-keepalive").exists():
            p.with_suffix(".wslconfig.bak-keepalive").write_text(
                text, encoding="utf-8")
        p.write_text(new_text, encoding="utf-8")
        log.info("keepalive: .wslconfig actualizado (vmIdleTimeout=-1)")
        return True
    except OSError as e:
        log.warning("keepalive: no se pudo escribir %s: %s", p, e)
        return False


class DistroKeepalive:
    """Watchdog + holders de sesion para que ninguna distro se apague sola."""

    def __init__(self, store: Any, metrics: Any = None,
                 wsl_exe: str | None = None,
                 clock: Any = time.monotonic) -> None:
        self.store = store
        self.metrics = metrics
        self._wsl_exe = wsl_exe
        self.clock = clock
        self._holders: dict[str, subprocess.Popen] = {}
        self._lock = threading.Lock()
        self._last_check = 0.0
        self._wslconfig_done = False
        self._born = self.clock()
        self.revived_count = 0
        self.last_revived: dict[str, float] = {}

    # --------------------------- deseados ---------------------------

    @property
    def wsl_exe(self) -> str:
        return (self._wsl_exe
                or getattr(self.store.cfg.windows, "wsl_exe", "")
                or "wsl.exe")

    def _stopped_by_user(self) -> list[str]:
        return list(getattr(self.store.cfg.keepalive, "stopped_by_user", []))

    def mark_user_stop(self, name: str) -> None:
        """Boton Detener/Apagar-todo: excluye la distro del revive."""
        ka = self.store.cfg.keepalive
        if name not in ka.stopped_by_user:
            ka.stopped_by_user.append(name)
            try:
                self.store.save()
            except Exception:  # noqa: BLE001
                log.exception("keepalive: save tras mark_user_stop")

    def mark_user_start(self, name: str) -> None:
        """Boton Iniciar/Reiniciar/Encender-todo/auto: re-incluye en revive."""
        ka = self.store.cfg.keepalive
        if name in ka.stopped_by_user:
            ka.stopped_by_user = [n for n in ka.stopped_by_user if n != name]
            try:
                self.store.save()
            except Exception:  # noqa: BLE001
                log.exception("keepalive: save tras mark_user_start")

    def mark_all_stopped(self, names: list[str]) -> None:
        """Boton 'Apagar todo WSL': excluye todas las distros del revive."""
        ka = self.store.cfg.keepalive
        merged = sorted(set(ka.stopped_by_user) | set(names))
        if merged != ka.stopped_by_user:
            ka.stopped_by_user = merged
            try:
                self.store.save()
            except Exception:  # noqa: BLE001
                log.exception("keepalive: save tras mark_all_stopped")

    def clear_all_stops(self) -> None:
        """Boton 'Encender todo': quita todas las exclusiones."""
        ka = self.store.cfg.keepalive
        if ka.stopped_by_user:
            ka.stopped_by_user = []
            try:
                self.store.save()
            except Exception:  # noqa: BLE001
                log.exception("keepalive: save tras clear_all_stops")

    # --------------------------- wsl.exe ----------------------------

    def list_states(self) -> dict[str, str]:
        p = subprocess.run(
            [self.wsl_exe, "--list", "--verbose"],
            capture_output=True, timeout=20, creationflags=CREATE_NO_WINDOW)
        raw = p.stdout or b""
        if raw.startswith(b"\xff\xfe") or b"\x00" in raw[:64]:
            text = raw.decode("utf-16-le", errors="replace")
        else:
            text = raw.decode("utf-8", errors="replace")
        return parse_wsl_list(text)

    def _spawn(self, args: list[str]) -> subprocess.Popen:
        return subprocess.Popen(
            args, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            stdin=subprocess.DEVNULL, creationflags=CREATE_NO_WINDOW)

    def ensure_holder(self, name: str) -> None:
        """Capa 2: sesion 'sleep infinity' persistente (arranca la distro)."""
        with self._lock:
            if name in self._holders and self._holders[name].poll() is None:
                return
            try:
                self._holders[name] = self._spawn(
                    [self.wsl_exe, "-d", name, "--exec", "sh", "-c",
                     f"sleep infinity {HOLDER_TAG}"])
            except OSError as e:
                log.warning("keepalive: holder de '%s' no arranco: %s", name, e)

    def kill_holder(self, name: str) -> None:
        """Deja de retener una distro (para apagados tacitos y stops)."""
        with self._lock:
            h = self._holders.pop(name, None)
        if h is not None and h.poll() is None:
            try:
                h.terminate()
            except OSError:
                pass

    def is_holder_alive(self, name: str) -> bool:
        with self._lock:
            h = self._holders.get(name)
        return h is not None and h.poll() is None

    # --------------------------- ciclo -------------------------------

    def cycle(self) -> None:
        """Llamado por el loop del supervisor cada interval; auto-throttle."""
        ka = self.store.cfg.keepalive
        now = self.clock()
        if now - self._last_check < max(5, ka.check_interval_seconds):
            return
        self._last_check = now
        if sys.platform != "win32":
            return
        if not self._wslconfig_done:
            self._wslconfig_done = True
            try:
                ensure_wslconfig()
            except Exception:  # noqa: BLE001
                log.exception("keepalive: ensure_wslconfig")
            # holders de ejecuciones anteriores de la app: matar y recrear
            self._kill_orphan_holders()
        if not ka.enabled:
            return
        # Gracia de arranque: tras el login de Windows no se toca NADA de WSL
        # (ni revividos, ni holders, ni el --list). Varios wsl.exe de arranque
        # concurrentes es justo lo que atraviesa wslservice (colgado del
        # 14/09: 3 distros + probes hostname -I simultaneos al boot).
        grace = float(getattr(ka, "startup_grace_seconds", 60))
        if now - self._born < grace:
            return
        try:
            states = self.list_states()
        except (OSError, subprocess.SubprocessError) as e:
            log.warning("keepalive: wsl --list fallo: %s", e)
            return
        # Revividos escalonados: maximo N arranques de distro por ciclo.
        budget = max(1, int(getattr(ka, "max_revives_per_cycle", 1)))
        for name, state in states.items():
            if name.lower().startswith(EXCLUDE_PREFIXES):
                continue
            if name in self._stopped_by_user():
                self.kill_holder(name)
                continue
            if state != "Running":
                if budget <= 0:
                    continue
                budget -= 1
                self.revive(name)
            else:
                self.ensure_holder(name)

    def _kill_orphan_holders(self) -> None:
        """Mata 'wsl.exe --exec sh -c sleep infinity #wsl-port-keepalive' de
        ejecuciones anteriores (la app murio sin limpiarlos)."""
        if sys.platform != "win32":
            return
        try:
            subprocess.run(
                ["powershell.exe", "-NoProfile", "-NonInteractive", "-Command",
                 "Get-CimInstance Win32_Process -Filter \"Name='wsl.exe'\" | "
                 "Where-Object { $_.CommandLine -like '*#wsl-port-keepalive*' } | "
                 "ForEach-Object { Stop-Process -Id $_.ProcessId -Force "
                 "-ErrorAction SilentlyContinue }"],
                capture_output=True, timeout=40,
                creationflags=CREATE_NO_WINDOW)
        except Exception:  # noqa: BLE001
            log.debug("keepalive: limpieza de holders huerfanos fallo",
                      exc_info=True)

    def revive(self, name: str) -> None:
        """Capa 3: distro caida (no pedida) -> arrancar + holder."""
        log.warning("keepalive: distro '%s' caida (Stopped) -> reviviendo",
                    name)
        if self.metrics is not None:
            try:
                self.metrics.record_event("keepalive_revive", distro=name)
            except Exception:  # noqa: BLE001
                pass
        self.revived_count += 1
        self.last_revived[name] = self.clock()
        self.ensure_holder(name)

    def kick(self) -> None:
        """Fuerza un ciclo inmediato (tras activar/en una proteccion nueva)."""
        self._last_check = 0.0
        self.cycle()

    def release_all(self) -> None:
        """Suelta todas las sesiones retenidas (desactivacion global)."""
        with self._lock:
            names = list(self._holders)
        for n in names:
            self.kill_holder(n)

    def protect(self, name: str) -> None:
        """Retener/arrancar una distro ya mismo (boton auto -> on)."""
        self.mark_user_start(name)
        self.ensure_holder(name)

    def status(self) -> dict[str, Any]:
        ka = self.store.cfg.keepalive
        return {
            "enabled": bool(ka.enabled),
            "stopped_by_user": list(ka.stopped_by_user),
            "holders": sorted(k for k, v in self._holders.items()
                              if v.poll() is None),
            "revived_count": self.revived_count,
        }
