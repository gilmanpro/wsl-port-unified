"""AppService: fachada operativa compartida por API REST y MCP.

Mismos providers que GUI/CLI (paridad garantizada, seccion 16). Cada metodo
devuelve dicts serializables {ok, data|error, message}. Los errores
funcionales se capturan aqui, no en el transporte.
"""

from __future__ import annotations

import time
from typing import Any

from wsl_port.vendor.port_forwarder.core.config import (
    Bind,
    ConfigError,
    ConfigStore,
    Forward,
    HealthCheck,
    ScheduleAction,
    ScheduleItem,
    Tunnel,
    TunnelHealthGate,
    Vps,
)
from wsl_port.vendor.port_forwarder.core.logger import get_logger
from wsl_port.vendor.port_forwarder.core.metrics_store import MetricsStore
from wsl_port.vendor.port_forwarder.core.profiles import Profiles
from wsl_port.vendor.port_forwarder.core.scheduler import WEEKDAYS
from wsl_port.vendor.port_forwarder.core.supervisor import Supervisor
from wsl_port.vendor.port_forwarder.providers.netsh_provider import NetshProvider
from wsl_port.vendor.port_forwarder.providers.ssh_tunnel_provider import SshTunnelError, SshTunnelProvider
from wsl_port.vendor.port_forwarder.providers.wsl_ip_provider import WslIpProvider

log = get_logger("port-forwarder.api")


class AppService:
    def __init__(
        self,
        store: ConfigStore | None = None,
        supervisor: Supervisor | None = None,
    ) -> None:
        self.store = store or ConfigStore()
        if supervisor is None:
            netsh = NetshProvider(
                netsh_exe=self.store.cfg.windows.netsh_exe or None
            )
            wsl = WslIpProvider(wsl_exe=self.store.cfg.windows.wsl_exe or None)
            ssh = SshTunnelProvider(ssh_exe=self.store.cfg.windows.ssh_exe or None,
                                    autossh_exe=self.store.cfg.windows.autossh_exe or None)
            metrics = MetricsStore()
            self.supervisor = Supervisor(
                self.store, netsh=netsh, wsl=wsl, ssh=ssh, metrics=metrics
            )
        else:
            self.supervisor = supervisor

    # -- helpers ---------------------------------------------------------------

    def _ok(self, data: Any = None, message: str = "") -> dict[str, Any]:
        return {"ok": True, "data": data, "message": message}

    def _err(self, message: str) -> dict[str, Any]:
        return {"ok": False, "data": None, "message": message}

    # -- status / health / doctor -------------------------------------------------

    def status(self) -> dict[str, Any]:
        return self._ok(self.supervisor.status())

    def health(self) -> dict[str, Any]:
        netsh = self.supervisor.netsh
        ssh = self.supervisor.ssh
        data: dict[str, Any] = {"forwards": [], "tunnels": [], "vps": []}
        for f in self.store.cfg.forwards:
            data["forwards"].append({
                "id": f.id, "listen_port": f.listen_port,
                "reachable": netsh.test_connection(f.listen_port, 2.0),
            })
        for t in self.store.cfg.tunnels:
            data["tunnels"].append({
                "id": t.id, "alive": ssh.is_alive(t),
            })
            vps = self.store.get_vps(t.vps_id)
            if vps and t.type == "ssh":
                data["vps"].append({
                    "id": vps.id, "host": vps.host,
                    "latency_ms": ssh.latency(t, vps),
                })
        return self._ok(data)

    # -- forwards ------------------------------------------------------------------

    def forwards_list(self) -> dict[str, Any]:
        rows = []
        for entry in self.supervisor.netsh.declared_forwards(self.store.cfg.forwards):
            rows.append(entry.as_dict())
        return self._ok(rows)

    def forwards_add(
        self,
        forward_id: str,
        listen_port: int,
        wsl_port: int,
        distro: str = "",
        listen_address: str = "0.0.0.0",
        protocol: str = "tcp",
        auto_apply: bool = False,
        health_check: bool = True,
    ) -> dict[str, Any]:
        try:
            fwd = Forward(
                id=forward_id, listen_port=listen_port,
                listen_address=listen_address, wsl_distro=distro,
                wsl_port=wsl_port, protocol=protocol,
                auto_apply=auto_apply,
                health_check=HealthCheck(enabled=health_check),
            )
            self.store.add_forward(fwd)
        except ConfigError as e:
            return self._err(str(e))
        ip = None
        if auto_apply:
            ip = self.supervisor.wsl.get_ip(distro)
            if not ip:
                self.store.remove_forward(fwd.id)
                return self._err(
                    f"no se encontro IP para la distro '{distro}'"
                )
            result = self.supervisor.netsh.add_forward(fwd, ip)
            if not result.ok:
                self.store.remove_forward(fwd.id)
                return self._err(result.error)
        return self._ok(
            {"id": fwd.id, "listen_port": listen_port, "ip": ip},
            f"forward '{fwd.id}' agregado",
        )

    def forwards_remove(self, forward_id: str) -> dict[str, Any]:
        try:
            fwd = self.store.remove_forward(forward_id)
        except ConfigError as e:
            return self._err(str(e))
        return self._ok({"id": fwd.id}, f"forward '{fwd.id}' eliminado")

    def forwards_apply(self, all_: bool = False) -> dict[str, Any]:
        targets = [f for f in self.store.cfg.forwards if all_ or f.auto_apply]
        if not targets:
            return self._ok(message="no hay forwards para aplicar")
        ips = self.supervisor.wsl.get_all_ips(
            list({f.wsl_distro for f in targets if f.wsl_distro})
        )
        results = []
        failed = 0
        for f in targets:
            ip = ips.get(f.wsl_distro)
            if not ip:
                results.append({"id": f.id, "ok": False,
                                "error": "distro sin IP"})
                failed += 1
                continue
            present = [x for x in self.supervisor.netsh.list_forwards()
                       if x.listen_port == f.listen_port]
            if present:
                self.supervisor.netsh.remove_forward(f)
            r = self.supervisor.netsh.add_forward(f, ip)
            results.append({"id": f.id, "ok": r.ok, "error": r.error or ""})
            failed += 0 if r.ok else 1
        return self._ok(results, "forwards aplicados" if not failed
                        else f"{failed} fallos")

    def forwards_clear(self) -> dict[str, Any]:
        results = self.supervisor.netsh.clear_all()
        failed = [r for r in results if not r.ok and r.error]
        return self._ok(
            {"operations": len(results), "failed": len(failed)},
            "forwards limpiados" if not failed else "hubo fallos",
        )

    def forwards_test(self, forward_id: str) -> dict[str, Any]:
        fwd = self.store.get_forward(forward_id)
        if not fwd:
            return self._err(f"forward '{forward_id}' no existe")
        ok = self.supervisor.netsh.test_connection(fwd.listen_port, 3.0)
        return self._ok({"id": fwd.id, "reachable": ok},
                        "conexion OK" if ok else "sin respuesta")

    def forwards_conflicts(self, port: int) -> dict[str, Any]:
        pids = self.supervisor.netsh.detect_conflicts(port)
        return self._ok({"port": port, "pids": pids})

    # -- tunnels -------------------------------------------------------------------

    def tunnels_add(self, tunnel_id: str, vps_id: str, local: str,
                    remote: list[str]) -> dict[str, Any]:
        try:
            host, port = local.rsplit(":", 1)
            local_bind = Bind(host=host, port=int(port))
            remotes = []
            for r in remote:
                rh, rp = r.rsplit(":", 1)
                remotes.append(Bind(host=rh, port=int(rp)))
            tun = Tunnel(
                id=tunnel_id, vps_id=vps_id, local_bind=local_bind,
                remote_binds=remotes,
                health_gate=TunnelHealthGate(enabled=True),
            )
            self.store.add_tunnel(tun)
        except ConfigError as e:
            return self._err(str(e))
        except ValueError as e:
            return self._err(f"bind invalido: {e}")
        return self._ok({"id": tun.id}, f"tunnel '{tun.id}' agregado")

    def tunnels_remove(self, tunnel_id: str) -> dict[str, Any]:
        t = self.store.get_tunnel(tunnel_id)
        if not t:
            return self._err(f"tunnel '{tunnel_id}' no existe")
        if self.supervisor.ssh.is_alive(t):
            self.supervisor.ssh.stop(t)
        try:
            self.store.remove_tunnel(tunnel_id)
        except ConfigError as e:
            return self._err(str(e))
        return self._ok({"id": tunnel_id}, f"tunnel '{tunnel_id}' eliminado")

    def tunnels_start_all(self) -> dict[str, Any]:
        started = []
        for t in self.store.cfg.tunnels:
            if t.auto_start and t.type == "ssh" and \
                    not self.supervisor.ssh.is_alive(t):
                vps = self.store.get_vps(t.vps_id)
                try:
                    self.supervisor.ssh.start(t, vps)
                    started.append(t.id)
                except SshTunnelError as e:
                    log.warning("tunnel %s no inicio: %s", t.id, e)
        return self._ok(started, f"{len(started)} tunnels iniciados")

    def tunnels_stop_all(self) -> dict[str, Any]:
        stopped = []
        for t in self.store.cfg.tunnels:
            if self.supervisor.ssh.is_alive(t):
                self.supervisor.ssh.stop(t)
                stopped.append(t.id)
        return self._ok(stopped, f"{len(stopped)} tunnels detenidos")

    def tunnels_list(self) -> dict[str, Any]:
        rows = []
        for t in self.store.cfg.tunnels:
            rows.append({
                "id": t.id, "type": t.type, "vps_id": t.vps_id,
                "local": t.ssh_dest if t.type == "ssh" else t.local_url,
                "remote": [f"{b.host}:{b.port}" for b in t.remote_binds],
                "auto_start": t.auto_start,
                "state": "running" if self.supervisor.ssh.is_alive(t) else "stopped",
            })
        return self._ok(rows)

    def tunnels_start(self, tunnel_id: str) -> dict[str, Any]:
        t = self.store.get_tunnel(tunnel_id)
        if not t:
            return self._err(f"tunnel '{tunnel_id}' no existe")
        vps = self.store.get_vps(t.vps_id)
        try:
            if not self.supervisor.ssh.is_alive(t):
                self.supervisor.ssh.start(t, vps)
        except SshTunnelError as e:
            return self._err(str(e))
        return self._ok({"id": t.id}, f"tunnel '{t.id}' iniciado")

    def tunnels_stop(self, tunnel_id: str) -> dict[str, Any]:
        t = self.store.get_tunnel(tunnel_id)
        if not t:
            return self._err(f"tunnel '{tunnel_id}' no existe")
        self.supervisor.ssh.stop(t)
        return self._ok({"id": t.id}, f"tunnel '{t.id}' detenido")

    def tunnels_restart(self, tunnel_id: str) -> dict[str, Any]:
        t = self.store.get_tunnel(tunnel_id)
        if not t:
            return self._err(f"tunnel '{tunnel_id}' no existe")
        vps = self.store.get_vps(t.vps_id)
        self.supervisor.ssh.restart(t, vps)
        return self._ok({"id": t.id}, f"tunnel '{t.id}' reiniciado")

    def tunnels_update(self, tunnel_id: str, **kwargs) -> dict[str, Any]:
        t = self.store.get_tunnel(tunnel_id)
        if not t:
            return self._err(f"tunnel '{tunnel_id}' no existe")
        try:
            if "local" in kwargs:
                host, port = kwargs.pop("local").rsplit(":", 1)
                kwargs["local_bind"] = Bind(host=host, port=int(port))
            if "remote" in kwargs:
                remotes = []
                for r in kwargs.pop("remote"):
                    rh, rp = r.rsplit(":", 1)
                    remotes.append(Bind(host=rh, port=int(rp)))
                kwargs["remote_binds"] = remotes
            if "vps_id" in kwargs:
                vps = self.store.get_vps(kwargs["vps_id"])
                if not vps:
                    return self._err(f"vps '{kwargs['vps_id']}' no existe")
            self.store.update_tunnel(tunnel_id, **kwargs)
        except ConfigError as e:
            return self._err(str(e))
        except ValueError as e:
            return self._err(f"valor invalido: {e}")
        return self._ok({"id": tunnel_id}, f"tunnel '{tunnel_id}' actualizado")

    # -- vps --------------------------------------------------------------------------

    def vps_list(self) -> dict[str, Any]:
        return self._ok([{"id": v.id, "host": v.host, "user": v.user,
                          "port": v.port, "identity_file": v.identity_file}
                         for v in self.store.cfg.vps_list])

    def vps_add(self, vps_id: str, host: str, user: str, port: int = 22,
                identity_file: str = "") -> dict[str, Any]:
        try:
            self.store.add_vps(Vps(id=vps_id, host=host, user=user,
                                   port=port, identity_file=identity_file))
        except ConfigError as e:
            return self._err(str(e))
        return self._ok({"id": vps_id}, f"vps '{vps_id}' agregado")

    def vps_remove(self, vps_id: str) -> dict[str, Any]:
        try:
            self.store.remove_vps(vps_id)
        except ConfigError as e:
            return self._err(str(e))
        return self._ok({"id": vps_id}, f"vps '{vps_id}' eliminado")

    # -- alerts / schedule / profiles ------------------------------------------------

    def alerts_list(self, state: str | None = None) -> dict[str, Any]:
        return self._ok(self.supervisor.metrics.list_alerts(state=state))

    def alerts_resolve(self, alert_id: int) -> dict[str, Any]:
        if not self.supervisor.metrics.resolve_alert(alert_id):
            return self._err(f"alerta #{alert_id} no existe")
        return self._ok({"id": alert_id}, f"alerta #{alert_id} resuelta")

    def schedule_list(self) -> dict[str, Any]:
        return self._ok([
            {"id": s.id, "name": s.name, "type": s.action.type,
             "time": (s.schedule or {}).get("time"),
             "days": (s.schedule or {}).get("days"),
             "enabled": s.enabled}
            for s in self.store.cfg.scheduler
        ])

    def schedule_add(self, name: str, action_type: str, time_: str,
                     days: str = "", tunnel: str | None = None,
                     profile: str | None = None) -> dict[str, Any]:
        import uuid

        days_list = [d.strip() for d in days.split(",") if d.strip()]
        bad = [d for d in days_list if d not in WEEKDAYS]
        if bad:
            return self._err(f"dias invalidos: {bad}")
        item = ScheduleItem(
            id=f"tarea-{uuid.uuid4().hex[:8]}",
            name=name,
            action=ScheduleAction(type=action_type, tunnel=tunnel,
                                  profile=profile),
            schedule={"days": days_list, "time": time_},
        )
        self.store.cfg.scheduler.append(item)
        self.store.save()
        return self._ok({"id": item.id}, f"tarea '{name}' programada")

    def schedule_remove(self, item_id: str) -> dict[str, Any]:
        before = len(self.store.cfg.scheduler)
        self.store.cfg.scheduler = [s for s in self.store.cfg.scheduler
                                    if s.id != item_id]
        if len(self.store.cfg.scheduler) == before:
            return self._err(f"tarea '{item_id}' no existe")
        self.store.save()
        return self._ok({"id": item_id}, f"tarea '{item_id}' eliminada")

    def profile_list(self) -> dict[str, Any]:
        return self._ok([{"name": p.name, "description": p.description,
                          "forwards": p.forwards, "tunnels": p.tunnels}
                         for p in Profiles(self.store, self.supervisor).list()])

    def profile_apply(self, name: str) -> dict[str, Any]:
        try:
            Profiles(self.store, self.supervisor).apply(name)
        except ValueError as e:
            return self._err(str(e))
        return self._ok({"name": name}, f"perfil '{name}' aplicado")

    def profile_capture(self, name: str, description: str = "") -> dict[str, Any]:
        p = Profiles(self.store, self.supervisor).capture(name, description)
        return self._ok({"name": p.name}, f"perfil '{p.name}' capturado")

    def secrets_check(self, ref: str) -> dict[str, Any]:
        from wsl_port.vendor.port_forwarder.utils.secrets import SecretsStore

        return self._ok({"ref": ref, "exists": SecretsStore().check(ref)})

    # -- WSL: distros + ejecucion de comandos (terminal remota) ----------------------------

    def wsl_distros_list(self) -> dict[str, Any]:
        """Lista distros WSL con estado (igual que el panel web)."""
        import subprocess

        from wsl_port.vendor.port_forwarder.web.server import WebPanel
        try:
            proc = subprocess.run(
                ["wsl.exe", "--list", "--verbose"],
                capture_output=True, timeout=10, creationflags=0x08000000,
            )
            if proc.returncode != 0:
                return self._err("WSL no responde")
            out = WebPanel._decode_wsl(proc.stdout)
            rows = []
            for line in out.splitlines():
                line = line.strip()
                if not line or "NAME" in line.upper() or "---" in line:
                    continue
                if line.startswith("*"):
                    line = line[1:].strip()
                cols = [p for p in line.split() if p]
                if len(cols) >= 3:
                    rows.append({"name": cols[0], "state": cols[1],
                                 "version": cols[2],
                                 "running": cols[1].lower() == "running"})
            return self._ok(rows)
        except Exception as e:
            return self._err(str(e))

    def wsl_exec(self, distro: str, command: str,
                 timeout: float = 120.0) -> dict[str, Any]:
        """Ejecuta un comando (bash -lc) en una distro y devuelve su salida."""
        from wsl_port.vendor.wsl_manager.utils.subprocess_async import run

        distro = str(distro or "").strip()
        command = str(command or "").strip()
        if not distro or not command:
            return self._err("distro y command son obligatorios")
        try:
            timeout = max(1.0, min(float(timeout), 600.0))
        except (TypeError, ValueError):
            timeout = 120.0
        r = run(["wsl.exe", "-d", distro, "--", "bash", "-lc", command],
                timeout=timeout, breaker=False)
        return self._ok(
            {"distro": distro, "command": command,
             "exit_code": r.exit_code, "output": r.output, "error": r.error},
            "comando ejecutado" if r.ok else f"exit {r.exit_code}",
        )

    # -- WSL: ciclo de vida de distros (crear / clonar / exportar / importar) ---------

    def distros_available(self) -> dict[str, Any]:
        """Catalogo de distros instalables (wsl --list --online)."""
        from wsl_port import core

        return self._ok(core.list_available_distros())

    def distro_create(self, name: str, custom_name: str = "",
                      no_launch: bool = True) -> dict[str, Any]:
        """Instala una distro del catalogo; custom_name la registra con otro
        nombre (permite el mismo SO varias veces)."""
        from wsl_port import core

        name = str(name or "").strip()
        if not name:
            return self._err("name es obligatorio")
        r = core.create_distro(name, no_launch=bool(no_launch),
                               custom_name=str(custom_name or "").strip())
        if not r.get("ok"):
            return self._err(r.get("error") or r.get("output")
                             or f"fallo al instalar '{name}'")
        reg = str(custom_name or "").strip() or name
        return self._ok({"name": reg, "from_catalog": name},
                        f"distro '{reg}' creada")

    def distro_clone(self, name: str, new_name: str) -> dict[str, Any]:
        """Clona una distro existente (export + import) con nombre nuevo."""
        from wsl_port import core

        name = str(name or "").strip()
        new_name = str(new_name or "").strip()
        if not name or not new_name:
            return self._err("name y new_name son obligatorios")
        if name.lower() == new_name.lower():
            return self._err("new_name debe ser distinto de name")
        r = core.clone(name, new_name)
        if not r.get("ok"):
            return self._err(r.get("error") or r.get("output")
                             or f"fallo al clonar '{name}'")
        return self._ok({"from": name, "clone": new_name},
                        f"distro '{name}' clonada como '{new_name}'")

    def distro_export(self, name: str, target: str) -> dict[str, Any]:
        """Exporta una distro a un archivo .tar."""
        from wsl_port import core

        name = str(name or "").strip()
        target = str(target or "").strip()
        if not name or not target:
            return self._err("name y target son obligatorios")
        r = core.export_distro(name, target)
        if not r.get("ok"):
            return self._err(r.get("error") or r.get("output")
                             or f"fallo al exportar '{name}'")
        return self._ok({"name": name, "target": target},
                        f"distro '{name}' exportada a {target}")

    def distro_import(self, source: str, name: str,
                      install_dir: str = "") -> dict[str, Any]:
        """Importa un .tar como distro nueva (por defecto en %LOCALAPPDATA%\\WSL)."""
        import os

        from wsl_port import core

        source = str(source or "").strip()
        name = str(name or "").strip()
        if not source or not name:
            return self._err("source (tar) y name son obligatorios")
        if not os.path.isfile(source):
            return self._err(f"no existe el archivo '{source}'")
        install_dir = str(install_dir or "").strip() or os.path.join(
            os.environ.get("LOCALAPPDATA", ""), "WSL", name)
        r = core.import_distro(source, name, install_dir)
        if not r.get("ok"):
            return self._err(r.get("error") or r.get("output")
                             or f"fallo al importar '{name}'")
        return self._ok({"name": name, "install_dir": r.get("install_dir"),
                         "source": source},
                        f"distro '{name}' importada")

    # -- maintenance / drift -------------------------------------------------------------

    def doctor(self) -> dict[str, Any]:
        """Misma logica que 'port-forwarder doctor' pero devuelve datos (U8)."""
        from wsl_port.vendor.port_forwarder.utils import subprocess_async as sp

        netsh = self.supervisor.netsh
        wsl = self.supervisor.wsl
        ssh = self.supervisor.ssh
        cfg = self.store.cfg
        checks: list[dict[str, Any]] = []

        def _check(name: str, ok: bool, detail: str = "") -> None:
            checks.append({"check": name, "ok": ok, "detail": detail})

        _check("netsh", sp.run(
            [cfg.windows.netsh_exe, "interface", "portproxy", "show", "all"],
            timeout=10, check=False).returncode == 0, "netsh no responde")
        _check("admin (para forwards)", sp.is_admin(),
               "aplicar forwards pedira UAC")
        _check("ssh", sp.run([cfg.windows.ssh_exe, "-V"], timeout=10,
                              check=False).returncode in (0, 1),
               "ssh.exe no disponible")
        for d in dict.fromkeys([f.wsl_distro for f in cfg.forwards
                                if f.wsl_distro]):
            _check(f"wsl distro '{d}'", wsl.get_ip(d) is not None,
                   "distro detenida o inexistente")
        for t in cfg.tunnels:
            vps = self.store.get_vps(t.vps_id)
            if vps is None:
                _check(f"tunnel {t.id} -> vps {t.vps_id}", False,
                       "vps_id no existe en config")
            elif t.type == "ssh":
                _check(f"vps {vps.id} alcanzable",
                       ssh.latency(t, vps) is not None,
                       "VPS inalcanzable o GatewayPorts off")
        for f in cfg.forwards:
            conflicts = netsh.detect_conflicts(f.listen_port)
            _check(f"puerto :{f.listen_port} libre", not conflicts,
                   f"en uso por PIDs {conflicts}")
        return self._ok(checks, f"{len(checks)} checks")

    def maintenance_on(self) -> dict[str, Any]:
        self.store.cfg.maintenance.active = True
        self.store.save()
        return self._ok(message="mantenimiento ON")

    def maintenance_off(self) -> dict[str, Any]:
        self.store.cfg.maintenance.active = False
        self.store.save()
        self.supervisor.run_once()
        return self._ok(message="mantenimiento OFF")

    def maintenance_status(self) -> dict[str, Any]:
        return self._ok({
            "active": self.store.cfg.maintenance.active,
            "window": f"{self.store.cfg.maintenance.start}-"
                      f"{self.store.cfg.maintenance.end}",
        })

    def drift_check(self) -> dict[str, Any]:
        entries = self.supervisor.netsh.declared_forwards(self.store.cfg.forwards)
        drift = [{"forward_id": e.forward_id, "listen_port": e.listen_port,
                  "state": e.state} for e in entries if e.state != "ok"]
        for t in self.store.cfg.tunnels:
            if t.auto_start and not self.supervisor.ssh.is_alive(t):
                drift.append({"tunnel_id": t.id, "state": "down"})
        return self._ok(drift)
