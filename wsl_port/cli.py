"""CLI integrado de wsl-port: todas las funcionalidades de WSL Manager + Port Forwarder."""
from __future__ import annotations

import argparse
import json
import sys
import webbrowser


def _out(data, as_json: bool) -> None:
    if as_json:
        print(json.dumps(data, indent=2, ensure_ascii=False, default=str))
    elif isinstance(data, list):
        for row in data:
            print(json.dumps(row, ensure_ascii=False, default=str))
    else:
        print(data)


def _fmt_bytes(n) -> str:
    n = float(n or 0)
    for u in ("B", "KB", "MB", "GB", "TB"):
        if n < 1024 or u == "TB":
            return f"{n:.1f} {u}"
        n /= 1024
    return f"{n:.1f} TB"


# ---------------------------------------------------------------------------
# Commands
# ---------------------------------------------------------------------------

def cmd_status(args) -> int:
    from . import core
    st = core.status()
    if getattr(args, "json", False):
        _out(st, True)
        return 0
    up = sum(1 for d in st["distros"] if d.get("running"))
    tun_ok = sum(1 for t in st["tunnels"] if t.get("state") == "running")
    print(f"Supervisor: {'RUNNING' if st['supervisor_running'] else 'idle'} "
          f"· admin={st['admin']} · maintenance={st['maintenance']}")
    print(f"Distros WSL: {up}/{len(st['distros'])} en marcha")
    for d in st["distros"]:
        print(f"  distro {d.get('name','?'):<18} {d.get('state','?'):<9} "
              f"ip={d.get('ip') or '-'}")
    print(f"Forwards: {len(st['forwards'])}  Tunnels: {tun_ok}/{len(st['tunnels'])}")
    for t in st["tunnels"]:
        tf = t.get("traffic")
        tr = ""
        if tf:
            tr = (f"  rx {_fmt_bytes(tf.get('rx_bytes',0))} tx {_fmt_bytes(tf.get('tx_bytes',0))}"
                  f" dl:{_fmt_bytes(tf.get('rx_rate_bps',0))}/s ul:{_fmt_bytes(tf.get('tx_rate_bps',0))}/s")
        print(f"  tun {t.get('id','?'):<18} {t.get('state','?'):<9} "
              f"local={t.get('local')} remote={','.join(t.get('remote') or [])}{tr}")
    for f in st["forwards"]:
        print(f"  fwd {f.get('id','?'):<18} :{f.get('listen_port','?'):<6} "
              f"{f.get('state','?'):<8} ip={f.get('ip') or '-'}")
    print(f"VPS registrados: {len(st['vps'])}")
    for v in st["vps"]:
        print(f"  vps {v.get('id','?'):<18} {v.get('host','?')}:{v.get('port',22)}")
    return 0


# -- Distros ----------------------------------------------------------------

def cmd_distro_list(args) -> int:
    from . import core
    ds = core.distros()
    if getattr(args, "json", False):
        _out(ds, True)
        return 0
    for d in ds:
        print(f"  {d['name']:<20} {d['state']:<10} ip={d.get('ip') or '-'}")
    return 0


def cmd_distro_start(args) -> int:
    from . import core
    r = core.start_distro(args.name)
    print(r.get("message", r.get("error", "ok")))
    return 0 if r.get("ok", True) else 1


def cmd_distro_stop(args) -> int:
    from . import core
    r = core.stop_distro(args.name)
    print(r.get("message", r.get("error", "ok")))
    return 0 if r.get("ok", True) else 1


def cmd_distro_restart(args) -> int:
    from . import core
    r = core.restart_distro(args.name)
    print(r.get("message", r.get("error", "ok")))
    return 0 if r.get("ok", True) else 1


def cmd_distro_ips(args) -> int:
    from . import core
    ips = core.get_all_ips()
    for name, ip in ips.items():
        print(f"  {name:<20} {ip or '-'}")
    return 0


def cmd_distro_snapshot(args) -> int:
    from . import core
    r = core.snapshot(args.name)
    if r.get("ok"):
        print(f"Snapshot: {r['path']}")
    else:
        print(f"error: {r.get('error')}", file=sys.stderr)
    return 0 if r.get("ok") else 1


def cmd_distro_clone(args) -> int:
    from . import core
    r = core.clone(args.name, args.new_name)
    print(r.get("message", r.get("error", "ok")))
    return 0 if r.get("ok") else 1


def cmd_distro_create(args) -> int:
    from . import core
    custom = getattr(args, "as_name", "") or ""
    etiqueta = custom or args.name
    print(f"Instalando distro '{args.name}'"
          + (f" con nombre '{custom}'" if custom else "")
          + "... (puede tardar varios minutos)")
    r = core.create_distro(args.name, no_launch=not args.launch,
                           custom_name=custom)
    if r.get("ok"):
        print(f"Distro '{etiqueta}' instalada correctamente")
    else:
        print(f"error: {r.get('error')}", file=sys.stderr)
    return 0 if r.get("ok") else 1


def cmd_distro_delete(args) -> int:
    from . import core
    from tkinter import messagebox
    if not args.yes:
        print(f"ATENCION: Esto eliminara la distro '{args.name}' y TODOS sus datos.")
        confirm = input("Escribe 'si' para confirmar: ").strip().lower()
        if confirm != "si":
            print("Cancelado")
            return 0
    r = core.delete_distro(args.name)
    if r.get("ok"):
        print(f"Distro '{args.name}' eliminada")
    else:
        print(f"error: {r.get('error')}", file=sys.stderr)
    return 0 if r.get("ok") else 1


def cmd_distro_available(args) -> int:
    from . import core
    distros = core.list_available_distros()
    if not distros:
        print("(no se pudo obtener la lista)")
        return 1
    print("Distros disponibles para instalar:")
    for d in distros:
        print(f"  {d}")
    return 0


def cmd_distro_export(args) -> int:
    from . import core
    r = core.export_distro(args.name, args.target)
    print(r.get("message", r.get("error", "ok")))
    return 0 if r.get("ok") else 1


def cmd_distro_import(args) -> int:
    from . import core
    r = core.import_distro(args.source, args.name, args.install_dir)
    print(r.get("message", r.get("error", "ok")))
    return 0 if r.get("ok") else 1


def cmd_distro_shutdown_all(args) -> int:
    from . import core
    r = core.shutdown_all()
    print(r.get("message", "WSL apagado"))
    return 0 if r.get("ok") else 1


def cmd_distro_metrics(args) -> int:
    from . import core
    m = core.distro_metrics(args.name)
    if m is None:
        print(f"error: distro '{args.name}' no encontrada o no esta corriendo", file=sys.stderr)
        return 1
    if getattr(args, "json", False):
        _out(m, True)
    else:
        print(f"Distro: {m['name']}  IP: {m.get('ip', '-')}")
        print(f"  RAM: {m.get('ram_used_mb',0)}/{m.get('ram_total_mb',0)} MB ({m.get('ram_percent',0)}%)")
        print(f"  CPUs: {m.get('cpus', '?')}  Uptime: {m.get('uptime_s',0)}s")
    return 0


# -- Recursos WSL (.wslconfig) ----------------------------------------------

def cmd_limits_get(args) -> int:
    from . import core
    limits = core.get_global_limits()
    if getattr(args, "json", False):
        _out(limits, True)
    else:
        if not limits.get("exists"):
            print("(.wslconfig no existe - sin limites personalizados)")
        else:
            print(f"RAM: {limits.get('memory_gb', 'auto')} GB")
            print(f"Processors: {limits.get('processors', 'auto')}")
            print(f"Swap: {limits.get('swap_gb', 'auto')} GB")
        print(f"Archivo: {limits.get('path')}")
    return 0


def cmd_limits_set(args) -> int:
    from . import core
    kwargs = {}
    if args.memory is not None:
        kwargs["memory_gb"] = args.memory
    if args.processors is not None:
        kwargs["processors"] = args.processors
    if args.swap is not None:
        kwargs["swap_gb"] = args.swap
    if args.vhd is not None:
        kwargs["default_vhd_gb"] = args.vhd
    if args.reclaim is not None:
        kwargs["auto_memory_reclaim"] = args.reclaim
    if args.sparse is not None:
        kwargs["sparse_vhd"] = args.sparse
    if args.localhost is not None:
        kwargs["localhost_forwarding"] = args.localhost
    r = core.set_global_limits(**kwargs)
    print(r.get("message", r.get("error", "ok")))
    return 0 if r.get("ok") else 1


# -- Autostart --------------------------------------------------------------

def cmd_autostart_list(args) -> int:
    from . import core
    entries = core.autostart_list()
    if not entries:
        print("(sin autoarranques configurados)")
        return 0
    for e in entries:
        print(f"  {e['name']:<20} delay={e['delay_s']}s enabled={e['enabled']}")
    return 0


def cmd_autostart_set(args) -> int:
    from . import core
    r = core.autostart_set(args.name, args.delay)
    print(r.get("message", "ok"))
    return 0 if r.get("ok") else 1


def cmd_autostart_remove(args) -> int:
    from . import core
    r = core.autostart_remove(args.name)
    print(r.get("message", "ok"))
    return 0 if r.get("ok") else 1


# -- Forwards ---------------------------------------------------------------

def cmd_forwards_list(args) -> int:
    from . import core
    fwds = core.forwards()
    if getattr(args, "json", False):
        _out(fwds, True)
        return 0
    if not fwds:
        print("(sin forwards)")
        return 0
    for f in fwds:
        print(f"  {f['id']:<20} :{f['listen_port']:<6} -> {f.get('wsl_distro','?')}:{f.get('wsl_port','?')} "
              f"proto={f.get('protocol','?')} state={f.get('state','?')}")
    return 0


def cmd_forwards_add(args) -> int:
    from . import core
    r = core.add_forward(args.id, args.listen_port, args.distro, args.wsl_port,
                         args.protocol, not args.no_auto_apply,
                         getattr(args, 'listen_address', '0.0.0.0'))
    print(r.get("message", r.get("error", "ok")))
    return 0 if r.get("ok") else 1


def cmd_forwards_remove(args) -> int:
    from . import core
    r = core.remove_forward(args.id)
    print(r.get("message", r.get("error", "ok")))
    return 0 if r.get("ok") else 1


def cmd_forwards_apply(args) -> int:
    from . import core
    r = core.apply_forwards()
    print(r.get("message", "Forwards aplicados"))
    return 0 if r.get("ok") else 1


def cmd_forwards_clear(args) -> int:
    from . import core
    r = core.clear_forwards()
    print(r.get("message", "Forwards limpiados"))
    return 0 if r.get("ok") else 1


def cmd_forwards_test(args) -> int:
    from . import core
    r = core.test_forward(args.id)
    if r.get("ok"):
        print(f"Forward '{args.id}': {'vivo' if r.get('alive') else 'muerto'} (:{r.get('port')})")
    else:
        print(f"error: {r.get('error')}", file=sys.stderr)
    return 0 if r.get("ok") else 1


def cmd_forwards_conflicts(args) -> int:
    from . import core
    r = core.detect_conflicts(args.port)
    if r.get("ok"):
        pids = r.get("conflicts", [])
        if pids:
            print(f"Conflictos en puerto {args.port}: PIDs {pids}")
        else:
            print(f"Puerto {args.port}: sin conflictos")
    return 0 if r.get("ok") else 1


def cmd_forwards_clone(args) -> int:
    from . import core
    r = core.clone_forward(args.id, args.new_id, args.new_port)
    print(r.get("message", r.get("error", "ok")))
    return 0 if r.get("ok") else 1


# -- Tunnels ----------------------------------------------------------------

def cmd_tunnels_list(args) -> int:
    from . import core
    tuns = core.tunnels()
    if getattr(args, "json", False):
        _out(tuns, True)
        return 0
    if not tuns:
        print("(sin tunnels)")
        return 0
    for t in tuns:
        tf = t.get("traffic")
        tr = ""
        if tf:
            tr = f"  rx {_fmt_bytes(tf.get('rx_bytes',0))} tx {_fmt_bytes(tf.get('tx_bytes',0))}"
        print(f"  {t['id']:<20} {t.get('type','ssh'):<6} vps={t.get('vps_id','?'):<16} "
              f"local={t.get('local')} remote={','.join(t.get('remote') or [])} "
              f"state={t.get('state','?')}{tr}")
    return 0


def cmd_tunnels_add(args) -> int:
    from . import core
    r = core.add_tunnel(args.id, args.vps, args.local_host, args.local_port,
                        args.remote_host, args.remote_port, args.type)
    print(r.get("message", r.get("error", "ok")))
    return 0 if r.get("ok") else 1


def cmd_tunnels_remove(args) -> int:
    from . import core
    r = core.remove_tunnel(args.id)
    print(r.get("message", r.get("error", "ok")))
    return 0 if r.get("ok") else 1


def cmd_tunnels_start(args) -> int:
    from . import core
    r = core.start_tunnel(args.id)
    print(r.get("message", r.get("error", "ok")))
    return 0 if r.get("ok") else 1


def cmd_tunnels_stop(args) -> int:
    from . import core
    r = core.stop_tunnel(args.id)
    print(r.get("message", r.get("error", "ok")))
    return 0 if r.get("ok") else 1


def cmd_tunnels_restart(args) -> int:
    from . import core
    r = core.restart_tunnel(args.id)
    print(r.get("message", r.get("error", "ok")))
    return 0 if r.get("ok") else 1


def cmd_tunnels_latency(args) -> int:
    from . import core
    r = core.tunnel_latency(args.id)
    if r.get("ok"):
        print(f"Latencia '{args.id}': {r.get('latency_ms', '?')} ms")
    else:
        print(f"error: {r.get('error')}", file=sys.stderr)
    return 0 if r.get("ok") else 1


def cmd_tunnels_update(args) -> int:
    from . import core
    kwargs = {}
    if args.vps is not None:
        kwargs["vps_id"] = args.vps
    if args.local is not None:
        kwargs["local"] = args.local
    if args.remote is not None:
        kwargs["remote"] = args.remote
    if args.auto_start is not None:
        kwargs["auto_start"] = args.auto_start
    if args.enabled is not None:
        kwargs["enabled"] = args.enabled
    if not kwargs:
        print("error:没有任何参数更新", file=sys.stderr)
        return 1
    r = core.update_tunnel(args.id, **kwargs)
    print(r.get("message", r.get("error", "ok")))
    return 0 if r.get("ok") else 1


# -- VPS --------------------------------------------------------------------

def cmd_vps_list(args) -> int:
    from . import core
    vps = core.vps_list()
    if getattr(args, "json", False):
        _out(vps, True)
        return 0
    if not vps:
        print("(sin VPS registrados)")
        return 0
    for v in vps:
        print(f"  {v['id']:<20} {v['host']}:{v['port']} (user={v.get('user', '-')})")
    return 0


def cmd_vps_add(args) -> int:
    from . import core
    r = core.add_vps(args.id, args.host, args.user, args.port, args.identity, args.password)
    print(r.get("message", r.get("error", "ok")))
    return 0 if r.get("ok") else 1


def cmd_vps_remove(args) -> int:
    from . import core
    r = core.remove_vps(args.id)
    print(r.get("message", r.get("error", "ok")))
    return 0 if r.get("ok") else 1


# -- Publish ----------------------------------------------------------------

def cmd_publish(args) -> int:
    from . import core
    try:
        r = core.publish(args.distro, args.wsl_port, args.vps,
                         args.public_port, args.bind, not args.no_start)
    except (ValueError, RuntimeError) as e:
        print(f"error: {e}", file=sys.stderr)
        return 1
    if getattr(args, "json", False):
        _out(r, True)
    else:
        print(f"Tunnel '{r['tunnel_id']}' corriendo")
        print(f"  local : {r['local']}  (servicio de la distro {args.distro})")
        print(f"  publico: {r['public_url']}")
        if not args.no_open:
            webbrowser.open(r["public_url"])
    return 0


def cmd_unpublish(args) -> int:
    from . import core
    ok = core.unpublish(args.tunnel)
    print("tunnel eliminado" if ok else f"no se pudo eliminar '{args.tunnel}'")
    return 0 if ok else 1


# -- Health / Alerts --------------------------------------------------------

def cmd_health(args) -> int:
    from . import core
    r = core.health_check()
    if getattr(args, "json", False):
        _out(r, True)
    else:
        print("Health check completado")
        if r.get("ok"):
            s = r.get("summary", {})
            for fid, info in s.get("forwards", {}).items():
                print(f"  fwd {fid}: {info.get('state', '?')}")
            for tid, info in s.get("tunnels", {}).items():
                print(f"  tun {tid}: {info.get('state', '?')}")
    return 0 if r.get("ok") else 1


def cmd_alerts_list(args) -> int:
    from . import core
    al = core.alerts(getattr(args, "state", None))
    if getattr(args, "json", False):
        _out(al, True)
        return 0
    if not al:
        print("(sin alertas)")
        return 0
    for a in al:
        print(f"  [{a.get('id','?')}] {a.get('type','?')}: {a.get('message','')} "
              f"({a.get('severity','?')}) state={a.get('state','?')}")
    return 0


def cmd_alerts_resolve(args) -> int:
    from . import core
    r = core.resolve_alert(args.id)
    print("alerta resuelta" if r.get("ok") else f"error: {r.get('error')}")
    return 0 if r.get("ok") else 1


# -- Schedule ---------------------------------------------------------------

def cmd_schedule_list(args) -> int:
    from . import core
    tasks = core.schedule_list()
    if getattr(args, "json", False):
        _out(tasks, True)
        return 0
    if not tasks:
        print("(sin tareas programadas)")
        return 0
    for t in tasks:
        print(f"  {t.get('id','?'):<20} {t.get('name','?'):<20} "
              f"action={t.get('action','?')} schedule={t.get('schedule',{})} "
              f"enabled={t.get('enabled', True)}")
    return 0


def cmd_schedule_add(args) -> int:
    from . import core
    days = args.days.split(",") if args.days else None
    r = core.schedule_add(args.name, args.type, args.time, days, args.tunnel, args.profile)
    print(r.get("message", r.get("error", "ok")))
    return 0 if r.get("ok") else 1


def cmd_schedule_remove(args) -> int:
    from . import core
    r = core.schedule_remove(args.id)
    print(r.get("message", r.get("error", "ok")))
    return 0 if r.get("ok") else 1


# -- Profiles ---------------------------------------------------------------

def cmd_profile_list(args) -> int:
    from . import core
    profs = core.profile_list()
    if getattr(args, "json", False):
        _out(profs, True)
        return 0
    if not profs:
        print("(sin perfiles)")
        return 0
    for p in profs:
        print(f"  {p.get('name','?'):<20} forwards={p.get('forwards',[])} tunnels={p.get('tunnels',[])}")
    return 0


def cmd_profile_apply(args) -> int:
    from . import core
    r = core.profile_apply(args.name)
    print(r.get("message", r.get("error", "ok")))
    return 0 if r.get("ok") else 1


def cmd_profile_capture(args) -> int:
    from . import core
    r = core.profile_capture(args.name, args.desc or "")
    print(r.get("message", r.get("error", "ok")))
    return 0 if r.get("ok") else 1


# -- Maintenance ------------------------------------------------------------

def cmd_maintenance_on(args) -> int:
    from . import core
    r = core.maintenance_on()
    print(r.get("message", "ok"))
    return 0 if r.get("ok") else 1


def cmd_maintenance_off(args) -> int:
    from . import core
    r = core.maintenance_off()
    print(r.get("message", "ok"))
    return 0 if r.get("ok") else 1


def cmd_maintenance_status(args) -> int:
    from . import core
    r = core.maintenance_status()
    if r.get("ok"):
        print(f"Mantenimiento: {'activo' if r.get('active') else 'inactivo'}")
    return 0 if r.get("ok") else 1


# -- Drift ------------------------------------------------------------------

def cmd_drift_check(args) -> int:
    from . import core
    r = core.drift_check()
    if getattr(args, "json", False):
        _out(r, True)
        return 0
    if r.get("ok"):
        drift = r.get("drift", [])
        if drift:
            print(f"Drift detectado ({len(drift)} forwards):")
            for d in drift:
                print(f"  {d}")
        else:
            print(f"Sin drift ({r.get('total',0)} forwards verificados)")
    else:
        print(f"error: {r.get('error')}", file=sys.stderr)
    return 0 if r.get("ok") else 1


# -- Doctor -----------------------------------------------------------------

def cmd_doctor(args) -> int:
    from . import core
    r = core.doctor()
    if getattr(args, "json", False):
        _out(r, True)
        return 0
    for c in r.get("checks", []):
        mark = "OK" if c["ok"] else "FAIL"
        print(f"  [{mark}] {c['check']}: {c['message']}")
    return 0 if r.get("ok") else 1


# -- Config -----------------------------------------------------------------

def cmd_config_export(args) -> int:
    from . import core
    r = core.config_export(args.path)
    print(r.get("message", r.get("error", "ok")))
    return 0 if r.get("ok") else 1


def cmd_config_import(args) -> int:
    from . import core
    r = core.config_import(args.path)
    print(r.get("message", r.get("error", "ok")))
    return 0 if r.get("ok") else 1


def cmd_config_validate(args) -> int:
    from . import core
    r = core.config_validate()
    print(r.get("message", r.get("error", "ok")))
    return 0 if r.get("ok") else 1


# -- Secrets ----------------------------------------------------------------

def cmd_secrets_set(args) -> int:
    from . import core
    import getpass
    if sys.stdin.isatty():
        value = getpass.getpass(f"Valor para '{args.ref}': ")
    else:
        value = sys.stdin.read().strip()
    r = core.secret_set(args.ref, value)
    print(r.get("message", r.get("error", "ok")))
    return 0 if r.get("ok") else 1


def cmd_secrets_check(args) -> int:
    from . import core
    r = core.secret_check(args.ref)
    if r.get("ok"):
        print(f"'{args.ref}': {'existe' if r.get('exists') else 'no existe'}")
    return 0 if r.get("ok") else 1


# -- Supervise / Watch ------------------------------------------------------

def cmd_supervise(args) -> int:
    from . import core
    print("Iniciando supervisor (Ctrl+C para salir)...")
    try:
        core.supervisor_run_forever()
    except KeyboardInterrupt:
        print("\nSupervisor detenido.")
    return 0


def cmd_watch(args) -> int:
    from wsl_port.vendor.port_forwarder.core.event_bus import bus
    def handler(event, **data):
        print(json.dumps({"event": event, **data}, default=str))
    bus.subscribe(handler)
    print("Escuchando eventos (Ctrl+C para salir)...")
    try:
        import time
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\nWatch detenido.")
    return 0


# ---------------------------------------------------------------------------
# Parser
# ---------------------------------------------------------------------------

def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="wsl-port",
                                description="WSL Manager + Port Forwarding integrados")
    p.add_argument("--json", action="store_true", help="Salida JSON")
    sub = p.add_subparsers(dest="cmd", required=True)

    # status
    s = sub.add_parser("status", help="Estado integrado")
    s.set_defaults(fn=cmd_status)

    # distro
    d = sub.add_parser("distro", help="Gestion de distros WSL")
    d_sub = d.add_subparsers(dest="distro_cmd", required=True)
    dl = d_sub.add_parser("list", help="Listar distros")
    dl.set_defaults(fn=cmd_distro_list)
    ds = d_sub.add_parser("start", help="Iniciar distro")
    ds.add_argument("name")
    ds.set_defaults(fn=cmd_distro_start)
    dt = d_sub.add_parser("stop", help="Detener distro")
    dt.add_argument("name")
    dt.set_defaults(fn=cmd_distro_stop)
    dr = d_sub.add_parser("restart", help="Reiniciar distro")
    dr.add_argument("name")
    dr.set_defaults(fn=cmd_distro_restart)
    di = d_sub.add_parser("ips", help="Ver IPs")
    di.set_defaults(fn=cmd_distro_ips)
    dn = d_sub.add_parser("snapshot", help="Snapshot")
    dn.add_argument("name")
    dn.set_defaults(fn=cmd_distro_snapshot)
    dc = d_sub.add_parser("clone", help="Clonar distro")
    dc.add_argument("name")
    dc.add_argument("new_name")
    dc.set_defaults(fn=cmd_distro_clone)
    de = d_sub.add_parser("export", help="Exportar distro")
    de.add_argument("name")
    de.add_argument("target")
    de.set_defaults(fn=cmd_distro_export)
    dim = d_sub.add_parser("import", help="Importar distro")
    dim.add_argument("source")
    dim.add_argument("name")
    dim.add_argument("install_dir")
    dim.set_defaults(fn=cmd_distro_import)
    dsa = d_sub.add_parser("shutdown-all", help="Apagar WSL")
    dsa.set_defaults(fn=cmd_distro_shutdown_all)
    dm = d_sub.add_parser("metrics", help="Metricas de distro")
    dm.add_argument("name")
    dm.set_defaults(fn=cmd_distro_metrics)
    dcr = d_sub.add_parser("create", help="Crear nueva distro (wsl --install)")
    dcr.add_argument("name", help="Nombre de la distro (ej: Ubuntu, Debian)")
    dcr.add_argument("--launch", action="store_true", help="Arrancar despues de instalar")
    dcr.add_argument("--as", dest="as_name", default="",
                     help="Nombre de registro (permite instalar el mismo SO "
                          "varias veces sin conflicto, ej: Kali-Work)")
    dcr.set_defaults(fn=cmd_distro_create)
    ddl = d_sub.add_parser("delete", help="Eliminar distro (wsl --unregister)")
    ddl.add_argument("name", help="Nombre de la distro a eliminar")
    ddl.add_argument("-y", "--yes", action="store_true", help="Sin confirmacion")
    ddl.set_defaults(fn=cmd_distro_delete)
    dav = d_sub.add_parser("available", help="Listar distros disponibles para instalar")
    dav.set_defaults(fn=cmd_distro_available)

    # limits
    lm = sub.add_parser("limits", help="Limites de recursos WSL (.wslconfig)")
    lm_sub = lm.add_subparsers(dest="limits_cmd", required=True)
    lg = lm_sub.add_parser("get", help="Ver limites")
    lg.set_defaults(fn=cmd_limits_get)
    ls = lm_sub.add_parser("set", help="Establecer limites")
    ls.add_argument("--memory", type=float, help="RAM en GB")
    ls.add_argument("--processors", type=int, help="Num CPUs")
    ls.add_argument("--swap", type=float, help="Swap en GB")
    ls.add_argument("--vhd", type=float, help="defaultVhdSize en GB")
    ls.add_argument("--reclaim", choices=["gradual", "dropcache", "disabled"],
                    help="autoMemoryReclaim")
    ls.add_argument("--sparse", choices=["true", "false"], help="sparseVhd")
    ls.add_argument("--localhost", choices=["true", "false"],
                    help="localhostForwarding")
    ls.set_defaults(fn=cmd_limits_set)

    # autostart
    au = sub.add_parser("autostart", help="Autoarranque de distros")
    au_sub = au.add_subparsers(dest="autostart_cmd", required=True)
    aul = au_sub.add_parser("list", help="Listar autoarranques")
    aul.set_defaults(fn=cmd_autostart_list)
    aus = au_sub.add_parser("set", help="Configurar autoarranque")
    aus.add_argument("name")
    aus.add_argument("--delay", type=int, default=0)
    aus.set_defaults(fn=cmd_autostart_set)
    aur = au_sub.add_parser("remove", help="Quitar autoarranque")
    aur.add_argument("name")
    aur.set_defaults(fn=cmd_autostart_remove)

    # forwards
    fw = sub.add_parser("forwards", help="Forwards Windows->WSL")
    fw_sub = fw.add_subparsers(dest="fwd_cmd", required=True)
    fwl = fw_sub.add_parser("list", help="Listar forwards")
    fwl.set_defaults(fn=cmd_forwards_list)
    fwa = fw_sub.add_parser("add", help="Agregar forward")
    fwa.add_argument("--id", required=True)
    fwa.add_argument("--listen-port", type=int, required=True)
    fwa.add_argument("--listen-address", default="0.0.0.0",
                     help="Direccion de escucha (ej: 127.0.0.1, 127.0.0.2, 0.0.0.0)")
    fwa.add_argument("--distro", required=True)
    fwa.add_argument("--wsl-port", type=int, required=True)
    fwa.add_argument("--protocol", choices=["tcp", "udp"], default="tcp")
    fwa.add_argument("--no-auto-apply", action="store_true")
    fwa.set_defaults(fn=cmd_forwards_add)
    fwr = fw_sub.add_parser("remove", help="Eliminar forward")
    fwr.add_argument("id")
    fwr.set_defaults(fn=cmd_forwards_remove)
    fwap = fw_sub.add_parser("apply", help="Aplicar forwards")
    fwap.set_defaults(fn=cmd_forwards_apply)
    fwcl = fw_sub.add_parser("clear", help="Limpiar todos los forwards")
    fwcl.set_defaults(fn=cmd_forwards_clear)
    fwt = fw_sub.add_parser("test", help="Test conexion forward")
    fwt.add_argument("id")
    fwt.set_defaults(fn=cmd_forwards_test)
    fwc = fw_sub.add_parser("conflicts", help="Detectar conflictos de puerto")
    fwc.add_argument("port", type=int)
    fwc.set_defaults(fn=cmd_forwards_conflicts)
    fwcl2 = fw_sub.add_parser("clone", help="Clonar forward")
    fwcl2.add_argument("id")
    fwcl2.add_argument("--new-id", required=True)
    fwcl2.add_argument("--new-port", type=int)
    fwcl2.set_defaults(fn=cmd_forwards_clone)

    # tunnels
    tn = sub.add_parser("tunnels", help="Tunnels SSH hacia VPS")
    tn_sub = tn.add_subparsers(dest="tun_cmd", required=True)
    tnl = tn_sub.add_parser("list", help="Listar tunnels")
    tnl.set_defaults(fn=cmd_tunnels_list)
    tna = tn_sub.add_parser("add", help="Agregar tunnel")
    tna.add_argument("--id", required=True)
    tna.add_argument("--vps", required=True)
    tna.add_argument("--local-host", default="127.0.0.1")
    tna.add_argument("--local-port", type=int, required=True)
    tna.add_argument("--remote-host", default="0.0.0.0")
    tna.add_argument("--remote-port", type=int, required=True)
    tna.add_argument("--type", choices=["ssh", "tailscale", "cloudflare"], default="ssh")
    tna.set_defaults(fn=cmd_tunnels_add)
    tnr = tn_sub.add_parser("remove", help="Eliminar tunnel")
    tnr.add_argument("id")
    tnr.set_defaults(fn=cmd_tunnels_remove)
    tns = tn_sub.add_parser("start", help="Iniciar tunnel")
    tns.add_argument("id")
    tns.set_defaults(fn=cmd_tunnels_start)
    tnst = tn_sub.add_parser("stop", help="Detener tunnel")
    tnst.add_argument("id")
    tnst.set_defaults(fn=cmd_tunnels_stop)
    tnrst = tn_sub.add_parser("restart", help="Reiniciar tunnel")
    tnrst.add_argument("id")
    tnrst.set_defaults(fn=cmd_tunnels_restart)
    tnlat = tn_sub.add_parser("latency", help="Latencia del tunnel")
    tnlat.add_argument("id")
    tnlat.set_defaults(fn=cmd_tunnels_latency)
    tnu = tn_sub.add_parser("update", help="Actualizar tunnel")
    tnu.add_argument("id")
    tnu.add_argument("--vps")
    tnu.add_argument("--local")
    tnu.add_argument("--remote")
    tnu.add_argument("--auto-start", type=bool)
    tnu.add_argument("--enabled", type=bool)
    tnu.set_defaults(fn=cmd_tunnels_update)

    # vps
    vp = sub.add_parser("vps", help="Gestion de VPS")
    vp_sub = vp.add_subparsers(dest="vps_cmd", required=True)
    vpl = vp_sub.add_parser("list", help="Listar VPS")
    vpl.set_defaults(fn=cmd_vps_list)
    vpa = vp_sub.add_parser("add", help="Agregar VPS")
    vpa.add_argument("--id", required=True)
    vpa.add_argument("--host", required=True)
    vpa.add_argument("--user", default="")
    vpa.add_argument("--port", type=int, default=22)
    vpa.add_argument("--identity", default="")
    vpa.add_argument("--password", default="")
    vpa.set_defaults(fn=cmd_vps_add)
    vpr = vp_sub.add_parser("remove", help="Eliminar VPS")
    vpr.add_argument("id")
    vpr.set_defaults(fn=cmd_vps_remove)

    # publish
    pu = sub.add_parser("publish", help="Publicar servicio en Internet")
    pu.add_argument("--distro", required=True)
    pu.add_argument("--wsl-port", type=int, required=True)
    pu.add_argument("--vps", required=True)
    pu.add_argument("--public-port", type=int, required=True)
    pu.add_argument("--bind", default="0.0.0.0")
    pu.add_argument("--no-start", action="store_true")
    pu.add_argument("--no-open", action="store_true")
    pu.set_defaults(fn=cmd_publish)
    up = sub.add_parser("unpublish", help="Detener publicacion")
    up.add_argument("tunnel")
    up.set_defaults(fn=cmd_unpublish)

    # health
    he = sub.add_parser("health", help="Health checks")
    he.set_defaults(fn=cmd_health)

    # alerts
    al = sub.add_parser("alerts", help="Alertas")
    al_sub = al.add_subparsers(dest="alert_cmd", required=True)
    all_ = al_sub.add_parser("list", help="Listar alertas")
    all_.add_argument("--state", choices=["open", "resolved"])
    all_.set_defaults(fn=cmd_alerts_list)
    alr = al_sub.add_parser("resolve", help="Resolver alerta")
    alr.add_argument("id", type=int)
    alr.set_defaults(fn=cmd_alerts_resolve)

    # schedule
    sc = sub.add_parser("schedule", help="Tareas programadas")
    sc_sub = sc.add_subparsers(dest="sched_cmd", required=True)
    scl = sc_sub.add_parser("list", help="Listar tareas")
    scl.set_defaults(fn=cmd_schedule_list)
    sca = sc_sub.add_parser("add", help="Agregar tarea")
    sca.add_argument("--name", required=True)
    sca.add_argument("--type", required=True,
                     choices=["tunnel_start", "tunnel_stop", "forwards_apply",
                              "forwards_clear", "apply_profile", "snapshot_state",
                              "distro_start", "distro_stop"])
    sca.add_argument("--time", required=True, help="HH:MM")
    sca.add_argument("--days", help="mon,tue,wed,thu,fri,sat,sun")
    sca.add_argument("--tunnel")
    sca.add_argument("--profile")
    sca.set_defaults(fn=cmd_schedule_add)
    scr = sc_sub.add_parser("remove", help="Eliminar tarea")
    scr.add_argument("id")
    scr.set_defaults(fn=cmd_schedule_remove)

    # profile
    pr = sub.add_parser("profile", help="Perfiles de exposicion")
    pr_sub = pr.add_subparsers(dest="profile_cmd", required=True)
    prl = pr_sub.add_parser("list", help="Listar perfiles")
    prl.set_defaults(fn=cmd_profile_list)
    pra = pr_sub.add_parser("apply", help="Aplicar perfil")
    pra.add_argument("name")
    pra.set_defaults(fn=cmd_profile_apply)
    prc = pr_sub.add_parser("capture", help="Capturar perfil")
    prc.add_argument("name")
    prc.add_argument("--desc", default="")
    prc.set_defaults(fn=cmd_profile_capture)

    # maintenance
    mt = sub.add_parser("maintenance", help="Modo mantenimiento")
    mt_sub = mt.add_subparsers(dest="maint_cmd", required=True)
    mton = mt_sub.add_parser("on", help="Activar")
    mton.set_defaults(fn=cmd_maintenance_on)
    mtoff = mt_sub.add_parser("off", help="Desactivar")
    mtoff.set_defaults(fn=cmd_maintenance_off)
    mtst = mt_sub.add_parser("status", help="Estado")
    mtst.set_defaults(fn=cmd_maintenance_status)

    # drift
    dr = sub.add_parser("drift", help="Deteccion de drift (config vs realidad)")
    dr.set_defaults(fn=cmd_drift_check)

    # doctor
    doc = sub.add_parser("doctor", help="Diagnostico del entorno")
    doc.set_defaults(fn=cmd_doctor)

    # config
    cfg = sub.add_parser("config", help="Configuracion")
    cfg_sub = cfg.add_subparsers(dest="config_cmd", required=True)
    cfgexp = cfg_sub.add_parser("export", help="Exportar config")
    cfgexp.add_argument("path")
    cfgexp.set_defaults(fn=cmd_config_export)
    cfgimp = cfg_sub.add_parser("import", help="Importar config")
    cfgimp.add_argument("path")
    cfgimp.set_defaults(fn=cmd_config_import)
    cfgval = cfg_sub.add_parser("validate", help="Validar config")
    cfgval.set_defaults(fn=cmd_config_validate)

    # secrets
    sec = sub.add_parser("secrets", help="Secretos cifrados (DPAPI)")
    sec_sub = sec.add_subparsers(dest="secret_cmd", required=True)
    secs = sec_sub.add_parser("set", help="Guardar secreto")
    secs.add_argument("ref")
    secs.set_defaults(fn=cmd_secrets_set)
    secc = sec_sub.add_parser("check", help="Verificar secreto")
    secc.add_argument("ref")
    secc.set_defaults(fn=cmd_secrets_check)

    # supervise
    sup = sub.add_parser("supervise", help="Ejecutar supervisor en foreground")
    sup.set_defaults(fn=cmd_supervise)

    # watch
    wa = sub.add_parser("watch", help="Escuchar eventos en vivo")
    wa.set_defaults(fn=cmd_watch)

    return p


def main(argv: list[str] | None = None) -> int:
    p = build_parser()
    args = p.parse_args(argv)
    return args.fn(args)


if __name__ == "__main__":
    sys.exit(main())
