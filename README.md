# wsl-port-unified — WSL + Internet en 1 clic

[![Python](https://img.shields.io/badge/Python-3.11%2B-3776AB?logo=python&logoColor=white)](#requisitos)
[![Integracion](https://img.shields.io/badge/Integra-WSL%20Manager%20%2B%20Port%20Forwarding-2ea44f)](#caracteristicas-integradas)
[![Plataforma](https://img.shields.io/badge/Plataforma-Windows%2010%2F11-0078D6?logo=windows&logoColor=white)](#requisitos)
[![Licencia](https://img.shields.io/badge/Licencia-MIT-blue.svg)](LICENSE)
[![Tests](https://img.shields.io/badge/Tests-130%2F130%20passed-2ea44f)](#tests)
[![Open Source](https://img.shields.io/badge/Open%20Source-Yes-2ea44f)](LICENSE)

> **Publica cualquier servicio de tu WSL en Internet con 1 clic.** wsl-port une **WSL Manager** (tus distros) y **Port Forwarding Manager** (tuneles al VPS) en una sola ventana y un solo comando.

**Reemplaza a las 2 apps por separado** — si usas wsl-port ya no necesitas abrir WSL Manager ni Port Forwarder.

### Ecosistema

| Repositorio | Descripción | Rol |
|---|---|---|
| **[wsl-port-unified](https://github.com/gilmanpro/wsl-port-unified)** | **App unificada** (este repo) — WSL + Internet en 1 clic | ⭐ Recomendado |
| [wsl-distro-manager](https://github.com/gilmanpro/wsl-distro-manager) | Gestión de distros WSL2 (GUI + CLI + panel web + MCP) | Base · vendored en wsl-port |
| [portforward-tunnels](https://github.com/gilmanpro/portforward-tunnels) | Port forwarding + túneles SSH al VPS (GUI + CLI + panel web + MCP) | Base · vendored en wsl-port |

---

## Inicio rapido

**Opcion A — Doble clic (recomendado, sin consola)**

1. Doble clic en `wsl-port.vbs` o el acceso directo del Escritorio.
2. ¡Listo! No se abre ninguna terminal — todo queda en segundo plano.

**Opcion B — Linea de comandos**

```bash
# Modo headless (fondo, sin ventana)
python run.py --headless

# Con interfaz grafica
python run.py

# Solo CLI (para scripts)
wsl-port status
```

---

## Caracteristicas integradas

| Lo que ves | De donde viene |
|---|---|
| **Distros WSL** — estado, IP, iniciar/apagar, snapshots, clones, crear/eliminar | WSL Manager |
| **Publicar en Internet** — asistente WSL -> VPS (1 clic) | **Nuevo: flujo integrado** |
| **Tunnels / VPS** — estado, trafico, gestion VPS, latency | Port Forwarder |
| **Forwards** — redirecciones Windows->WSL (netsh + firewall) | Port Forwarder |
| **Limites de recursos** — .wslconfig (RAM, CPUs, swap) | WSL Manager |
| **Autoarranque** — distros con Windows + delay | WSL Manager |
| **Health checks** — TCP, alertas, umbrales configurables | Port Forwarder |
| **Scheduler** — tareas programadas (dias/hora) | Ambos |
| **Perfiles** — capturar/aplicar estados | Ambos |
| **Maintenance** — pausar todo sin borrar config | Port Forwarder |
| **Drift** — config vs realidad (deteccion + reconciliacion) | Port Forwarder |
| **Doctor** — diagnostico del entorno | Ambos |
| **Supervisor** — loop unificado (IPs + tunnels + forwards) | Port Forwarder |
| **Panel web** — dashboard en `:8780` | Nuevo |
| **API REST** — `:8781` con tokens + scopes | Nuevo |
| **MCP** — `:8782` para agentes LLM | Nuevo |

---

## CLI completo

### Estado global

```bash
wsl-port status [--json]                 # Estado integrado (distros + forwards + tunnels + VPS)
wsl-port doctor [--json]                 # Diagnostico del entorno
```

### Distros WSL

```bash
wsl-port distro list [--json]            # Listar distros
wsl-port distro start <distro>           # Iniciar distro
wsl-port distro stop <distro>            # Detener distro
wsl-port distro restart <distro>         # Reiniciar distro
wsl-port distro ips                      # IPs de todas las distros
wsl-port distro metrics <distro>         # RAM, CPUs, uptime
wsl-port distro snapshot <distro>        # Crear snapshot (.tar)
wsl-port distro clone <distro> <nuevo>   # Clonar distro
wsl-port distro export <distro> <ruta>   # Exportar distro
wsl-port distro import <tar> <nombre> <dir>  # Importar distro
wsl-port distro shutdown-all             # Apagar WSL
wsl-port distro create <nombre>          # Crear nueva distro (wsl --install)
wsl-port distro delete <nombre> [-y]     # Eliminar distro (wsl --unregister)
wsl-port distro available                # Listar distros disponibles para instalar
```

### Limites de recursos (.wslconfig)

```bash
wsl-port limits get                      # Ver limites actuales
wsl-port limits set --memory 8GB --processors 4 --swap 4GB  # Establecer limites
```

### Autoarranque

```bash
wsl-port autostart list                  # Listar autoarranques
wsl-port autostart set <distro> [--delay N]  # Configurar autoarranque
wsl-port autostart remove <distro>       # Quitar autoarranque
```

### Forwards (Windows->WSL)

```bash
wsl-port forwards list [--json]          # Listar forwards
wsl-port forwards add --id <id> --listen-port <N> --distro <distro> --wsl-port <N> [--listen-address 0.0.0.0] [--protocol tcp|udp]
wsl-port forwards remove <id>            # Eliminar forward
wsl-port forwards apply                  # Aplicar forwards
wsl-port forwards clear                  # Limpiar TODOS los forwards
wsl-port forwards test <id>              # Test conexion TCP
wsl-port forwards conflicts <puerto>     # Detectar conflictos de puerto
wsl-port forwards clone <id> --new-id <id> [--new-port N]  # Clonar forward
```

### Tunnels (hacia VPS)

```bash
wsl-port tunnels list [--json]           # Listar tunnels
wsl-port tunnels add --id <id> --vps <vps-id> --local-host 127.0.0.1 --local-port <N> --remote-host 0.0.0.0 --remote-port <N>
wsl-port tunnels remove <id>             # Eliminar tunnel
wsl-port tunnels start <id>              # Iniciar tunnel
wsl-port tunnels stop <id>               # Detener tunnel (NO revive automaticamente)
wsl-port tunnels restart <id>            # Reiniciar tunnel
wsl-port tunnels latency <id>            # Latencia al VPS
```

### VPS

```bash
wsl-port vps list [--json]               # Listar VPS
wsl-port vps add --id <id> --host <host> --user <user> [--port 22] [--identity <ruta>] [--password <pass>]
wsl-port vps remove <id>                 # Eliminar VPS
```

### Publicar en Internet (1 clic)

```bash
wsl-port publish --distro Debian --wsl-port 9000 --vps "vps1 de canada" --public-port 18097
wsl-port unpublish pub-debian-9000       # Detener publicacion
```

### Health, alertas y umbrales

```bash
wsl-port health                          # Health checks
wsl-port alerts list [--state open|resolved]  # Listar alertas
wsl-port alerts resolve <id>             # Resolver alerta
```

### Programacion y perfiles

```bash
wsl-port schedule list [--json]          # Listar tareas
wsl-port schedule add --name <nombre> --type <tipo> --time HH:MM [--days mon,tue,...]
wsl-port schedule remove <id>            # Eliminar tarea
wsl-port profile list [--json]           # Listar perfiles
wsl-port profile apply <nombre>          # Aplicar perfil
wsl-port profile capture <nombre> [--desc "..."]  # Capturar perfil
```

### Maintenance y drift

```bash
wsl-port maintenance on                  # Activar modo mantenimiento
wsl-port maintenance off                 # Desactivar modo mantenimiento
wsl-port maintenance status              # Estado del mantenimiento
wsl-port drift                           # Deteccion de drift (config vs realidad)
```

### Configuracion y secrets

```bash
wsl-port config validate                 # Validar config
wsl-port config export <ruta>            # Exportar config
wsl-port config import <ruta>            # Importar config
wsl-port secrets set <ref>               # Guardar secreto (por stdin)
wsl-port secrets check <ref>             # Verificar si existe un secreto
```

### Supervisor y eventos

```bash
wsl-port supervise                       # Supervisor headless (Ctrl+C para salir)
wsl-port watch                           # Eventos en vivo estilo tail
```

---

## Publicar en Internet (1 clic)

```bash
# Publicar el servicio 9000 de Debian en http://TU_VPS:18097
wsl-port publish --distro Debian --wsl-port 9000 --vps "vps1 de canada" --public-port 18097

# Detener publicacion
wsl-port unpublish pub-debian-9000
```

Desde la GUI: pestana **Publicar en Internet** — elige distro, puerto, VPS y puerto publico.

---

## Panel Web, API REST y MCP

### Panel Web (puerto 8780)

```bash
# Configurar token (obligatorio)
echo "TU-TOKEN-SECRETO" | wsl-port secrets set web_panel_token

# Acceso: http://127.0.0.1:8780
# Requiere: Authorization: Bearer <token>
```

### API REST (puerto 8781)

```bash
# Configurar en config.json: api.enabled=true
# Acceso: http://127.0.0.1:8781/api/v1/*
# Auth: Authorization: Bearer <token>
```

### MCP Server (stdio)

```bash
export PORT_FORWARDER_TOKEN="mi-token"
wsl-port mcp serve                       # Servidor MCP stdio
```

**29 tools disponibles** para agentes LLM (Claude Code, Cursor, etc.)

---

## GUI (Interfaz Grafica)

La GUI tiene 6 pestanas:

1. **Distros WSL** — Iniciar, Detener, Reiniciar, Snapshot, Metricas, Crear, Eliminar, Exportar, Importar
2. **Publicar en Internet** — Asistente 1-click (distro + puerto + VPS + puerto publico)
3. **Tunnels / VPS** — Nuevo Tunnel, Iniciar, Detener, Eliminar, Nuevo VPS, Editar VPS
4. **Forwards** — Nuevo Forward (con selector de direccion listen), Reaplicar, Eliminar
5. **Logs** — Visor en vivo
6. **Ajustes** — General, Supervisor, Panel Web, API REST, MCP, Rutas, Limites de recursos (.wslconfig), Autoarranque

---

## Estructura

```
wsl-port-unified/
├── run.py                  # Entry point (GUI / headless)
├── pyproject.toml          # Configuracion del paquete
├── README.md               # Este archivo
├── wsl_port/
│   ├── __init__.py
│   ├── core.py             # Nucleo integrado (providers directos)
│   ├── cli.py              # CLI completo (20 grupos de comandos)
│   ├── publish.py          # Flujo publicar/despublicar
│   ├── ui/
│   │   ├── __init__.py
│   │   ├── main_window.py  # GUI (6 pestanas + ajustes)
│   │   └── publish_tab.py  # Asistente Publicar
│   └── vendor/             # Auto-generado (wsl_manager + port_forwarder)
├── tests/                  # Suite completa (130 tests: core, CLI, GUI, web, MCP)
├── docs/
│   ├── REPORTE-TESTS-COMPLETO.md
│   ├── REPORTE-TESTS-WEB-PANEL.md
│   ├── REPORTE-TESTS-MCP.md
│   ├── REPORTE-PRUEBAS-EXPORTAR-PUERTOS.md
│   └── PROYECTOS-GILMANPRO.md
├── scripts/
│   ├── vendor_copy.py      # Genera vendor/ desde repos base
│   ├── wsl-port.spec       # PyInstaller spec
│   └── wsl-port.vbs        # Lanzador sin consola
└── .gitignore
```

---

## Requisitos

- Windows 10/11 + WSL2 con al menos 1 distro.
- Python 3.11+.
- `ssh.exe` disponible (Windows OpenSSH).
- Un VPS con `GatewayPorts yes` (ver `vps/sshd_config.snippet`).
- Admin (UAC) solo para aplicar forwards.

---

## Instalacion

```bash
# 1. Clonar y crear entorno (Python 3.11+)
git clone https://github.com/gilmanpro/wsl-port-unified
cd wsl-port-unified
python -m venv .venv
.venv\Scripts\activate

# 2. Instalar (CLI + GUI; agrega [dev] para tests y [mcp] para el servidor MCP)
pip install -e ".[dev,mcp]"

# 3. Arrancar
.venv\Scripts\wsl-port.exe status          # CLI: estado integrado
python run.py                              # GUI en system tray (o doble clic en wsl-port.vbs)
```

Autoarranque con Windows (oculto, sin consola): registra `wscript.exe "<ruta>\wsl-port.vbs"` en `HKCU\Software\Microsoft\Windows\CurrentVersion\Run`.

---

## Tests

```bash
python -m pytest tests -q
```

---

## Contribuir

Las contribuciones son bienvenidas! Por favor lee [CONTRIBUTING.md](CONTRIBUTING.md) para mas informacion.

1. Haz un fork del repositorio
2. Crea una rama para tu feature o fix
3. Haz tus cambios y asegurate de que los tests pasan
4. Envia un pull request

---

## Licencia

MIT — ver [LICENSE](LICENSE) y los repos base:
[WSL Manager](https://github.com/gilmanpro/wsl-distro-manager) ·
[Port Forwarder](https://github.com/gilmanpro/portforward-tunnels)
