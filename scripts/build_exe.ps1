# Compila wsl-port a un unico ejecutable (PyInstaller, sin consola).
# Uso:  powershell -File scripts\build_exe.ps1
# Salida: ejecutables\wsl-port.exe
$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $PSScriptRoot
Set-Location $root
& "$root\.venv\Scripts\python.exe" -m pip show pyinstaller *> $null
if ($LASTEXITCODE) { & "$root\.venv\Scripts\python.exe" -m pip install -q pyinstaller }
& "$root\.venv\Scripts\pyinstaller.exe" --noconfirm --clean --onefile --windowed `
    --name wsl-port --distpath "$root\ejecutables" `
    --workpath "$root\build\work" --specpath "$root\build" `
    "$root\run.py" `
    --collect-all ttkbootstrap --collect-all pystray `
    --hidden-import winotify --hidden-import PIL `
    --hidden-import uvicorn.logging --hidden-import uvicorn.loops.auto `
    --hidden-import uvicorn.protocols.http.auto `
    --hidden-import uvicorn.protocols.websockets.auto
Write-Host "Listo: $root\ejecutables\wsl-port.exe"
