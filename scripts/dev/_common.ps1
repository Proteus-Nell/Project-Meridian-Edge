# Shared helpers for the scripts/dev/*.ps1 developer tools. Dot-sourced by the
# others; not meant to be run directly.
#
# LOCAL DEVELOPMENT ONLY. These start Vite and an auto-reloading uvicorn on
# localhost with SQLite - none of it is a deployment path. Production runs via
# Docker Compose; see DEPLOY.md.
#
# Windows PowerShell 5.1 compatible: no &&/||, ternary, or null-coalescing.

$ErrorActionPreference = "Stop"

# scripts/dev/ -> repo root is two levels up.
$RepoRoot = (Resolve-Path (Join-Path $PSScriptRoot "..\..")).Path
$ClientDir = Join-Path $RepoRoot "client"
$ServerDir = Join-Path $RepoRoot "server"

# Local dev ports: uvicorn serves the API, Vite serves the client and proxies
# /v1 to the API. Vite defaults to 5173; override with the PORT env var.
$ServerPort = 8000
$ClientPort = 5173
if ($env:PORT) { $ClientPort = [int]$env:PORT }

# Prefer the project virtualenv's Python so uvicorn and the deps resolve without
# an activated shell; fall back to whatever `python` is on PATH.
function Get-ServerPython {
    $venvPython = Join-Path $ServerDir ".venv\Scripts\python.exe"
    if (Test-Path $venvPython) { return $venvPython }
    $onPath = Get-Command python -ErrorAction SilentlyContinue
    if ($onPath) { return $onPath.Source }
    throw "No Python found. Create server\.venv (see scripts\dev\update.ps1) or install Python 3.12+."
}

# The PID(s) listening on a TCP port, or an empty array. Get-NetTCPConnection
# ships with Windows 8 / Server 2012 and later.
function Get-ListenerPids([int]$Port) {
    try {
        $conns = Get-NetTCPConnection -State Listen -LocalPort $Port -ErrorAction Stop
        return @($conns | Select-Object -ExpandProperty OwningProcess -Unique)
    } catch {
        return @()
    }
}

# True if something is already listening on the port.
function Test-PortListening([int]$Port) {
    return (Get-ListenerPids $Port).Count -gt 0
}

function Write-Head([string]$Text) {
    Write-Host ""
    Write-Host "== $Text ==" -ForegroundColor Cyan
}
