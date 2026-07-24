# Start the local dev servers (LOCAL DEVELOPMENT ONLY - see _common.ps1).
#
# Opens the API (auto-reloading uvicorn) and the client (Vite) each in their own
# PowerShell window so you can watch their logs. Re-running is safe: a port
# already in use is left alone rather than double-started. Stop them with
# stop.ps1.

. (Join-Path $PSScriptRoot "_common.ps1")

Write-Head "Starting Meridian Edge dev servers"

if (-not (Test-Path (Join-Path $ClientDir "node_modules"))) {
    Write-Host "client\node_modules is missing - run scripts\dev\update.ps1 first." -ForegroundColor Yellow
    exit 1
}

# API (uvicorn). Skip if the port is already serving.
if (Test-PortListening $ServerPort) {
    Write-Host "API already listening on $ServerPort - leaving it." -ForegroundColor Yellow
} else {
    $python = Get-ServerPython
    Write-Host "API      -> http://127.0.0.1:$ServerPort  (uvicorn --reload)"
    Start-Process -FilePath $python `
        -ArgumentList @("-m", "uvicorn", "app.main:create_app", "--factory", "--reload", "--port", "$ServerPort") `
        -WorkingDirectory $ServerDir
}

# Client (Vite). Skip if the port is already serving.
if (Test-PortListening $ClientPort) {
    Write-Host "Client already listening on $ClientPort - leaving it." -ForegroundColor Yellow
} else {
    Write-Host "Client   -> http://localhost:$ClientPort  (vite, proxies /v1 to the API)"
    # npm is a .cmd shim, so launch it through cmd.exe for a clean child window.
    $env:PORT = "$ClientPort"
    Start-Process -FilePath "cmd.exe" `
        -ArgumentList @("/c", "npm", "run", "dev") `
        -WorkingDirectory $ClientDir
}

Write-Host ""
Write-Host "Open http://localhost:$ClientPort once Vite finishes its first build." -ForegroundColor Green
Write-Host "Stop everything with:  scripts\dev\stop.ps1"
