# Pull the latest code and reinstall dependencies (LOCAL DEVELOPMENT ONLY).
#
# This is the one dev script with side effects beyond localhost: it runs
# `git pull --ff-only` on your current branch, then reinstalls client and server
# dependencies from the committed lockfiles. It never touches production - a real
# deployment is redeployed via Docker Compose (DEPLOY.md section 9), not this.
#
# Stop the dev servers (stop.ps1) before running so Vite/uvicorn are not holding
# files open.

. (Join-Path $PSScriptRoot "_common.ps1")

Write-Head "Updating Meridian Edge (local dev)"

if ((Test-PortListening $ServerPort) -or (Test-PortListening $ClientPort)) {
    Write-Host "A dev server is still running. Run stop.ps1 first, then re-run update." -ForegroundColor Yellow
    exit 1
}

Write-Head "git pull --ff-only"
Push-Location $RepoRoot
try {
    git pull --ff-only
    if ($LASTEXITCODE -ne 0) {
        Write-Host "git pull did not fast-forward (diverged or dirty tree). Resolve by hand, then re-run." -ForegroundColor Yellow
        exit 1
    }
} finally {
    Pop-Location
}

Write-Head "client: npm ci"
Push-Location $ClientDir
try {
    npm ci
} finally {
    Pop-Location
}

Write-Head "server: virtualenv + pip install"
$venvDir = Join-Path $ServerDir ".venv"
if (-not (Test-Path $venvDir)) {
    Write-Host "Creating server\.venv ..."
    python -m venv $venvDir
}
$python = Join-Path $venvDir "Scripts\python.exe"
& $python -m pip install --upgrade pip
& $python -m pip install -r (Join-Path $ServerDir "requirements.txt") -r (Join-Path $ServerDir "requirements-dev.txt")

Write-Host ""
Write-Host "Update complete. Start the servers with scripts\dev\start.ps1." -ForegroundColor Green
