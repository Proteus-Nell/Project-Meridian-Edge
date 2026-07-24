# Read-only health check of the local dev setup (LOCAL DEVELOPMENT ONLY).
#
# Changes nothing: reports tool versions, whether dependencies are installed,
# and whether the dev servers are up and reachable. Run it when "it works on my
# machine" needs checking, or before filing a bug.

. (Join-Path $PSScriptRoot "_common.ps1")

$problems = 0

function Report-Ok([string]$Text) { Write-Host "  [ok]   $Text" -ForegroundColor Green }
function Report-Warn([string]$Text) {
    Write-Host "  [warn] $Text" -ForegroundColor Yellow
    $script:problems += 1
}

Write-Head "Toolchain"
$node = Get-Command node -ErrorAction SilentlyContinue
if ($node) { Report-Ok "node    $(& node --version)" } else { Report-Warn "node not found on PATH (need >= 22)" }
$npm = Get-Command npm -ErrorAction SilentlyContinue
if ($npm) { Report-Ok "npm     $(& npm --version)" } else { Report-Warn "npm not found on PATH" }

$venvPython = Join-Path $ServerDir ".venv\Scripts\python.exe"
if (Test-Path $venvPython) {
    Report-Ok "python  $(& $venvPython --version)  (server\.venv)"
} else {
    $sysPython = Get-Command python -ErrorAction SilentlyContinue
    if ($sysPython) {
        Report-Warn "server\.venv missing; system python is $(& python --version). Run update.ps1 to create the venv."
    } else {
        Report-Warn "no Python found (need >= 3.12). Run update.ps1 after installing Python."
    }
}

Write-Head "Dependencies"
if (Test-Path (Join-Path $ClientDir "node_modules")) { Report-Ok "client\node_modules present" } else { Report-Warn "client\node_modules missing - run update.ps1" }
if (Test-Path $venvPython) { Report-Ok "server virtualenv present" } else { Report-Warn "server virtualenv missing - run update.ps1" }

Write-Head "Dev servers"
if (Test-PortListening $ServerPort) {
    Report-Ok "API listening on $ServerPort"
    # A 404 from a bogus path still proves the app is serving.
    try {
        $res = Invoke-WebRequest -Uri "http://127.0.0.1:$ServerPort/v1/does-not-exist" -UseBasicParsing -TimeoutSec 5 -ErrorAction Stop
        Report-Warn "API answered but a missing route returned $($res.StatusCode) (expected 404)"
    } catch [System.Net.WebException] {
        $resp = $_.Exception.Response
        if ($resp -and [int]$resp.StatusCode -eq 404) {
            Report-Ok "API responds (404 on an unknown route, as expected)"
        } else {
            Report-Warn "API on $ServerPort did not respond cleanly: $($_.Exception.Message)"
        }
    }
} else {
    Write-Host "  [info] API not running on $ServerPort (start.ps1 to launch)"
}

if (Test-PortListening $ClientPort) {
    Report-Ok "Client (Vite) listening on $ClientPort"
} else {
    Write-Host "  [info] Client not running on $ClientPort (start.ps1 to launch)"
}

Write-Host ""
if ($problems -eq 0) {
    Write-Host "No problems found." -ForegroundColor Green
} else {
    Write-Host "$problems item(s) need attention (see [warn] above)." -ForegroundColor Yellow
}
