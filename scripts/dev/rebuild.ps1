# Clean-reinstall the client and produce a production bundle (LOCAL DEV).
#
# Use after a dependency change or when a stale node_modules is suspected. This
# runs the same `tsc --noEmit && vite build` the CI build gate runs, so it also
# catches type errors. It does NOT deploy anything - the bundle lands in
# client\dist for inspection; real deploys build inside Docker (DEPLOY.md).

. (Join-Path $PSScriptRoot "_common.ps1")

Write-Head "Rebuilding the client bundle"

if (Test-PortListening $ClientPort) {
    Write-Host "The client dev server is running on $ClientPort. Run stop.ps1 first." -ForegroundColor Yellow
    exit 1
}

Push-Location $ClientDir
try {
    Write-Head "npm ci"
    npm ci
    if ($LASTEXITCODE -ne 0) { throw "npm ci failed" }

    Write-Head "npm run build"
    npm run build
    if ($LASTEXITCODE -ne 0) { throw "build failed" }
} finally {
    Pop-Location
}

Write-Host ""
Write-Host "Bundle written to client\dist. Preview it with:  cd client; npm run preview" -ForegroundColor Green
