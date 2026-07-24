# Stop the local dev servers started by start.ps1 (LOCAL DEVELOPMENT ONLY).
#
# Finds whatever is listening on the API and client dev ports and stops it. Only
# touches those two ports, so it will not disturb unrelated processes.

. (Join-Path $PSScriptRoot "_common.ps1")

Write-Head "Stopping Meridian Edge dev servers"

function Stop-Port([int]$Port, [string]$Label) {
    $listenerPids = Get-ListenerPids $Port
    if ($listenerPids.Count -eq 0) {
        Write-Host "$Label (port $Port): nothing listening."
        return
    }
    foreach ($processId in $listenerPids) {
        try {
            $proc = Get-Process -Id $processId -ErrorAction Stop
            Stop-Process -Id $processId -Force -ErrorAction Stop
            Write-Host "$Label (port $Port): stopped $($proc.ProcessName) (PID $processId)." -ForegroundColor Green
        } catch {
            Write-Host "$Label (port $Port): could not stop PID $processId - $($_.Exception.Message)" -ForegroundColor Yellow
        }
    }
}

# Client first so it stops proxying to an API that is about to disappear.
Stop-Port $ClientPort "Client"
Stop-Port $ServerPort "API"
