# Developer scripts (Windows PowerShell)

Convenience wrappers for the local dev loop on Windows. **Local development
only** - they start Vite and an auto-reloading uvicorn on `localhost` with
SQLite. None of this is a deployment path; production runs via Docker Compose
(see [DEPLOY.md](../../DEPLOY.md)).

| Script | Does |
|---|---|
| `start.ps1` | Start the API (uvicorn `--reload`, :8000) and client (Vite, :5173) each in their own window. Skips a server already listening. |
| `stop.ps1` | Stop whatever is listening on the two dev ports. Touches only those ports. |
| `update.ps1` | `git pull --ff-only`, then reinstall client (`npm ci`) and server (venv + `pip install`) deps from the lockfiles. The only script with effects beyond localhost. |
| `rebuild.ps1` | Clean client reinstall + `npm run build` (the CI build gate; catches type errors). Bundle lands in `client\dist`. |
| `diagnose.ps1` | Read-only health check: tool versions, installed deps, and whether the dev servers are up and answering. Changes nothing. |

`_common.ps1` holds shared helpers and is dot-sourced by the others - do not run
it directly.

## Usage

From anywhere in the repo:

```powershell
powershell -ExecutionPolicy Bypass -File scripts\dev\start.ps1
```

or, in a session that already allows local scripts (`Set-ExecutionPolicy
-Scope CurrentUser RemoteSigned` once):

```powershell
.\scripts\dev\start.ps1     # then diagnose.ps1 / stop.ps1 as needed
```

The client dev port defaults to 5173; override it with `$env:PORT` before
`start.ps1` to run a second instance (useful for testing two users - each
browser origin is its own encrypted store).

## Notes

- Windows PowerShell 5.1 compatible (no `&&`, ternary, or null-coalescing).
- Cross-platform equivalents are not provided; on macOS/Linux run the two
  commands from the [README](../../README.md) quick start directly, or use the
  Docker Compose setup.
