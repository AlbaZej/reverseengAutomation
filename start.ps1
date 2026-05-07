# Deshifro startup script — sets up PATH and starts API + web
# Usage: .\start.ps1

$ErrorActionPreference = "Stop"
$ProjectRoot = $PSScriptRoot

# Add bundled radare2 to PATH (if present)
$R2Bin = Join-Path $ProjectRoot ".tools\radare2-6.1.4-w64\bin"
if (Test-Path $R2Bin) {
    $env:PATH = "$R2Bin;$env:PATH"
    Write-Host "[+] radare2 added to PATH"
}

# Load .env if it exists
$EnvFile = Join-Path $ProjectRoot ".env"
if (Test-Path $EnvFile) {
    Get-Content $EnvFile | Where-Object { $_ -match '^[A-Z_]+=' } | ForEach-Object {
        $name, $value = $_.Split('=', 2)
        Set-Item -Path "env:$name" -Value $value
    }
    Write-Host "[+] Loaded .env"
}

# Default secret if not set
if (-not $env:DESHIFRO_SECRET_KEY) {
    $env:DESHIFRO_SECRET_KEY = "dev-secret-only"
}

Write-Host ""
Write-Host "Starting Deshifro..."
Write-Host "  API:  http://localhost:8000"
Write-Host "  Web:  http://localhost:3000"
Write-Host ""
Write-Host "Press Ctrl+C in either window to stop."
Write-Host ""

# Start API in a new PowerShell window
Start-Process powershell -ArgumentList @(
    "-NoExit",
    "-Command",
    "cd '$ProjectRoot'; `$env:PATH = '$R2Bin;' + `$env:PATH; python -m uvicorn api.main:app --host 127.0.0.1 --port 8000 --reload"
)

# Start web in another window
Start-Process powershell -ArgumentList @(
    "-NoExit",
    "-Command",
    "cd '$ProjectRoot\web'; npm run dev"
)

Write-Host "Both windows opened. Open http://localhost:3000 in your browser."
