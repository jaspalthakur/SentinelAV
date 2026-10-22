# PowerShell launcher script for SentinelAV Standalone App

$AppDir = $PSScriptRoot
$JarFile = Join-Path $AppDir "SentinelAV.jar"

if (-not (Test-Path $JarFile)) {
    Write-Host "SentinelAV.jar not found. Building project..." -ForegroundColor Yellow
    powershell -ExecutionPolicy Bypass -File (Join-Path $AppDir "build_jar.ps1")
}

if ($args.Count -gt 0) {
    # Arguments are forwarded to the headless CLI, e.g. .\run.ps1 --scan . --json
    & java -jar "$JarFile" @args
    exit $LASTEXITCODE
}

Write-Host "Launching SentinelAV Application in separate environment..." -ForegroundColor Green
Start-Process -FilePath "javaw.exe" -ArgumentList "-jar `"$JarFile`"" -WorkingDirectory "$AppDir"
Write-Host "SentinelAV GUI application launched successfully!" -ForegroundColor Cyan
