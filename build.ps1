# PowerShell compilation script for SentinelAV

$AppDir = $PSScriptRoot
$SrcDir = Join-Path $AppDir "src"
$BinDir = Join-Path $AppDir "bin"
$LibDir = Join-Path $AppDir "lib"
$FlatLafJar = Join-Path $LibDir "flatlaf-3.4.1.jar"
$SourcesFile = Join-Path $AppDir "sources.txt"

if (-not (Test-Path $BinDir)) {
    New-Item -ItemType Directory -Path $BinDir | Out-Null
}

Write-Host "Gathering Java source files..." -ForegroundColor Cyan

# Forward slashes + quoted string in argfile
$javaFiles = Get-ChildItem -Path $SrcDir -Recurse -Filter "*.java" | ForEach-Object { "`"$($_.FullName.Replace('\', '/'))`"" }
[System.IO.File]::WriteAllLines($SourcesFile, $javaFiles)

Write-Host "Compiling SentinelAV with javac..." -ForegroundColor Cyan
javac -encoding UTF-8 -cp "$FlatLafJar" -d "$BinDir" "@$SourcesFile"

if ($LASTEXITCODE -eq 0) {
    Write-Host "Compilation SUCCESSFUL! Binaries output to: $BinDir" -ForegroundColor Green
    Remove-Item $SourcesFile -ErrorAction SilentlyContinue
} else {
    Write-Host "Compilation FAILED!" -ForegroundColor Red
}
