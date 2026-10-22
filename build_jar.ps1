# PowerShell build and packaging script for SentinelAV Runnable Fat JAR

$AppDir = $PSScriptRoot
$SrcDir = Join-Path $AppDir "src"
$BinDir = Join-Path $AppDir "bin"
$LibDir = Join-Path $AppDir "lib"
$FlatLafJar = Join-Path $LibDir "flatlaf-3.4.1.jar"
$JarFile = Join-Path $AppDir "SentinelAV.jar"
$SourcesFile = Join-Path $AppDir "sources.txt"
$ManifestFile = Join-Path $AppDir "MANIFEST.MF"

Write-Host "Cleaning old build artifacts..." -ForegroundColor Cyan
if (Test-Path $BinDir) { Remove-Item -Path $BinDir -Recurse -Force }
New-Item -ItemType Directory -Path $BinDir | Out-Null

Write-Host "Gathering Java source files..." -ForegroundColor Cyan
$javaFiles = Get-ChildItem -Path $SrcDir -Recurse -Filter "*.java" | ForEach-Object { "`"$($_.FullName.Replace('\', '/'))`"" }
[System.IO.File]::WriteAllLines($SourcesFile, $javaFiles)

Write-Host "Compiling Java sources..." -ForegroundColor Cyan
javac -encoding UTF-8 -cp "$FlatLafJar" -d "$BinDir" "@$SourcesFile"

if ($LASTEXITCODE -ne 0) {
    Write-Host "Compilation FAILED!" -ForegroundColor Red
    exit 1
}

Write-Host "Extracting FlatLaf library into bin..." -ForegroundColor Cyan
Set-Location -Path $BinDir
jar xf "$FlatLafJar"
Remove-Item -Path (Join-Path $BinDir "META-INF\*.SF"), (Join-Path $BinDir "META-INF\*.DSA"), (Join-Path $BinDir "META-INF\*.RSA") -ErrorAction SilentlyContinue

Write-Host "Creating Manifest..." -ForegroundColor Cyan
"Main-Class: com.sentinel.av.Main`n" | Out-File -FilePath $ManifestFile -Encoding ASCII

Write-Host "Creating Runnable JAR: SentinelAV.jar..." -ForegroundColor Cyan
jar cfm "$JarFile" "$ManifestFile" -C "$BinDir" .

Remove-Item $SourcesFile -ErrorAction SilentlyContinue
Remove-Item $ManifestFile -ErrorAction SilentlyContinue

Write-Host "`nSUCCESS! Standalone SentinelAV.jar created at:`n$JarFile" -ForegroundColor Green
