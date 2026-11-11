$ErrorActionPreference = "Stop"
$ProjectDir = "D:\Projects\SentinelAV"
$CscPath = "C:\Windows\Microsoft.NET\Framework64\v4.0.30319\csc.exe"
$ZipPayload = Join-Path $ProjectDir "payload.zip"
$TargetExe = Join-Path $ProjectDir "SentinelAV-Installer.exe"
$CsSource = Join-Path $ProjectDir "InstallerSource.cs"

Set-Location $ProjectDir

Write-Host "Creating zip package containing SentinelAV executable and libraries..." -ForegroundColor Cyan
if (Test-Path $ZipPayload) {
    Remove-Item -Force $ZipPayload
}

# Create zip with SentinelAV.exe and required DLLs
$filesToBundle = @(
    "SentinelAV.exe",
    "awt.dll",
    "fontmanager.dll",
    "freetype.dll",
    "java.dll",
    "javaaccessbridge.dll",
    "javajpeg.dll",
    "jawt.dll",
    "jsound.dll",
    "jvm.dll",
    "lcms.dll"
)

$tempFolder = Join-Path $env:TEMP "SentinelAV_Bundle"
if (Test-Path $tempFolder) { Remove-Item -Recurse -Force $tempFolder }
New-Item -ItemType Directory -Force -Path $tempFolder | Out-Null

foreach ($f in $filesToBundle) {
    $src = Join-Path $ProjectDir $f
    if (Test-Path $src) {
        Copy-Item $src -Destination $tempFolder
    } else {
        Write-Warning "File missing: $src"
    }
}

Compress-Archive -Path "$tempFolder\*" -DestinationPath $ZipPayload -Force
Remove-Item -Recurse -Force $tempFolder

Write-Host "Compiling stand-alone single EXE with embedded payload..." -ForegroundColor Cyan
& $CscPath /target:winexe /optimize+ /platform:x64 `
    /reference:System.dll,System.Windows.Forms.dll,System.IO.Compression.dll,System.IO.Compression.FileSystem.dll `
    /resource:"$ZipPayload,SentinelAV_Payload.zip" `
    /out:"$TargetExe" `
    "$CsSource"

if (Test-Path $TargetExe) {
    $sizeMb = [math]::Round((Get-Item $TargetExe).Length / 1MB, 2)
    Write-Host "SUCCESS! Single standalone installer EXE created at:" -ForegroundColor Green
    Write-Host "  $TargetExe ($sizeMb MB)" -ForegroundColor Green
    Remove-Item -Force $ZipPayload
} else {
    Write-Error "Compilation of SentinelAV-Installer.exe failed!"
}
