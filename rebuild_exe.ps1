$graalHome = 'C:\graalvm\graalvm-community-25.5.5.0.3+1.1'
$nativeImage = Join-Path $graalHome 'bin\native-image.cmd'
$ProjectRoot = 'D:\Projects\SentinelAV'
$BinDir = Join-Path $ProjectRoot 'bin'
$FlatLafJar = Join-Path $ProjectRoot 'lib\flatlaf-3.4.1.jar'
$ConfDir = Join-Path $ProjectRoot 'graal-conf'

$env:JAVA_HOME = $graalHome
$env:PATH = "$graalHome\bin;$env:PATH"

Write-Host "Rebuilding SentinelAV.exe with reflection config..." -ForegroundColor Cyan

$ClassPath = "${BinDir};${FlatLafJar}"

& $nativeImage `
    -cp "$ClassPath" `
    com.sentinel.av.Main `
    -o SentinelAV `
    -H:+UnlockExperimentalVMOptions `
    -H:+AllowIncompleteClasspath `
    -H:EnableURLProtocols=http,https `
    --enable-all-security-services `
    --enable-native-access=ALL-UNNAMED `
    -H:ConfigurationFileDirectories="$ConfDir" `
    -march=native

$exePath = Join-Path $ProjectRoot 'SentinelAV.exe'
if (Test-Path $exePath) {
    Write-Host ""
    Write-Host "SUCCESS! SentinelAV.exe built at: $exePath" -ForegroundColor Green
    Write-Host ""
    Write-Host "Now packaging into a distributable ZIP..." -ForegroundColor Cyan
    $zipPath = Join-Path $ProjectRoot 'SentinelAV-Windows.zip'
    # Remove old zip if exists
    if (Test-Path $zipPath) { Remove-Item $zipPath -Force }
    # Package exe + all required DLLs into a single zip
    $filesToZip = Get-ChildItem -Path $ProjectRoot -Filter "*.dll" | Select-Object -ExpandProperty FullName
    $filesToZip += $exePath
    Compress-Archive -Path $filesToZip -DestinationPath $zipPath
    Write-Host ""
    Write-Host "Distributable ZIP ready: $zipPath" -ForegroundColor Green
    Write-Host "Share this ZIP with anyone - they just extract and double-click SentinelAV.exe!" -ForegroundColor Green
} else {
    Write-Host "Build FAILED - check the output above." -ForegroundColor Red
    exit 1
}
