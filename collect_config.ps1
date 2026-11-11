$graalHome = 'C:\graalvm\graalvm-community-25.5.5.0.3+1.1'
$java = Join-Path $graalHome 'bin\java.exe'
$jar = 'D:\Projects\SentinelAV\SentinelAV.jar'
$confDir = 'D:\Projects\SentinelAV\graal-conf'

New-Item -ItemType Directory -Force -Path $confDir | Out-Null

Write-Host "Running app with native-image-agent to collect reflection config..." -ForegroundColor Cyan
Write-Host "(The SentinelAV window will open - interact with ALL panels/features, then close it)" -ForegroundColor Yellow

& $java "-agentlib:native-image-agent=config-output-dir=$confDir" -jar $jar

Write-Host "Config files generated in: $confDir" -ForegroundColor Green
Get-ChildItem $confDir
