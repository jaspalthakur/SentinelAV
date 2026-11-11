# PowerShell script to build SentinelAV JAR and compile it to a native Windows .exe
# ------------------------------------------------------------------------------

# ---- Configuration -----------------------------------------------------------
$ProjectRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
$GraalVMHome = "C:\graalvm\graalvm-community-25.5.5.0.3+1.1"
$JarFile = Join-Path $ProjectRoot "SentinelAV.jar"
$ExeFile = Join-Path $ProjectRoot "SentinelAV.exe"
$LibDir = Join-Path $ProjectRoot "lib"
$FlatLafJar = Join-Path $LibDir "flatlaf-3.4.1.jar"
$BinDir = Join-Path $ProjectRoot "bin"
$NativeImage = Join-Path $GraalVMHome "bin\native-image.cmd"

# ---- Ensure GraalVM is on PATH ----------------------------------------------
if (Test-Path $GraalVMHome) {
    $env:JAVA_HOME = $GraalVMHome
    $env:PATH = "${GraalVMHome}\bin;${env:PATH}"
} else {
    Write-Host "GraalVM not found at $GraalVMHome – please adjust the path." -ForegroundColor Red
    exit 1
}

# ---- Step 1: Build the fat JAR (if not present) -----------------------------
if (-not (Test-Path $JarFile)) {
    Write-Host "SentinelAV.jar not found – building JAR..." -ForegroundColor Cyan
    $buildJarScript = Join-Path $ProjectRoot "build_jar.ps1"
    if (Test-Path $buildJarScript) {
        & $buildJarScript
        if (-not (Test-Path $JarFile)) {
            Write-Host "Failed to produce SentinelAV.jar – aborting." -ForegroundColor Red
            exit 1
        }
    } else {
        Write-Host "build_jar.ps1 not found – cannot compile JAR." -ForegroundColor Red
        exit 1
    }
} else {
    Write-Host "Found existing SentinelAV.jar – skipping JAR build." -ForegroundColor Green
}

# ---- Step 2: Run native-image -----------------------------------------------
Write-Host "Running GraalVM native-image to create Windows .exe ..." -ForegroundColor Cyan

$ClassPath = "${BinDir};${FlatLafJar}"

# Use the full path to native-image.cmd so it is not confused with PowerShell aliases
# Boolean flags use the +/- prefix; non-boolean flags use Key=Value
& $NativeImage `
    -cp "$ClassPath" `
    com.sentinel.av.Main `
    -H:Name=SentinelAV `
    -H:+AllowIncompleteClasspath `
    -H:+EnableAllSecurityServices `
    -H:EnableURLProtocols=http,https

# ---- Step 3: Verify & move the result ---------------------------------------
$built = Join-Path $ProjectRoot "SentinelAV.exe"
if (Test-Path $built) {
    if ($built -ne $ExeFile) {
        Move-Item -Force $built $ExeFile
    }
    Write-Host ""
    Write-Host "✅ SUCCESS!  Native executable ready at:" -ForegroundColor Green
    Write-Host "   $ExeFile" -ForegroundColor Green
} else {
    Write-Host ""
    Write-Host "❌ native-image did not produce SentinelAV.exe – check the output above." -ForegroundColor Red
    exit 1
}
