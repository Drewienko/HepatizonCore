param(
    [string]$BuildDir = "out/build/msvc-debug",
    [string]$Config = "Debug",
    [string]$QtRoot = "C:/Qt/6.10.1/msvc2022_64"
)

$qtBin = Join-Path $QtRoot "bin"
$windeployqt = Join-Path $qtBin "windeployqt.exe"

if (-not (Test-Path $windeployqt)) {
    Write-Error "windeployqt not found at $windeployqt. Set -QtRoot to your Qt msvc install."
    exit 1
}

$exeCandidates = @(
    (Join-Path $BuildDir "$Config/hepatizoncore_gui.exe")
    (Join-Path $BuildDir "src/$Config/hepatizoncore_gui.exe")
)
$exePath = $exeCandidates | Where-Object { Test-Path $_ } | Select-Object -First 1
if (-not $exePath) {
    Write-Error "Executable not found in: $($exeCandidates -join ', '). Build the GUI target first."
    exit 1
}

$configFlag = if ($Config -ieq "Debug") { "--debug" } else { "--release" }

& $windeployqt $configFlag --compiler-runtime $exePath
if ($LASTEXITCODE -ne 0) {
    exit $LASTEXITCODE
}

Write-Host "windeployqt completed for $exePath"
