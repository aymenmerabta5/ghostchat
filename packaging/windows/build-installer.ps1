# Builds the per-user Windows installer from a finished dist folder.
#
#   powershell -File packaging/windows/build-installer.ps1
#   powershell -File packaging/windows/build-installer.ps1 -Dist dist/windows -Out dist
#
# ghostchat.exe, its .sha256 sidecar, its .json provenance and
# THIRD-PARTY-NOTICES.txt must already be in -Dist; `cargo run -p ghostchat-xtask
# -- dist target/release/ghostchat.exe dist/windows` writes exactly that.
#
# Needs NSIS 3 (makensis). CI installs it with Chocolatey; locally set
# MAKENSIS to makensis.exe if it is not on PATH.

[CmdletBinding()]
param(
    [string]$Dist = '',
    [string]$Out = '',
    [string]$Version = ''
)

$ErrorActionPreference = 'Stop'

$repo = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path
if (-not $Dist) { $Dist = Join-Path $repo 'dist\windows' }
if (-not $Out) { $Out = Join-Path $repo 'dist' }
$Dist = (Resolve-Path $Dist).Path
if (-not (Test-Path $Out)) { New-Item -ItemType Directory -Force -Path $Out | Out-Null }
$Out = (Resolve-Path $Out).Path

$manifestPath = Join-Path $Dist 'ghostchat.exe.json'
if (-not (Test-Path $manifestPath)) {
    throw "no ghostchat.exe.json in $Dist; run the dist step first"
}
if (-not $Version) {
    $Version = (Get-Content $manifestPath -Raw | ConvertFrom-Json).version
}
if ($Version -notmatch '^\d+\.\d+\.\d+') {
    throw "version '$Version' does not start with major.minor.patch"
}

# VERSIONINFO wants four numbers; 0.1.0 becomes 0.1.0.0.
$parts = @($Version -split '[.\-+]' | Where-Object { $_ -match '^\d+$' } | ForEach-Object { [int]$_ })
while ($parts.Count -lt 4) { $parts += 0 }
$version4 = ($parts[0..3] -join '.')

function Find-Makensis {
    if ($env:MAKENSIS -and (Test-Path $env:MAKENSIS)) { return $env:MAKENSIS }
    $command = Get-Command makensis.exe -ErrorAction SilentlyContinue
    if ($command) { return $command.Source }
    $candidates = @(
        "$env:ProgramFiles\NSIS\makensis.exe",
        "${env:ProgramFiles(x86)}\NSIS\makensis.exe",
        "${env:ProgramFiles(x86)}\NSIS\Bin\makensis.exe",
        "$env:ProgramData\chocolatey\bin\makensis.exe",
        "$env:LOCALAPPDATA\Programs\NSIS\makensis.exe"
    )
    foreach ($candidate in $candidates) {
        if ($candidate -and (Test-Path $candidate)) { return $candidate }
    }
    throw 'makensis.exe not found; install NSIS 3 or set MAKENSIS to its full path'
}

$makensis = Find-Makensis
$outFile = Join-Path $Out "ghostchat-$Version-windows-x86_64-setup.exe"

Write-Host "makensis:  $makensis"
Write-Host "source:    $Dist"
Write-Host "installer: $outFile"

$arguments = @(
    '/V3',
    ('/DPRODUCT_VERSION=' + $Version),
    ('/DPRODUCT_VERSION4=' + $version4),
    ('/DSOURCE_DIR=' + $Dist),
    ('/DOUTFILE=' + $outFile),
    ('/DROOT=' + $repo),
    (Join-Path $PSScriptRoot 'ghostchat.nsi')
)

& $makensis @arguments
if ($LASTEXITCODE -ne 0) { throw "makensis failed with exit code $LASTEXITCODE" }
if (-not (Test-Path $outFile)) { throw "makensis exited 0 but $outFile is missing" }

Get-Item $outFile | Select-Object FullName, @{ n = 'MB'; e = { [math]::Round($_.Length / 1MB, 2) } }
