<#
.SYNOPSIS
  Builds the Windows desktop app (ADR-048): NSIS installer and MSI, unsigned.

.DESCRIPTION
  Steps: build the CLI -> stage the sidecar for x86_64-pc-windows-msvc (official Node.js, flat
  node_modules, smoke-tested) -> tauri build --bundles nsis,msi -> copy the installers to
  apps/desktop/release/<version>/windows-x64/ with SHA256SUMS.

  Needs Node.js (the version in .nvmrc), pnpm, Rust (rustup, MSVC toolchain) and the Visual Studio
  C++ Build Tools. Tauri downloads NSIS and WiX on first use. WebView2 ships with Windows 10/11.

  When TAURI_SIGNING_PRIVATE_KEY (and TAURI_SIGNING_PRIVATE_KEY_PASSWORD) is set, the updater
  signatures (*.sig) are produced too. Authenticode signing is not configured: SmartScreen warns
  on first launch until the installer is signed (bundle.windows.signCommand in tauri.conf.json).

.PARAMETER SkipBuild
  Reuse the CLI build and staged sidecar; only run the Tauri bundling step.

.PARAMETER Bundles
  Comma-separated Tauri bundle types (default: nsis,msi).

.EXAMPLE
  powershell -NoProfile -ExecutionPolicy Bypass -File apps\desktop\scripts\build-windows.ps1
#>
[CmdletBinding()]
param(
  [switch]$SkipBuild,
  [string]$Bundles = 'nsis,msi'
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version 3.0

$Triple = 'x86_64-pc-windows-msvc'
$Desktop = Split-Path -Parent $PSScriptRoot
$Repo = Split-Path -Parent (Split-Path -Parent $Desktop)
$TauriDir = Join-Path $Desktop 'src-tauri'

function Step([string]$Message) { Write-Host "`n==> $Message" -ForegroundColor Cyan }

# Windows PowerShell does not stop on a failing native command; check every exit code.
function Invoke-Native([string]$File, [string[]]$Arguments, [string]$WorkDir = $Repo) {
  Push-Location $WorkDir
  try {
    & $File @Arguments
    if ($LASTEXITCODE -ne 0) { throw "$File $($Arguments -join ' ') exited with $LASTEXITCODE" }
  } finally {
    Pop-Location
  }
}

if ($env:OS -ne 'Windows_NT') { throw 'run this on Windows' }
foreach ($tool in 'node', 'pnpm', 'cargo', 'rustup') {
  if (-not (Get-Command $tool -ErrorAction SilentlyContinue)) { throw "$tool is not on PATH" }
}
if (-not (Test-Path (Join-Path $Repo 'node_modules'))) { throw 'dependencies are missing: run pnpm install --frozen-lockfile' }
if ([Environment]::Is64BitOperatingSystem -eq $false) { throw 'a 64-bit Windows is required' }

$Conf = Get-Content -Raw (Join-Path $TauriDir 'tauri.conf.json') | ConvertFrom-Json
$Version = $Conf.version
$FileBase = ($Conf.productName -replace ' ', '-') + "_$Version" + '_x64'
$Out = Join-Path $Desktop (Join-Path 'release' (Join-Path $Version 'windows-x64'))

if (-not $SkipBuild) {
  Step 'Building the CLI'
  Invoke-Native 'pnpm' @('turbo', 'run', 'build', '--filter=@spinxsca/cli...')
  Step "Staging the sidecar for $Triple"
  Invoke-Native 'node' @((Join-Path $PSScriptRoot 'stage-sidecar.mjs'), '--target', $Triple)
}
if (-not (Test-Path (Join-Path $TauriDir 'sidecar\node\node.exe'))) {
  throw 'the sidecar is not staged for Windows (run without -SkipBuild)'
}

$installed = & rustup target list --installed
if ($installed -notcontains $Triple) { Invoke-Native 'rustup' @('target', 'add', $Triple) }

Step "Building $($Conf.productName) ($Bundles)"
$tauriArgs = @('tauri', 'build', '--target', $Triple, '--bundles', $Bundles)
$configFile = $null
if ($env:TAURI_SIGNING_PRIVATE_KEY) {
  # A file, not inline JSON: Windows PowerShell mangles quotes in native command arguments.
  $configFile = Join-Path ([IO.Path]::GetTempPath()) "spinxsca-tauri-$PID.json"
  Set-Content -Path $configFile -Value '{"bundle":{"createUpdaterArtifacts":true}}' -Encoding ASCII
  $tauriArgs += @('--config', $configFile)
}
try {
  Invoke-Native 'pnpm' $tauriArgs $Desktop
} finally {
  if ($configFile) { Remove-Item -Force $configFile -ErrorAction SilentlyContinue }
}

Step "Collecting the installers in $Out"
if (Test-Path $Out) { Remove-Item -Recurse -Force $Out }
New-Item -ItemType Directory -Force -Path $Out | Out-Null
$bundleDir = Join-Path $TauriDir "target\$Triple\release\bundle"
$artifacts = @()
foreach ($pattern in 'nsis\*-setup.exe', 'msi\*.msi') {
  foreach ($file in Get-ChildItem -Path (Join-Path $bundleDir $pattern) -ErrorAction SilentlyContinue) {
    # "Spinx SecureCode AI_0.5.0_x64-setup.exe" -> "Spinx-SecureCode-AI_0.5.0_x64-setup.exe"
    $marker = "_$Version" + '_x64'
    $at = $file.Name.IndexOf($marker)
    $name = if ($at -ge 0) { $FileBase + $file.Name.Substring($at + $marker.Length) } else { $file.Name -replace ' ', '-' }
    Copy-Item $file.FullName (Join-Path $Out $name)
    $artifacts += $name
    if (Test-Path "$($file.FullName).sig") {
      Copy-Item "$($file.FullName).sig" (Join-Path $Out "$name.sig")
    }
  }
}
if ($artifacts.Count -eq 0) { throw "no installers found under $bundleDir" }

Copy-Item (Join-Path $TauriDir 'sidecar\manifest.json') (Join-Path $Out 'sidecar-manifest.json')
$sums = foreach ($name in $artifacts) {
  '{0}  {1}' -f (Get-FileHash -Algorithm SHA256 (Join-Path $Out $name)).Hash.ToLowerInvariant(), $name
}
# LF line endings and no BOM, so `sha256sum -c` / `shasum -c` read it on any platform.
[IO.File]::WriteAllText((Join-Path $Out 'SHA256SUMS'), (($sums -join "`n") + "`n"))

Step 'Done'
Write-Host 'Unsigned build: SmartScreen shows "Windows protected your PC" on first run (More info -> Run anyway).'
Get-ChildItem $Out | Format-Table Name, @{ Name = 'Size (MB)'; Expression = { [math]::Round($_.Length / 1MB, 1) } } -AutoSize
