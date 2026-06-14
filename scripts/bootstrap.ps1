param(
    [string]$Channel = '10.0',
    [string]$InstallDir,
    [switch]$Force
)

$ErrorActionPreference = 'Stop'

function Write-Step {
    param([string]$Message)
    Write-Host "==> $Message" -ForegroundColor Cyan
}

function Write-Info {
    param([string]$Message)
    Write-Host "    $Message" -ForegroundColor DarkGray
}

function Test-IsWindowsHost {
    if ($PSVersionTable.PSEdition -eq 'Desktop') {
        return $true
    }

    return [bool]$IsWindows
}

function Test-DotNetSdk {
    param(
        [string]$DotNetPath,
        [int]$RequiredMajor
    )

    if (-not $DotNetPath -or -not (Test-Path $DotNetPath)) {
        return $false
    }

    try {
        $versionText = (& $DotNetPath --version 2>$null | Select-Object -First 1)
        if (-not $versionText) {
            return $false
        }

        $version = [version]$versionText
        if ($version.Major -lt $RequiredMajor) {
            Write-Info "Found dotnet $versionText at $DotNetPath, but .NET $RequiredMajor or newer is required."
            return $false
        }

        Write-Info "Found dotnet $versionText at $DotNetPath"
        return $true
    } catch {
        return $false
    }
}

function Get-SystemDotNetPath {
    $command = Get-Command dotnet -ErrorAction SilentlyContinue
    if ($command) {
        return $command.Source
    }

    return $null
}

$repoRoot = Split-Path -Parent $PSScriptRoot
$solution = Join-Path $repoRoot 'UniversalClipboard.slnx'

if (-not $InstallDir) {
    $InstallDir = Join-Path $repoRoot '.dotnet'
}

$localDotnet = Join-Path $InstallDir 'dotnet.exe'
$requiredMajor = 10

if (-not (Test-IsWindowsHost)) {
    throw 'Universal Clipboard is a Windows tray application. Run bootstrap.ps1 from Windows PowerShell or PowerShell on Windows.'
}

if (-not (Test-Path $solution)) {
    throw "Solution not found: $solution. Run this script from a clone of the Universal_Clipboard repository."
}

Write-Step 'Checking .NET SDK'

if (-not $Force) {
    if (Test-DotNetSdk -DotNetPath $localDotnet -RequiredMajor $requiredMajor) {
        Write-Step 'Bootstrap complete'
        Write-Info 'Using repository-local .NET SDK.'
        return
    }

    $systemDotnet = Get-SystemDotNetPath
    if ($systemDotnet -and (Test-DotNetSdk -DotNetPath $systemDotnet -RequiredMajor $requiredMajor)) {
        Write-Step 'Bootstrap complete'
        Write-Info 'Using system .NET SDK. No repository-local install was needed.'
        return
    }
}

Write-Step "Installing .NET SDK from channel $Channel into $InstallDir"
Write-Info 'The install is repository-local and does not require Administrator permissions.'

New-Item -ItemType Directory -Force -Path $InstallDir | Out-Null

$installScript = Join-Path ([System.IO.Path]::GetTempPath()) 'dotnet-install.ps1'
$previousProgressPreference = $ProgressPreference
$ProgressPreference = 'SilentlyContinue'
try {
    Invoke-WebRequest -Uri 'https://dot.net/v1/dotnet-install.ps1' -OutFile $installScript -UseBasicParsing
} finally {
    $ProgressPreference = $previousProgressPreference
}

& powershell -NoProfile -ExecutionPolicy Bypass -File $installScript `
    -Channel $Channel `
    -InstallDir $InstallDir `
    -Architecture x64 `
    -NoPath

if (-not (Test-DotNetSdk -DotNetPath $localDotnet -RequiredMajor $requiredMajor)) {
    throw "Installed dotnet could not be verified at $localDotnet"
}

Write-Step 'Bootstrap complete'
Write-Info "Repository-local dotnet is ready: $localDotnet"
