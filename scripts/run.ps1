param(
    [switch]$ConfigureFirewall,
    [ValidateSet('Debug', 'Release')]
    [string]$Configuration = 'Release'
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

function Test-IsAdministrator {
    if (-not (Test-IsWindowsHost)) {
        return $false
    }

    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = [Security.Principal.WindowsPrincipal]::new($identity)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Invoke-DotNetCommand {
    param(
        [string]$DotNetPath,
        [string[]]$Arguments,
        [switch]$AllowCtrlCExit
    )

    & $DotNetPath @Arguments
    $exitCode = [int]$LASTEXITCODE
    if ($exitCode -eq 0) {
        return
    }

    $unsignedExitCode = if ($exitCode -lt 0) {
        [uint32]([int64]$exitCode + 4294967296)
    } else {
        [uint32]$exitCode
    }

    if ($AllowCtrlCExit -and $unsignedExitCode -eq 0xC000013A) {
        return
    }

    throw ("dotnet {0} failed with exit code 0x{1:X8} ({2})." -f (
        $Arguments -join ' '),
        $unsignedExitCode,
        $exitCode)
}

function Test-RestoreRequired {
    param(
        [string]$RepoRoot,
        [string]$Solution
    )

    $projectRoots = @(
        Join-Path $RepoRoot 'src'
        Join-Path $RepoRoot 'tests'
    ) | Where-Object { Test-Path $_ }
    $projects = @(
        $projectRoots | ForEach-Object {
            Get-ChildItem -Path $_ -Recurse -Filter *.csproj -File
        }
    )

    if ($projects.Count -eq 0) {
        return $true
    }

    $assetPaths = @(
        $projects | ForEach-Object {
            Join-Path $_.DirectoryName 'obj/project.assets.json'
        }
    )

    if ($assetPaths | Where-Object { -not (Test-Path $_) }) {
        return $true
    }

    $restoreInputs = @(
        $Solution
        Join-Path $RepoRoot 'Directory.Build.props'
        Join-Path $RepoRoot 'Directory.Packages.props'
    )
    $restoreInputs += $projects.FullName
    $restoreInputs += @(
        $projects | ForEach-Object {
            Join-Path $_.DirectoryName 'packages.lock.json'
        }
    )

    $existingInputs = @(
        $restoreInputs |
            Where-Object { Test-Path $_ } |
            ForEach-Object { Get-Item $_ }
    )
    if ($existingInputs.Count -eq 0) {
        return $true
    }

    $latestInput = (
        $existingInputs |
            Sort-Object LastWriteTimeUtc -Descending |
            Select-Object -First 1
    ).LastWriteTimeUtc
    $oldestAsset = (
        $assetPaths |
            ForEach-Object { Get-Item $_ } |
            Sort-Object LastWriteTimeUtc |
            Select-Object -First 1
    ).LastWriteTimeUtc

    return $latestInput -gt $oldestAsset
}

$repoRoot = Split-Path -Parent $PSScriptRoot
$solution = Join-Path $repoRoot 'UniversalClipboard.slnx'
$appProject = Join-Path $repoRoot 'src/UniversalClipboard.App/UniversalClipboard.App.csproj'
$localDotnet = Join-Path $repoRoot '.dotnet/dotnet.exe'

if (-not (Test-IsWindowsHost)) {
    throw 'Universal Clipboard is a Windows tray application. Run this script from Windows PowerShell or PowerShell on Windows.'
}

if (-not (Test-Path $solution)) {
    throw "Solution not found: $solution. Run this script from a clone of the Universal_Clipboard repository."
}

if (-not (Test-Path $appProject)) {
    throw "App project not found: $appProject"
}

$bootstrapScript = Join-Path $PSScriptRoot 'bootstrap.ps1'
if (Test-Path $bootstrapScript) {
    & $bootstrapScript
}

if (Test-Path $localDotnet) {
    $dotnet = $localDotnet
} else {
    $dotnetCommand = Get-Command dotnet -ErrorAction SilentlyContinue
    if (-not $dotnetCommand) {
        throw '.NET SDK not found. Install .NET 10 SDK, then rerun scripts/run.ps1.'
    }
    $dotnet = $dotnetCommand.Source
}

Write-Step "Using dotnet: $dotnet"
& $dotnet --version | ForEach-Object { Write-Info ".NET SDK $_" }

if ($ConfigureFirewall) {
    Write-Step 'Configuring Windows Firewall rule for iPhone LAN access'

    if (-not (Test-IsAdministrator)) {
        throw 'The -ConfigureFirewall option must be run from Administrator PowerShell. Reopen PowerShell as Administrator and rerun: .\scripts\run.ps1 -ConfigureFirewall'
    }

    $displayName = 'Universal Clipboard LAN'
    $existingRule = Get-NetFirewallRule -DisplayName $displayName -ErrorAction SilentlyContinue

    if ($existingRule) {
        Write-Info "Firewall rule already exists: $displayName"
    } else {
        New-NetFirewallRule `
            -DisplayName $displayName `
            -Direction Inbound `
            -Action Allow `
            -Protocol TCP `
            -LocalPort 43127 `
            -Profile Private `
            -RemoteAddress LocalSubnet | Out-Null
        Write-Info "Created firewall rule: $displayName"
    }
} else {
    Write-Step 'Skipping firewall changes'
    Write-Info 'To create the Private + LocalSubnet firewall rule, rerun from Administrator PowerShell:'
    Write-Info '.\scripts\run.ps1 -ConfigureFirewall'
}

Push-Location $repoRoot
try {
    if (Test-RestoreRequired -RepoRoot $repoRoot -Solution $solution) {
        Write-Step 'Restoring packages'
        Invoke-DotNetCommand -DotNetPath $dotnet -Arguments @('restore', $solution)
    } else {
        Write-Step 'Skipping package restore'
        Write-Info 'Restore assets are current. Package/security checks still run in CI.'
    }

    Write-Step "Building Universal Clipboard ($Configuration)"
    Invoke-DotNetCommand -DotNetPath $dotnet -Arguments @(
        'build',
        $solution,
        '-c',
        $Configuration,
        '--no-restore'
    )

    Write-Step 'Starting Universal Clipboard tray app'
    Write-Info 'Windows management stays in the tray UI.'
    Write-Info 'Use the tray window to choose the LAN interface, generate a QR code, and view the iPhone URL.'
    Write-Info 'iPhone Safari should use the tray URL, for example: https://<LAN-IP>:43127/'
    Write-Info 'Keep this PowerShell window open while running from source. Press Ctrl+C to stop dotnet run.'

    Invoke-DotNetCommand -DotNetPath $dotnet -Arguments @(
        'run',
        '--project',
        $appProject,
        '-c',
        $Configuration,
        '--no-build'
    ) -AllowCtrlCExit
} finally {
    Pop-Location
}
