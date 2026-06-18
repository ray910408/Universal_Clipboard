param(
    [string]$DisplayName = 'Universal Clipboard LAN'
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

if (-not (Test-IsWindowsHost)) {
    throw 'This script manages Windows Firewall rules. Run it from Windows PowerShell or PowerShell on Windows.'
}

if (-not (Test-IsAdministrator)) {
    throw 'Removing Windows Firewall rules requires Administrator PowerShell. Reopen PowerShell as Administrator and rerun: .\scripts\remove-firewall.ps1'
}

Write-Step "Removing Windows Firewall rule: $DisplayName"

$rules = @(
    Get-NetFirewallRule -Name $DisplayName -ErrorAction SilentlyContinue
    Get-NetFirewallRule -DisplayName $DisplayName -ErrorAction SilentlyContinue
) | Sort-Object -Property Name -Unique
if (-not $rules) {
    Write-Info "No firewall rule found: $DisplayName"
    exit 0
}

$rules | Remove-NetFirewallRule
Write-Info "Removed firewall rule: $DisplayName"
