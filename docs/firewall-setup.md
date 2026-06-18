# Windows Firewall Setup

Universal Clipboard listens on TCP port `43127` on one selected private LAN IPv4
address. `UniversalClipboard.exe` manages the required Windows Firewall rule for
the normal runtime path: it asks for elevation on launch if it needs to create or
repair the rule, and Tray **Exit** removes the rule during normal shutdown.

If automatic setup is denied or you need to prepare the rule before launch, run
this command in **Administrator PowerShell**:

```powershell
New-NetFirewallRule `
  -Name "Universal Clipboard LAN" `
  -DisplayName "Universal Clipboard LAN" `
  -Direction Inbound `
  -Action Allow `
  -Protocol TCP `
  -LocalPort 43127 `
  -Profile Private `
  -RemoteAddress LocalSubnet
```

The exact rule matters. The tray recognizes only a rule whose `Name` and
`DisplayName` are both `Universal Clipboard LAN`, enabled, inbound allow, TCP,
local port `43127`, Private profile, and `LocalSubnet` remote scope.

Do not create a Public-profile rule. If Windows reports the network as Public,
change the network profile to Private first.

## Verify

```powershell
$rule = Get-NetFirewallRule -Name "Universal Clipboard LAN"

$rule |
  Get-NetFirewallPortFilter

$rule |
  Get-NetFirewallAddressFilter
```

Expected values:

- protocol: `TCP`
- local port: `43127`
- profile: `Private`
- remote address: `LocalSubnet`

## Remove

Tray **Exit** removes the runtime rule during normal shutdown. If the process is
terminated or automatic cleanup fails, run this command in **Administrator
PowerShell**:

```powershell
.\scripts\remove-firewall.ps1
```

Equivalent manual command:

```powershell
Remove-NetFirewallRule -Name "Universal Clipboard LAN"
```

## If Phone Still Cannot Connect

- Confirm Windows and the phone are on the same private Wi-Fi or Ethernet LAN.
- Disable VPN temporarily on either device.
- Avoid guest Wi-Fi or client isolation.
- Make sure the tray-selected adapter matches the phone network.
- Confirm no other process is using TCP `43127`.
- Try opening the tray URL directly in iPhone Safari or Android Chrome, for example
  `https://192.168.1.5:43127/`. The browser may show a certificate warning because
  the MVP uses a self-signed HTTPS certificate. The tray shows the current HTTPS
  identity short code and fingerprint; if the browser reports a changed certificate
  unexpectedly, stop and verify the tray identity before pairing again.

The tray's local port-listening check only proves the Windows app is listening. It
does not prove the phone can reach the PC through Wi-Fi isolation or firewall
policy.
