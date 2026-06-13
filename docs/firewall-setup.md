# Windows Firewall Setup

Universal Clipboard listens on TCP port `43127` on one selected private LAN IPv4
address. The MVP does not change Windows Firewall automatically.

Run this command in **Administrator PowerShell**:

```powershell
New-NetFirewallRule `
  -DisplayName "Universal Clipboard LAN" `
  -Direction Inbound `
  -Action Allow `
  -Protocol TCP `
  -LocalPort 43127 `
  -Profile Private `
  -RemoteAddress LocalSubnet
```

The exact rule matters. The tray recognizes only a rule named
`Universal Clipboard LAN` that is enabled, inbound allow, TCP, local port `43127`,
Private profile, and `LocalSubnet` remote scope.

Do not create a Public-profile rule. If Windows reports the network as Public,
change the network profile to Private first.

## Verify

```powershell
Get-NetFirewallRule -DisplayName "Universal Clipboard LAN" |
  Get-NetFirewallPortFilter

Get-NetFirewallRule -DisplayName "Universal Clipboard LAN" |
  Get-NetFirewallAddressFilter
```

Expected values:

- protocol: `TCP`
- local port: `43127`
- profile: `Private`
- remote address: `LocalSubnet`

## Remove

```powershell
Remove-NetFirewallRule -DisplayName "Universal Clipboard LAN"
```

## If iPhone Still Cannot Connect

- Confirm Windows and iPhone are on the same private Wi-Fi or Ethernet LAN.
- Disable VPN temporarily on either device.
- Avoid guest Wi-Fi or client isolation.
- Make sure the tray-selected adapter matches the iPhone network.
- Confirm no other process is using TCP `43127`.
- Try opening the tray URL directly in Safari, for example
  `http://192.168.1.5:43127/`.

The tray's local port-listening check only proves the Windows app is listening. It
does not prove the iPhone can reach the PC through Wi-Fi isolation or firewall
policy.
