# Universal Clipboard

Universal Clipboard is a personal Windows-to-iPhone text bridge. Copy plain text on
Windows, open the paired local page on iPhone Safari, tap **Copy to iPhone**, then
paste in another iPhone app.

This MVP is intentionally local-first:

- no account;
- no cloud relay;
- no iPhone app;
- no clipboard payloads written by the app to disk;
- latest three approved text items only.

## Requirements

- Windows PC on a trusted **Private** Ethernet or Wi-Fi network.
- iPhone Safari on the same LAN.
- TCP port `43127` reachable from the iPhone.
- For source builds, .NET 10 SDK.

The app serves plain HTTP on the selected LAN address, for example
`http://192.168.1.5:43127/`. Do not use it on public, guest, hotel, school, or
untrusted networks.

## Build From Source

```powershell
$dotnet = 'C:\Universal_Clipboard\.dotnet\dotnet.exe'
& $dotnet restore UniversalClipboard.slnx
& $dotnet build UniversalClipboard.slnx -c Release --no-restore
& $dotnet test UniversalClipboard.slnx -c Release --no-build
& $dotnet publish src/UniversalClipboard.App/UniversalClipboard.App.csproj -c Release -r win-x64 --self-contained true -o artifacts/win-x64
Get-FileHash artifacts/win-x64/UniversalClipboard.App.exe, artifacts/win-x64/UniversalClipboard.App.dll -Algorithm SHA256
```

Run:

```powershell
.\artifacts\win-x64\UniversalClipboard.App.exe
```

Unsigned local builds may trigger Windows SmartScreen. That is expected for this
MVP; verify the source and checksums before running builds you did not create.

## First Setup

1. Set the Windows network profile to **Private**.
2. Add the firewall rule from [docs/firewall-setup.md](docs/firewall-setup.md).
3. Launch `UniversalClipboard.App.exe`.
4. If multiple eligible LAN interfaces are shown, choose the one on the same network
   as the iPhone.
5. Choose a pairing duration. The default is **5 hours**.
6. Generate a pairing QR code in the tray window.
7. Open or scan the pairing URL on iPhone Safari.
8. Copy text on Windows. Sensitive-looking text is held for approval in the tray.
9. On iPhone, tap **Copy to iPhone**. If browser copy is unavailable over HTTP, use
   the selected textarea and long-press **Copy**.

## Pairing Durations

- **1 hour**: short session for a single task.
- **5 hours**: default work-session duration.
- **1 day**: useful for one-day setup or travel.
- **1 week**: longer trusted-device convenience.
- **Permanent**: server-side authorization does not expire until revoked. This is
  high risk; revoke it when no longer needed. Safari may still delete its cookie.

Every paired browser authorization can read the latest three shared items while it
is valid. Revoke one browser or revoke all from the tray window.

## Privacy And Security Limits

Clipboard text stays in process memory only. Restarting the Windows app clears
shared and pending clipboard content. Authorization metadata is stored under
`%LOCALAPPDATA%\UniversalClipboard\authorizations.v1.bin` and protected with Windows
DPAPI for the current user.

Important limits:

- The MVP uses HTTP, not HTTPS. Same-network traffic can be observed or modified by
  a capable attacker.
- The session cookie is scoped to `/clip-api`, but HTTP cookies are not isolated by
  TCP port. A different service on the same IP and matching path could receive it.
- The cookie cannot use the `Secure` flag because the MVP is HTTP.
- Sensitive detection is a guardrail, not data loss prevention. It covers PEM
  private keys, GitHub-style tokens, and AWS access-key identifiers.
- Windows may write process memory to pagefile, hibernation files, or crash dumps.
- A compromised Windows machine, paired browser, or LAN invalidates the trust model.

## Troubleshooting

- **Tray says Public network**: switch the Windows network profile to Private.
- **iPhone cannot load the URL**: check same Wi-Fi, guest/client isolation, VPN, and
  Windows Firewall.
- **Firewall shows Unknown**: the tray only recognizes the exact Private +
  LocalSubnet rule documented in [docs/firewall-setup.md](docs/firewall-setup.md).
- **Port conflict**: another process is listening on TCP `43127`; stop it before
  starting sharing.
- **Expired or reused QR**: generate a new pairing code. Codes are single-use and
  expire after two minutes.
- **Copy button does not confirm Copied**: use the visible selected text and
  long-press Copy. Manual copy is the reliable HTTP baseline for Safari.

## Manual Release Gates

Before a public release, complete the real-device checklist in
[docs/manual-transfer-fixtures.md](docs/manual-transfer-fixtures.md), including five
actual Windows-to-iPhone transfers. Do not invent those observations.
