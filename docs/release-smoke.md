# Release Smoke Notes

Date: 2026-06-13

## Automated Verification

- `dotnet test UniversalClipboard.slnx -c Release --no-restore /p:NuGetAudit=false`
  passed:
  - Core: 105 passed
  - App: 167 passed
- `git diff --check` passed with CRLF normalization warnings only.
- `dotnet publish src\UniversalClipboard.App\UniversalClipboard.App.csproj -c Release -r win-x64 --self-contained true --no-restore -o artifacts\win-x64 /p:NuGetAudit=false`
  passed.
- SHA256 hashes were generated for `UniversalClipboard.App.exe` and
  `UniversalClipboard.App.dll`.

## Release Binary Smoke Evidence

The published binary was launched on the Private Wi-Fi network after the final
startup, network-profile, firewall-diagnostics, and single-instance fixes.
Observed:

- TCP listener appeared on `192.168.8.216:43127` with one owner process.
- `GET http://192.168.8.216:43127/` returned `200`.
- unpaired `GET http://192.168.8.216:43127/clip-api/clips` returned `401`.
- a second launch exited after activating the existing owner; process count
  remained `1`.
- stopping the process removed the listener and left process count `0`.

Fixes covered by this smoke:

- startup no longer captures the pre-message-loop WinForms synchronization
  context while starting sharing;
- slow Windows Firewall COM inspection returns `Unknown` instead of blocking
  startup;
- localized Traditional Chinese Windows network-profile output maps the active
  Wi-Fi profile to `Private`;
- secondary pipe delivery no longer captures the pre-message-loop WinForms
  synchronization context.

## Pending Manual/Runtime Gates

These remain pending and must not be marked as passed without a fresh runtime
check:

- verify owner tray activation visually on second launch;
- pair through the real tray QR from iPhone Safari;
- verify manual copy fallback with a harmless clipboard fixture on iPhone;
- verify tray Exit, not forced process termination, removes the listener.
