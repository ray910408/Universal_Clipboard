# Release Smoke Checklist

Use this checklist for each release candidate. Do not mark an item complete from
old notes; rerun the command or manual check for the current build.

## Automated Checks

Run from a Windows clone of the repository:

```powershell
.\scripts\bootstrap.ps1
.\.dotnet\dotnet.exe restore UniversalClipboard.slnx /p:NuGetAudit=false
.\.dotnet\dotnet.exe build UniversalClipboard.slnx -c Release --no-restore /p:NuGetAudit=false
.\.dotnet\dotnet.exe test UniversalClipboard.slnx -c Release --no-build /p:NuGetAudit=false
.\.dotnet\dotnet.exe publish src\UniversalClipboard.App\UniversalClipboard.App.csproj -c Release -r win-x64 --self-contained true -o artifacts\win-x64 /p:NuGetAudit=false
Get-FileHash artifacts\win-x64\UniversalClipboard.App.exe, artifacts\win-x64\UniversalClipboard.App.dll -Algorithm SHA256
```

Expected result:

- [ ] bootstrap finds or installs a usable .NET 10 SDK;
- [ ] restore succeeds;
- [ ] build succeeds;
- [ ] test succeeds and includes both test projects from `tests/`;
- [ ] publish succeeds;
- [ ] SHA-256 hashes are recorded for the published executable and DLL.

## Runtime Smoke Checks

Launch the published binary on a trusted Private LAN. Windows management remains in
the Tray UI. iPhone Safari uses the tray-reported LAN URL, for example
`https://<LAN-IP>:43127/`.

Because the MVP uses an ephemeral self-signed HTTPS certificate, command-line smoke
checks may need explicit certificate bypass. This bypass is for release testing only;
it does not make the MVP a complete trust model.

Example endpoint checks:

```powershell
curl.exe -k https://<LAN-IP>:43127/
curl.exe -k https://<LAN-IP>:43127/clip-api/clips
```

Expected result:

- [ ] published binary launches from `artifacts\win-x64\UniversalClipboard.App.exe`;
- [ ] TCP listener appears on the tray-selected LAN IPv4 address and port `43127`;
- [ ] `GET https://<LAN-IP>:43127/` returns `200`;
- [ ] unpaired `GET https://<LAN-IP>:43127/clip-api/clips` returns `401`;
- [ ] second launch activates the existing tray owner instead of creating a second
      long-running owner process;
- [ ] tray **Exit** removes the TCP listener.

## Manual iPhone Gates

These gates require real device interaction and must stay unchecked until verified
against the current release candidate:

- [ ] pair through the real tray QR from iPhone Safari;
- [ ] copy a harmless clipboard fixture from Windows;
- [ ] tap **Copy to iPhone** in Safari;
- [ ] verify the manual textarea long-press **Copy** fallback in Safari;
- [ ] revoke the paired browser from the Tray UI and verify access stops.
