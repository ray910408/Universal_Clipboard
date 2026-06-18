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
Get-FileHash artifacts\win-x64\UniversalClipboard.exe, artifacts\win-x64\UniversalClipboard.dll -Algorithm SHA256 |
    ForEach-Object { "$($_.Hash)  $([System.IO.Path]::GetFileName($_.Path))" } |
    Set-Content artifacts\win-x64\UniversalClipboard-win-x64.sha256 -Encoding ASCII
```

Expected result:

- [ ] bootstrap finds or installs a usable .NET 10 SDK;
- [ ] restore succeeds;
- [ ] build succeeds;
- [ ] test succeeds and includes both test projects from `tests/`;
- [ ] publish succeeds;
- [ ] SHA-256 hashes are recorded for the published executable and DLL.
- [ ] `UniversalClipboard-win-x64.zip` or the GitHub Actions artifact contains
      `UniversalClipboard.exe` at the extracted root.
- [ ] `UniversalClipboard-win-x64.zip` or the GitHub Actions artifact contains
      `UniversalClipboard-win-x64.sha256` at the extracted root.

## Runtime Smoke Checks

Launch the published binary on a trusted Private LAN. Windows management remains in
the Tray UI. iPhone Safari or Android Chrome uses the tray-reported LAN URL, for example
`https://<LAN-IP>:43127/`.

Because the MVP uses a persisted self-signed HTTPS certificate, command-line smoke
checks may need explicit certificate bypass. This bypass is for release testing only;
it does not make the MVP a complete trust model. The tray HTTPS identity should stay
stable across app restarts on the same selected IPv4 address unless **Reset HTTPS**
is used.

Example endpoint checks:

```powershell
curl.exe -k https://<LAN-IP>:43127/
curl.exe -k https://<LAN-IP>:43127/clip-api/clips
```

Expected result:

- [ ] published binary launches from `artifacts\win-x64\UniversalClipboard.exe`;
- [ ] TCP listener appears on the tray-selected LAN IPv4 address and port `43127`;
- [ ] `GET https://<LAN-IP>:43127/` returns `200`;
- [ ] unpaired `GET https://<LAN-IP>:43127/clip-api/clips` returns `401`;
- [ ] tray HTTPS identity short code is unchanged after app restart on the same
      selected IPv4 address;
- [ ] **Reset HTTPS** changes the tray HTTPS identity and revokes existing pairings;
- [ ] second launch activates the existing tray owner instead of creating a second
      long-running owner process;
- [ ] tray **Exit** removes the TCP listener.

## Manual iPhone Safari Gates

These gates require real device interaction and must stay unchecked until verified
against the current release candidate:

- [ ] pair through the real tray QR from iPhone Safari;
- [ ] verify the tray permission selector defaults to **Read only** before pairing;
- [ ] copy a harmless clipboard fixture from Windows;
- [ ] tap **Copy to iPhone** in Safari;
- [ ] verify the manual textarea long-press **Copy** fallback in Safari;
- [ ] verify **Send to Windows** is disabled for a Read-only pairing;
- [ ] re-pair with **Write only** and verify the Windows feed is unavailable while
      **Send to Windows** remains enabled;
- [ ] re-pair with **Read + Write**, send harmless text from Safari, and verify the
      tray shows **Pending incoming text** without exposing the full text;
- [ ] click **Apply to Windows Clipboard** and paste on Windows to verify the exact
      incoming text was applied;
- [ ] revoke the paired browser from the Tray UI and verify access stops;
- [ ] after revoke or expiry cleanup, verify any pending incoming item from that
      authorization is gone and stale Apply/Discard actions do nothing.

## Manual Android Chrome Gates

These gates verify that Android Chrome supports the same bidirectional workflow as
iPhone Safari and that Chrome-specific user-agent detection is preserved:

- [ ] pair from Android Chrome and verify the Tray UI shows **Chrome**, not
      Safari, for the paired browser;
- [ ] copy a harmless clipboard fixture from Windows and use **Copy to iPhone** in
      Android Chrome;
- [ ] verify **Send to Windows** is disabled for a Read-only Android Chrome pairing;
- [ ] re-pair Android Chrome with **Write only** and verify the Windows feed is
      unavailable while **Send to Windows** remains enabled;
- [ ] re-pair Android Chrome with **Read + Write**, send harmless text from Chrome,
      and verify the tray shows **Pending incoming text** until **Apply to Windows
      Clipboard** is clicked;
- [ ] pair Android Chrome with **Read + Write**, then while the authorization is
      still valid, background the paired mobile browser long enough for the tab to
      reload or be restored, then verify **Copy to iPhone** and **Send to Windows**
      still work without re-pairing.
