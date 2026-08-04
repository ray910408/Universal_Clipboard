# AGENTS.md — Universal Clipboard

Personal Windows-to-mobile text bridge (local-first MVP): copy on Windows, fetch on iPhone Safari / Android Chrome via a paired local page; write-enabled pairings can send text back (pending until tray "Apply to Windows Clipboard"). .NET solution `UniversalClipboard.slnx`: `src/UniversalClipboard.App` (tray app) + `src/UniversalClipboard.Core`. Global constitution in `~/.codex/AGENTS.md` applies; this file adds project specifics.

## Verify (run before any completion claim)
- No global `dotnet` SDK on PATH — run `.\scripts\bootstrap.ps1` once, then use `.\.dotnet\dotnet.exe`.
- `.\.dotnet\dotnet.exe build UniversalClipboard.slnx`
- `.\.dotnet\dotnet.exe test UniversalClipboard.slnx` (covers `tests/UniversalClipboard.App.Tests` and `tests/UniversalClipboard.Core.Tests`)
- Behavioral claims about clipboard/pairing flows need a manual run of the tray app — otherwise phrase as "implemented but NOT verified".

## Boundaries
- Local-first is a design decision: do not add cloud sync, external services, or telemetry unless explicitly requested.
- Clipboard write-back must stay behind the explicit tray "Apply" action — never auto-apply received text.
- `.worktrees/`, `.agents/`, `artifacts/` are operational artifacts; leave them alone.
- Note: this repo lives in the home directory (grandfathered); new sibling projects go in `C:\code\...`.
