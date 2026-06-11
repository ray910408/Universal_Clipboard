# Universal Clipboard MVP Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development to implement this plan task-by-task. Each implementation task must use superpowers:test-driven-development. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build a self-contained Windows tray application that captures approved plain-text clipboard items and exposes the latest three to paired iPhone Safari browsers over a local HTTP connection.

**Architecture:** A Windows-independent core library owns validation, classification, history, pending approvals, pairing, and authorization state. A WinForms executable owns the STA clipboard listener and tray UI, while an in-process Kestrel host serves a framework-free mobile page and read-only API. Clipboard content remains application-memory-only; only DPAPI-protected authorization metadata persists.

**Tech Stack:** .NET 10 LTS, C# 14, WinForms, ASP.NET Core Kestrel, xUnit, FluentAssertions, QRCoder, Windows DPAPI.

**Approved specification:** `docs/design.md`

---

## File Structure

```text
UniversalClipboard.slnx
Directory.Build.props
src/
  UniversalClipboard.Core/
    UniversalClipboard.Core.csproj
    Clipboard/
      ClipboardCapturePipeline.cs
      ClipboardHistory.cs
      ClipboardItem.cs
      ClipboardSnapshot.cs
      PendingApprovalStore.cs
      SensitiveTextClassifier.cs
      StrictUtf8TextValidator.cs
    Authorization/
      AuthorizationCoordinator.cs
      AuthorizationModels.cs
      IAuthorizationService.cs
      IAuthorizationPersistence.cs
      PairingCodeManager.cs
      SessionTokenService.cs
  UniversalClipboard.App/
    UniversalClipboard.App.csproj
    Program.cs
    App/
      ClipboardApplicationContext.cs
      SingleInstanceCoordinator.cs
    Clipboard/
      WindowsClipboardMonitor.cs
    Network/
      NetworkCoordinator.cs
      NetworkInterfaceSelector.cs
    Security/
      DpapiAuthorizationPersistence.cs
    Web/
      ApiContracts.cs
      LocalWebHost.cs
      WebAssets.cs
    Ui/
      TrayWindow.cs
      TrayWindow.Designer.cs
    wwwroot/
      index.html
      app.css
      app.js
tests/
  UniversalClipboard.Core.Tests/
  UniversalClipboard.App.Tests/
README.md
docs/
  firewall-setup.md
```

`UniversalClipboard.Core` must not reference WinForms, ASP.NET Core, DPAPI,
filesystem paths, ACL APIs, or network-interface APIs. It contains only the
authorization persistence interface. `UniversalClipboard.App` owns all Windows and
delivery concerns, including the DPAPI implementation.

---

### Task 1: Solution Skeleton and Clipboard Core

**Files:**
- Create: `UniversalClipboard.slnx`
- Create: `Directory.Build.props`
- Create: `src/UniversalClipboard.Core/UniversalClipboard.Core.csproj`
- Create: `src/UniversalClipboard.Core/Clipboard/*.cs`
- Create: `tests/UniversalClipboard.Core.Tests/UniversalClipboard.Core.Tests.csproj`
- Create: `tests/UniversalClipboard.Core.Tests/Clipboard/*.cs`

- [ ] **Step 1: Scaffold projects and test references**

Run:

```powershell
$dotnet = 'C:\Universal_Clipboard\.dotnet\dotnet.exe'
& $dotnet new sln --format slnx -n UniversalClipboard
& $dotnet new classlib -n UniversalClipboard.Core -o src/UniversalClipboard.Core -f net10.0
& $dotnet new xunit -n UniversalClipboard.Core.Tests -o tests/UniversalClipboard.Core.Tests -f net10.0
& $dotnet sln UniversalClipboard.slnx add src/UniversalClipboard.Core/UniversalClipboard.Core.csproj
& $dotnet sln UniversalClipboard.slnx add tests/UniversalClipboard.Core.Tests/UniversalClipboard.Core.Tests.csproj
& $dotnet add tests/UniversalClipboard.Core.Tests/UniversalClipboard.Core.Tests.csproj reference src/UniversalClipboard.Core/UniversalClipboard.Core.csproj
& $dotnet add tests/UniversalClipboard.Core.Tests/UniversalClipboard.Core.Tests.csproj package FluentAssertions
```

Expected: solution and two projects created; restore succeeds.

- [ ] **Step 2: Write failing validator and history tests**

Tests must cover:

```csharp
[Theory]
[InlineData(1_048_575, true)]
[InlineData(1_048_576, true)]
[InlineData(1_048_577, false)]
public void Validate_enforces_utf8_byte_limit(int byteCount, bool expected);

[Fact]
public void Validate_rejects_unpaired_surrogate();

[Fact]
public void History_keeps_three_newest_items();

[Fact]
public void History_withdrawal_changes_version_once();

[Fact]
public void New_process_instance_changes_snapshot_identity();
```

Run:

```powershell
& $dotnet test tests/UniversalClipboard.Core.Tests --filter "FullyQualifiedName~Clipboard"
```

Expected: FAIL because production types do not exist.

- [ ] **Step 3: Implement immutable clipboard history and strict UTF-8 validation**

Required public surface:

```csharp
public sealed record ClipboardItem(Guid Id, DateTimeOffset CopiedAt, string Text);
public sealed record ClipboardSnapshot(Guid InstanceId, ulong Version, ImmutableArray<ClipboardItem> Items);

public sealed class StrictUtf8TextValidator
{
    public const int MaximumBytes = 1_048_576;
    public TextValidationResult Validate(string text);
}

public sealed class ClipboardHistory
{
    public ClipboardSnapshot Snapshot { get; }
    public ClipboardItem Add(string text, DateTimeOffset copiedAt);
    public bool Withdraw(Guid id);
}
```

Use `new UTF8Encoding(false, true)` and immutable snapshots. One mutation publishes
one version increment, including add-plus-evict.

- [ ] **Step 4: Write failing classifier, pending-store, and dedup pipeline tests**

Cover every normative row in the design's deduplication table, plus:

- exact PEM marker pairs and line boundaries;
- GitHub and AWS token rules;
- representative near-miss false positives;
- three-item and 3 MiB pending limits;
- allow-once and discard;
- rejected/discarded/withdrawn text is not recaptured until clipboard changes.

Expected: FAIL because classifier and pipeline do not exist.

- [ ] **Step 5: Implement classifier, pending store, and capture pipeline**

Required surface:

```csharp
public sealed record SensitiveMatch(string Rule);
public sealed class SensitiveTextClassifier
{
    public SensitiveMatch? Classify(string text);
}

public sealed class PendingApprovalStore
{
    public ImmutableArray<PendingClipboardItem> Items { get; }
    public PendingClipboardItem Add(string text, string rule, DateTimeOffset copiedAt);
    public PendingClipboardItem? Remove(Guid id);
}

public sealed class ClipboardCapturePipeline
{
    public CaptureResult Observe(string? unicodeText, DateTimeOffset copiedAt);
    public bool AllowPending(Guid id);
    public bool DiscardPending(Guid id);
}
```

Do not use backtracking regexes. Direct span scanning or
`RegexOptions.NonBacktracking | RegexOptions.CultureInvariant` is required.

- [ ] **Step 6: Run the full core suite**

```powershell
& $dotnet test tests/UniversalClipboard.Core.Tests
```

Expected: PASS, zero warnings.

- [ ] **Step 7: Commit**

```powershell
git add UniversalClipboard.slnx Directory.Build.props src/UniversalClipboard.Core tests/UniversalClipboard.Core.Tests
git commit -m "feat: add clipboard capture core"
```

---

### Task 2: Pairing and Authorization Coordination

**Files:**
- Create: `src/UniversalClipboard.Core/Authorization/*.cs`
- Create: `tests/UniversalClipboard.Core.Tests/Authorization/*.cs`
- Modify: `src/UniversalClipboard.Core/UniversalClipboard.Core.csproj`

- [ ] **Step 1: Write failing pairing and session tests**

Cover:

- 192-bit base64url pairing codes;
- one active code and two-minute expiry;
- atomic concurrent exchange with one winner;
- 256-bit session tokens and SHA-256 digests;
- fixed-time token validation;
- all five duration choices;
- bound IPv4 validation;
- stable authorization IDs.

Expected: FAIL because authorization types do not exist.

- [ ] **Step 2: Implement pairing and token primitives**

Required types:

```csharp
public enum AuthorizationDuration { OneHour, FiveHours, OneDay, OneWeek, Permanent }
public sealed record PairingGrant(string Code, DateTimeOffset ExpiresAt, AuthorizationDuration Duration);
public sealed record BrowserAuthorization(
    Guid Id,
    byte[] TokenDigest,
    string Label,
    DateTimeOffset CreatedAt,
    DateTimeOffset? ExpiresAt,
    IPAddress BoundAddress);
```

Use `RandomNumberGenerator.GetBytes`, `CryptographicOperations.FixedTimeEquals`, and
base64url without padding.

- [ ] **Step 3: Write failing persistence and transaction tests**

Create a persistence interface so tests do not depend on DPAPI:

```csharp
public interface IAuthorizationPersistence
{
    Task<AuthorizationDocument> LoadAsync(CancellationToken cancellationToken);
    Task SaveAsync(AuthorizationDocument document, CancellationToken cancellationToken);
}
```

The web host depends on a narrow `IAuthorizationService` implemented by the real
coordinator. Integration tests should normally use the real coordinator with fake
persistence and a fake clock; simple API error-mapping tests may use the interface.

Test:

- save-before-publish;
- failed save leaves old snapshot active;
- failed revoke does not claim success;
- revoke blocks new leases and drains existing leases before success;
- forced restart reads revoked state;
- schema mismatch and corrupt data fail closed;
- stale bound-IP records are removed before server start.

Expected: FAIL.

- [ ] **Step 4: Implement authorization coordinator against the persistence interface**

Use a single-reader `Channel<AuthorizationCommand>`. Expose:

```csharp
public sealed class AuthorizationCoordinator : IAsyncDisposable
{
    public Task<PairingExchangeResult> ExchangeAsync(...);
    public ValueTask<AuthorizationLease?> AcquireLeaseAsync(string token, IPAddress host, ...);
    public Task<MutationResult> RevokeAsync(Guid authorizationId, ...);
    public Task<MutationResult> RevokeAllAsync(...);
    public Task<MutationResult> RemoveStaleBindingsAsync(IPAddress selectedAddress, ...);
}
```

Core must not implement or reference DPAPI, `%LOCALAPPDATA%`, ACL, or file APIs.

- [ ] **Step 5: Run authorization and full core tests**

```powershell
$dotnet = 'C:\Universal_Clipboard\.dotnet\dotnet.exe'
& $dotnet test tests/UniversalClipboard.Core.Tests --filter "FullyQualifiedName~Authorization"
& $dotnet test tests/UniversalClipboard.Core.Tests
```

Expected: PASS.

- [ ] **Step 6: Commit**

```powershell
git add src/UniversalClipboard.Core/Authorization tests/UniversalClipboard.Core.Tests/Authorization
git commit -m "feat: add paired browser authorization"
```

---

### Task 3: Windows Authorization Persistence, Local Web API, and iPhone Page

**Files:**
- Create: `src/UniversalClipboard.App/UniversalClipboard.App.csproj`
- Create: `src/UniversalClipboard.App/Web/*.cs`
- Create: `src/UniversalClipboard.App/Security/DpapiAuthorizationPersistence.cs`
- Create: `src/UniversalClipboard.App/wwwroot/*`
- Create: `tests/UniversalClipboard.App.Tests/UniversalClipboard.App.Tests.csproj`
- Create: `tests/UniversalClipboard.App.Tests/Web/*.cs`
- Create: `tests/UniversalClipboard.App.Tests/Security/*.cs`
- Modify: `UniversalClipboard.slnx`

- [ ] **Step 1: Scaffold app and integration-test projects**

Create a `net10.0-windows` WinForms executable with
`<FrameworkReference Include="Microsoft.AspNetCore.App" />`, plus an xUnit test
project referencing App and Core. Add `QRCoder`,
`System.Security.Cryptography.ProtectedData`,
`System.IO.FileSystem.AccessControl`, and `System.IO.Pipes.AccessControl`.

- [ ] **Step 2: Write failing Windows persistence tests**

Test the concrete DPAPI implementation on Windows:

- current-user DPAPI round trip;
- schema mismatch, truncated ciphertext, and decryption failure fail closed;
- corrupt file is renamed;
- destination file and directory ACL exclude other users;
- disk/write failure and atomic-replace failure leave the previous document readable;
- no serialized plaintext token, clipboard text, pairing code, or masked preview;
- pairing save failure consumes the one-time code and sets no cookie when exercised
  through the API in the next step.

Use injectable file-operation boundaries only where required to deterministically
simulate disk and atomic-replace failures.

- [ ] **Step 3: Implement DPAPI persistence in App**

Implement `%LOCALAPPDATA%\UniversalClipboard\authorizations.v1.bin` using
`DataProtectionScope.CurrentUser`, explicit schema versioning, current-user ACL,
same-directory temporary file, flush, and atomic replacement.

- [ ] **Step 4: Write failing API contract tests**

Use an in-memory fake history and the real authorization coordinator with fake
persistence/clock where lease and mutation semantics matter. Cover:

- invalid Host;
- pairing success and all pairing failures;
- cookie name/path/flags and clearing on `401`;
- changed, unchanged, restarted-instance, and future-version feeds;
- `400/401/404/405/413/415/429/500` JSON mappings;
- all cache/CSP/referrer/nosniff headers;
- no body on `204`;
- request rate limits;
- logs do not contain tokens, codes, bodies, or clipboard text.
- capture all logger output and assert it does not contain masked previews either.
- exact limits: pairing 1 KiB, 5 attempts/minute/source, 20 attempts/minute/process;
  feed 2 requests/second/authorization.
- pairing persistence failure consumes the code, returns `500`, and sets no cookie.
- a real hosted response holds an authorization lease through body completion:
  revoke cannot report success while that response is in flight, and no response
  completes after revoke success.
- real Kestrel startup and fixed-port collision;
- shutdown stops accepting requests, drains an active response for up to five
  seconds, cancels and joins remaining handlers for up to two seconds, and allows an
  authorization command already persisting to commit.

Expected: FAIL.

- [ ] **Step 5: Implement API host**

`LocalWebHost` accepts explicit dependencies and binds only when started by the
network coordinator. It maps:

```text
POST /clip-api/pair/exchange
GET  /clip-api/clips
GET  /
GET  /pair
GET  /app.css
GET  /app.js
```

Override framework errors so API routes always use the documented JSON schema.
Validate the exact selected `Host` address and port.

- [ ] **Step 6: Write browser asset behavior tests**

Test generated/static JavaScript text or extract pure JS functions where practical.
Required assertions:

- pairing fragment is cleared before POST;
- malformed fragment and failed `replaceState` do not POST;
- code variable is cleared in `finally`;
- polling stops while hidden;
- DOM clears on hidden, pagehide, `401`, and pairing transitions;
- bfcache pages wait for fresh authorization;
- only resolved Clipboard API displays `Copied`;
- fallback selects the exact textarea value and never claims confirmed success.

- [ ] **Step 7: Implement the framework-free mobile page**

Use semantic HTML, no dependencies, no external resources, and `textContent`.
Render three newest items, paired-browser expiry state, explicit HTTP warning, copy
fallback, pairing screen, loading/empty/error states, and one-second visible polling.

- [ ] **Step 8: Run app tests**

```powershell
$dotnet = 'C:\Universal_Clipboard\.dotnet\dotnet.exe'
& $dotnet test tests/UniversalClipboard.App.Tests --filter "FullyQualifiedName~Web"
& $dotnet test UniversalClipboard.slnx
```

Expected: PASS.

- [ ] **Step 9: Commit**

```powershell
git add UniversalClipboard.slnx src/UniversalClipboard.App tests/UniversalClipboard.App.Tests
git commit -m "feat: add paired local clipboard web app"
```

---

### Task 4: Windows Single Instance, Clipboard Monitor, and Network State

**Files:**
- Create: `src/UniversalClipboard.App/App/SingleInstanceCoordinator.cs`
- Create: `src/UniversalClipboard.App/Clipboard/WindowsClipboardMonitor.cs`
- Create: `src/UniversalClipboard.App/Network/*.cs`
- Create: `tests/UniversalClipboard.App.Tests/App/*.cs`
- Create: `tests/UniversalClipboard.App.Tests/Clipboard/*.cs`
- Create: `tests/UniversalClipboard.App.Tests/Network/*.cs`

- [ ] **Step 1: Write failing single-instance tests**

Abstract mutex and pipe creation behind narrow factories. Test:

- simultaneous launch has one owner;
- second instance sends `ShowTray`;
- two-second timeout reports failure;
- names contain current-user SID;
- pipe ACL is current-user-only.

- [ ] **Step 2: Implement single-instance coordinator**

Use a named mutex plus named pipe. Do not start another server when the pipe is
unresponsive.

- [ ] **Step 3: Write failing clipboard monitor tests**

Extract retry scheduling and event-to-pipeline behavior behind interfaces. Test:

- `WM_CLIPBOARDUPDATE` reads Unicode text;
- busy clipboard retries at 25/50/100 ms without blocking;
- exhausted retries record a content-free diagnostic;
- disposal unregisters listener;
- monitor runs only on an STA message loop.

STA integration tests create a dedicated `Thread`, call
`SetApartmentState(ApartmentState.STA)` before `Start`, run a minimal WinForms
message loop, and shut it down through `Application.ExitThread`.

- [ ] **Step 4: Implement Windows clipboard monitor**

Use a hidden `NativeWindow`, `AddClipboardFormatListener`, and
`RemoveClipboardFormatListener`. Marshal no clipboard reads to worker threads.

- [ ] **Step 5: Write failing network state tests**

Cover:

- no, one, and multiple eligible interfaces;
- retained explicit selection;
- complete state priority;
- Public profile;
- fixed-port conflict;
- owning-port diagnostic;
- only operational Ethernet/Wi-Fi interfaces with private IPv4 and a default gateway
  are eligible;
- selected interface loss stops and drains the host and invalidates the active
  pairing code;
- serialized/coalesced change events;
- DHCP address change performs stop, drain, revoke, bind, start;
- startup with stale bound address revokes before bind;
- revoke persistence failure keeps sharing paused.

- [ ] **Step 6: Implement interface selector and network coordinator**

Exclude loopback and tunnel adapters. Bind Kestrel only to selected private IPv4 and
port `43127`. Report firewall state as unknown unless the exact expected rule can be
identified.

- [ ] **Step 7: Run tests and commit**

```powershell
$dotnet = 'C:\Universal_Clipboard\.dotnet\dotnet.exe'
& $dotnet test tests/UniversalClipboard.App.Tests --filter "FullyQualifiedName~SingleInstance|FullyQualifiedName~Clipboard|FullyQualifiedName~Network"
& $dotnet test UniversalClipboard.slnx
git add src/UniversalClipboard.App tests/UniversalClipboard.App.Tests
git commit -m "feat: integrate Windows clipboard and LAN state"
```

---

### Task 5: Tray UI and Application Composition

**Files:**
- Create: `src/UniversalClipboard.App/Program.cs`
- Create: `src/UniversalClipboard.App/App/ClipboardApplicationContext.cs`
- Create: `src/UniversalClipboard.App/Ui/TrayWindow.cs`
- Create: `src/UniversalClipboard.App/Ui/TrayWindow.Designer.cs`
- Create: `tests/UniversalClipboard.App.Tests/App/ApplicationCompositionTests.cs`

- [ ] **Step 1: Write failing composition and presentation tests**

Test observable view-model behavior rather than pixel layout:

- sharing state and selected URL;
- authorization duration default is five hours;
- QR code contains fragment pairing URL;
- paired browser rows have unique suffixes;
- revoke one/all waits for durable coordinator result;
- sensitive notifications contain only rule and masked preview;
- over-limit and invalid UTF-16 notifications contain no clipboard content;
- exhausted clipboard retries increment a content-free diagnostic count;
- allow/discard/withdraw updates view state;
- Public profile displays a blocking warning;
- uncertain firewall state reads `Unknown - test from iPhone`;
- shutdown order drains host before clearing content.
- shutdown tests use a controlled in-flight HTTP response and a persistence gate to
  assert the five-second drain, two-second cancel/join, and commit-in-progress rules.

- [ ] **Step 2: Implement tray window and application context**

The tray UI must provide:

- service and firewall status;
- interface selection when needed;
- duration selector and QR pairing;
- paired browser authorization list with revoke one/all;
- three shared items with withdrawal;
- pending sensitive list with allow once/discard;
- stop/start sharing and exit.

Use QRCoder to render the QR code in memory. Notifications open the tray and do not
contain interactive approval buttons.

- [ ] **Step 3: Wire startup and shutdown**

`Program.Main` is `[STAThread]`. Compose persistence, authorization, clipboard core,
network coordinator, Kestrel, monitor, and application context. Enforce the designed
startup and bounded shutdown order.

- [ ] **Step 4: Run all automated tests**

```powershell
$dotnet = 'C:\Universal_Clipboard\.dotnet\dotnet.exe'
& $dotnet test UniversalClipboard.slnx
```

Expected: PASS with zero warnings.

- [ ] **Step 5: Commit**

```powershell
git add src/UniversalClipboard.App tests/UniversalClipboard.App.Tests
git commit -m "feat: add Windows tray application"
```

---

### Task 6: Documentation, Publish, and End-to-End Verification

**Files:**
- Create: `README.md`
- Create: `docs/firewall-setup.md`
- Create: `.github/workflows/build.yml`
- Modify: application project only for publish metadata discovered during verification

- [ ] **Step 1: Write setup and security documentation**

Document:

- trusted Private Wi-Fi requirement;
- exact administrator PowerShell firewall command for TCP 43127, Private profile,
  LocalSubnet;
- pairing and five duration meanings;
- HTTP interception and Cookie port limitations;
- Safari manual-copy baseline;
- memory-only application behavior and Windows paging/crash-dump caveat;
- SmartScreen warning for unsigned builds.

- [ ] **Step 2: Add Windows CI**

GitHub Actions must restore, build Release, run all tests, publish self-contained
`win-x64`, and produce a SHA-256 checksum.

- [ ] **Step 3: Run verification commands**

```powershell
$dotnet = 'C:\Universal_Clipboard\.dotnet\dotnet.exe'
& $dotnet restore UniversalClipboard.slnx
& $dotnet build UniversalClipboard.slnx -c Release --no-restore
& $dotnet test UniversalClipboard.slnx -c Release --no-build
& $dotnet publish src/UniversalClipboard.App/UniversalClipboard.App.csproj -c Release -r win-x64 --self-contained true -o artifacts/win-x64
Get-FileHash artifacts/win-x64/UniversalClipboard.App.exe -Algorithm SHA256
```

Expected: all succeed; executable and checksum exist.

- [ ] **Step 4: Perform release-binary smoke test without adding a product test mode**

Launch the normal Release binary on a Private test network. Verify:

- tray starts once and a second launch activates the existing tray;
- the selected LAN URL loads the pairing page;
- an unpaired feed returns `401`;
- pairing through the real tray QR reaches an empty or real clipboard feed;
- manual copy fallback is visible after copying a harmless fixture;
- exit terminates the process and port listener.

Do not add a hidden loopback, synthetic-history, debug API, or test-only product
entry point. Automated synthetic data stays inside the test host.

- [ ] **Step 5: Commit**

```powershell
git add README.md docs/firewall-setup.md .github src/UniversalClipboard.App
git commit -m "docs: add build and setup workflow"
```

---

## Final Acceptance

After all tasks:

1. Run the complete automated suite and Release publish.
2. Dispatch a final specification reviewer against `docs/design.md`.
3. Dispatch a final code-quality reviewer across the complete branch diff.
4. Fix and re-review all findings.
5. Use `superpowers:finishing-a-development-branch`.

Manual real-device iPhone validation remains required before declaring a public
release. If no physical iPhone is available during implementation, report that
specific unverified surface without weakening automated acceptance.

Before Task 1 begins, create `docs/manual-transfer-fixtures.md` with a five-row
template for the user-requested real transfer observations. If five real observations
are not available during implementation, keep the rows explicitly marked
`PENDING_REAL_DEVICE_OBSERVATION`; do not invent data. Completion of those rows,
the full manual Windows matrix, the real Safari matrix, and the clean-machine
ten-minute setup check are public-release gates, not implementation gates and not
reasons to falsify automated results. This timing follows the user's explicit
2026-06-11 approval to begin implementation immediately.
