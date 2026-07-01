---
name: testing-guide
description: >-
  Use when running tests, writing tests, investigating test failures, setting up
  a test environment against a live Safeguard appliance, or working with the
  PowerShell integration test framework. Covers live appliance workflow, PKCE vs
  ROG, running test suites, writing new suites, assertion functions, TOTP
  generation, and module-to-suite mapping.
---

# Testing Guide

## Two test layers: deterministic unit tests + live-appliance integration

This SDK is validated at two levels:

- **Deterministic unit tests** live in `Test/SafeguardDotNetUnitTest/` (xUnit, `net10.0`).
  They cover pure, appliance-independent logic with injected collaborators and no network
  I/O. Current coverage: `ReconnectBackoffTests.cs` (SignalR reconnect backoff) and
  `DeviceCodeLoginTests.cs` (the OAuth 2.0 device-code flow). Run them with:

  ```powershell
  dotnet test Test\SafeguardDotNetUnitTest\SafeguardDotNetUnitTest.csproj
  ```

  These tests are fast, require no appliance, and run on every build. Prefer adding unit
  coverage here whenever logic can be exercised without an appliance (timers, retry/backoff,
  request/response shaping, error mapping, cancellation). The device-code flow injects an
  `HttpClient` (stub `HttpMessageHandler`), an `IDeviceCodeClock` seam, and an
  `RstsTokenExchange` delegate into `internal` overloads surfaced via `InternalsVisibleTo`;
  follow that pattern — keep the public API unchanged and inject fakes that queue rSTS
  responses and advance virtual time rather than sleeping.

- **Live-appliance integration tests** in `Test/` (CLI tools + the PowerShell framework)
  remain the only way to validate anything that actually talks to a Safeguard appliance:
  authentication, API calls, connection logic, events, A2A, and SPS. Most regression
  coverage lives here.

The rest of this guide covers the live-appliance workflow.


## Asking the user for appliance access

**If you are making non-trivial code changes, ask the user whether they have access to a
live Safeguard appliance for testing.** If they do, ask for:

1. **Appliance address** (IP or hostname of a Safeguard for Privileged Passwords appliance)
2. **Admin username** (typically `Admin` — the built-in admin account)
3. **Admin password** (for the admin account above)
4. *(Optional)* **TOTP seed** (Base32-encoded secret for MFA-enabled user, if testing MFA)
5. *(Optional)* **SPS appliance address** (for Safeguard for Privileged Sessions tests)
6. *(Optional)* **SPS credentials** (username and password)

This is not required for documentation or minor fixes, but it is **strongly encouraged**
for any change that touches authentication, API calls, connection logic, or event handling.

## AOT cleanliness — how reflection regressions are caught

Every CLI tool csproj under `Test/` carries the **full AOT property set**: `IsAotCompatible`,
`IsTrimmable`, `EnableAotAnalyzer`, `EnableTrimAnalyzer`, `EnableSingleFileAnalyzer`,
`JsonSerializerIsReflectionEnabledByDefault=false`. This gives two complementary guards:

1. **Build-time** — analyzers run against tool source; any reflection-based JSON
   introduced in a tool fails the build via repo-wide `TreatWarningsAsErrors`.
2. **Runtime** — when the PowerShell suite `dotnet run`s these tools against a live
   appliance, they execute with reflection disabled, so any new SDK code path that needs
   reflection fails loudly in regression instead of silently shipping to consumers.

**Every new tool csproj under `Test/` must carry this full property set.** If a regression
run starts failing event listeners, A2A retrieval, or auth, the answer is **not** "remove
the AOT switches from the tool" — it's "fix the SDK code path that's trying to use
reflection." The canonical example: SignalR registrations must be typed
(`On<JsonElement>(...)`, never `On("name", (object) => ...)`) so `JsonHubProtocol` can
deserialize without reflection.

### Gap to be aware of

The SDK targets `netstandard2.0`; trim/AOT analyzers do not run on its own source. A
regression in the SDK that switches `SafeguardJson.Deserialize<T>` (or any other facade
method) to a `[RequiresUnreferencedCode]`/`[RequiresDynamicCode]`-annotated overload
**will not** be caught at SDK build time. It only surfaces either:

- as `IL2026` / `IL3050` warnings in a downstream `PublishAot=true` consumer's build
  (e.g. safeguard-mcp), or
- as runtime failures during live appliance regression (broken event listeners, A2A
  retrieval, auth).

**For changes touching `SafeguardDotNet/Serialization/`, `SafeguardJsonContext`, the
`SafeguardJson` facade, any `JsonSerializer.*` site, or any SignalR `HubConnection`
registration, the live appliance regression is the primary safety net.** Run the full
PowerShell suite (see below) before declaring such a change done.

## Connecting to the appliance (PKCE vs Resource Owner Grant)

**Resource Owner Grant (ROG) is disabled by default** on Safeguard appliances. The SDK's
`PasswordAuthenticator` uses ROG under the hood, which will fail with a 400 error when ROG
is disabled.

**Always use PKCE as the default connection method** for testing:

```csharp
// Using the PKCE non-interactive login module
var connection = PkceNoninteractiveLogin.Connect(
    appliance, "local", "Admin", password.ToSecureString(),
    apiVersion: 4, ignoreSsl: true);
```

Or via the CLI test tool:
```powershell
dotnet run --project Test\SafeguardDotNetPkceNoninteractiveLoginTester -- `
    -a <appliance> -i local -u Admin -x
# (reads password from stdin)
```

If you attempt a `Safeguard.Connect()` with username/password and receive a 400 error like
`"OAuth2 resource owner password credentials grant type is not allowed"`, switch to PKCE.
**Do not try to enable ROG on the appliance** — use PKCE as the standard approach.

The PowerShell test runner (`Invoke-SafeguardTests.ps1`) uses PKCE for its preflight
connection check.

## Running the PowerShell test suite

```powershell
# Build first (always build before testing)
dotnet build SafeguardDotNet.Core.sln /p:SignFiles=false

# Run all suites
pwsh -File Test\TestFramework\Invoke-SafeguardTests.ps1 `
    -Appliance <address> -AdminUserName Admin -AdminPassword <password>

# Run a specific suite
pwsh -File Test\TestFramework\Invoke-SafeguardTests.ps1 `
    -Appliance <address> -AdminUserName Admin -AdminPassword <password> `
    -Suite PkceAuthentication

# Run MFA tests (requires TOTP-enabled user with the same credentials)
pwsh -File Test\TestFramework\Invoke-SafeguardTests.ps1 `
    -Appliance <address> -AdminUserName <mfa-user> -AdminPassword <password> `
    -Suite PkceAuthentication -TotpSeed <base32-totp-secret>

# List available suites
pwsh -File Test\TestFramework\Invoke-SafeguardTests.ps1 -ListSuites
```

**Important:** The test runner requires **PowerShell 7** (`pwsh`). It:
- Validates the appliance is reachable (preflight HTTPS check)
- Authenticates using PKCE (not ROG) to verify credentials
- Discovers and runs suite files from `Test/TestFramework/Suites/`
- Reports pass/fail/skip with structured output

## Running individual CLI test tools

Each test tool in `Test/` is a standalone CLI application:

```powershell
# PKCE login tester (basic)
dotnet run --project Test\SafeguardDotNetPkceNoninteractiveLoginTester -- `
    -a <appliance> -i local -u Admin -x
# Enter password when prompted via stdin

# PKCE login tester with MFA (TOTP)
dotnet run --project Test\SafeguardDotNetPkceNoninteractiveLoginTester -- `
    -a <appliance> -i local -u <mfa-user> -s <totp-code> -x
# Enter password when prompted via stdin

# General SDK test tool
dotnet run --project Test\SafeguardDotNetTool -- `
    -a <appliance> -i local -u Admin -x -m Get -U "v4/Me"
# Enter password when prompted via stdin
```

## Module-to-suite mapping

When you change a specific SDK module, run the relevant suite(s) rather than the full set:

| SDK module / project | Relevant test suite(s) |
|---|---|
| `SafeguardDotNet.PkceNoninteractiveLogin/` | PkceAuthentication |
| `SafeguardDotNet/Safeguard.cs` | PasswordAuth, CertificateAuth, AccessTokenAuth, AnonymousAccess |
| `SafeguardDotNet/SafeguardConnection.cs` | ApiInvocation, PersistentConnection, TokenManagement |
| `SafeguardDotNet/Authentication/` | PasswordAuth, CertificateAuth, AccessTokenAuth |
| `SafeguardDotNet/Event/` | EventListeners |
| `SafeguardDotNet/A2A/` | A2ACredentialRetrieval, A2AAccessRequestBroker, A2AEventListener |
| `SafeguardDotNet/Sps/` | SpsIntegration (requires SPS appliance) |
| `SafeguardDotNet/SafeguardDotNetException.cs` | ExceptionHandling |
| `SafeguardDotNet/*Streaming*` | Streaming |

## Fixing test failures

When a test fails, **investigate and fix the source code first** — do not change the test
to make it pass without asking the user. The test suite exists to catch regressions.

Only modify a test if:
- The test itself has a genuine bug (wrong assertion logic, stale assumptions)
- The user explicitly approves changing the test
- A new feature intentionally changes behavior and the test needs updating

Always ask the user before weakening or removing an assertion.

## Writing a new test suite

### Suite file structure

Create `Test/TestFramework/Suites/Suite-YourFeature.ps1` returning a hashtable:

```powershell
@{
    Name        = "Your Feature"
    Description = "Tests for your feature"
    Tags        = @("yourfeature")

    Setup = {
        param($Context)
        # Setup code — prepare test data, store in $Context.SuiteData
        # Keep setup minimal; the test runner handles authentication
    }

    Execute = {
        param($Context)

        # Success test
        Test-SgDnAssert "Can do the thing" {
            $result = Invoke-SgDnSafeguardTool -ProjectDir $Context.SomeToolDir `
                -Arguments "-a $($Context.Appliance) -i local -u $($Context.AdminUserName) -x" `
                -StdinLine $Context.AdminPassword
            $result -match "expected output"
        }

        # Error test
        Test-SgDnAssertThrows "Rejects bad input" `
            -Match "expected error message" `
            -ScriptBlock {
                Invoke-SgDnSafeguardTool -ProjectDir $Context.SomeToolDir `
                    -Arguments "-a $($Context.Appliance) -i local -u BadUser -x" `
                    -StdinLine "wrong"
            }
    }

    Cleanup = {
        param($Context)
        # Cleanup code — remove test objects
    }
}
```

### Available context properties

The `$Context` object provides:

| Property | Description |
|---|---|
| `$Context.Appliance` | Appliance network address |
| `$Context.AdminUserName` | Admin username (from CLI) |
| `$Context.AdminPassword` | Admin password (from CLI) |
| `$Context.TotpSeed` | Base32 TOTP seed (from CLI `-TotpSeed`, or `$null`) |
| `$Context.PkceToolDir` | Path to `Test/SafeguardDotNetPkceNoninteractiveLoginTester` |
| `$Context.DeviceCodeToolDir` | Path to `Test/SafeguardDotNetDeviceCodeLoginTester` |
| `$Context.SuiteData` | Hashtable for per-suite state (shared between Setup/Execute/Cleanup) |
| `$Context.TestPrefix` | Name prefix for test objects (default: "SgDnTest") |

### Available assertion functions

| Function | Purpose |
|---|---|
| `Test-SgDnAssert "name" { <bool-expr> }` | Assert a boolean expression is `$true` |
| `Test-SgDnAssertEqual "name" -Expected $a -Actual $b` | Assert equality |
| `Test-SgDnAssertNotNull "name" -Value $x` | Assert value is not `$null` |
| `Test-SgDnAssertContains "name" -Collection $arr -Item $x` | Assert collection contains item |
| `Test-SgDnAssertThrows "name" -Match "pattern" -ScriptBlock { ... }` | Assert code throws with matching message |
| `Test-SgDnSkip "reason"` | Skip remaining tests in suite |

### Running test tools from suites

Use `Invoke-SgDnSafeguardTool` to run CLI test tools and capture their output:

```powershell
$result = Invoke-SgDnSafeguardTool `
    -ProjectDir $Context.PkceToolDir `
    -Arguments "-a $($Context.Appliance) -i local -u $($Context.AdminUserName) -x" `
    -StdinLine $Context.AdminPassword `
    -ParseJson $true    # Parse JSON output (default: $true)
```

The function runs `dotnet run --project <dir> -- <arguments>`, pipes `StdinLine` to stdin,
and captures stdout. Set `-ParseJson $false` for non-JSON output.

### Generating TOTP codes in tests

Do not generate TOTP codes in C# — use Python from within the PowerShell test:

```powershell
$totpCode = python -c @"
import hmac, hashlib, struct, time, base64
key = base64.b32decode('$($Context.TotpSeed)')
t = struct.pack('>Q', int(time.time()) // 30)
h = hmac.new(key, t, hashlib.sha1).digest()
o = h[-1] & 0xF
code = (struct.unpack('>I', h[o:o+4])[0] & 0x7FFFFFFF) % 1000000
print(f'{code:06d}')
"@
```

This avoids adding crypto dependencies to the SDK and keeps TOTP generation in the test
layer where it belongs.

### Writing strong test assertions

Tests must validate that operations **actually worked** — not just that they did not throw.
The goal is to catch regressions, confirm the API contract, and prove that data round-trips
correctly.

**Principles:**

1. **Assert specific values, not just existence.** Do not write `$null -ne $result` as the
   only check. Verify concrete field values in the response.

2. **Test error paths.** When an operation should fail, verify it throws with an appropriate
   error message. Use `Test-SgDnAssertThrows` with `-Match` to confirm the error is specific.

3. **Handle appliance configuration differences.** Some error messages change based on
   appliance settings (e.g., detailed error messages can be disabled, making all auth
   failures return "Access denied."). Use manual try/catch with `-match` against multiple
   acceptable patterns when needed:

   ```powershell
   Test-SgDnAssert "Wrong password gives appropriate error" {
       $threw = $false
       try {
           Invoke-SgDnSafeguardTool -ProjectDir $Context.PkceToolDir `
               -Arguments "..." -StdinLine "wrongpassword"
       }
       catch {
           $threw = ($_.Exception.Message -match "Invalid password") -or
                    ($_.Exception.Message -match "Access denied")
       }
       $threw
   }
   ```

4. **Be mindful of rSTS rate limiting.** Multiple failed authentication attempts against
   the same user trigger rate limiting. In error-path tests, keep failure count low and
   only run them in standard (non-MFA) mode.

5. **Test both modes when applicable.** The PKCE test suite supports two modes:
   - **Standard mode** (no `TotpSeed`): Runs login success + error tests
   - **MFA mode** (`TotpSeed` provided): Runs only the TOTP success test

## Suite interactivity classification

All suites are designed to run **non-interactively** (no human input during execution).
Suites that test browser or device-code flows use timeouts and error paths to validate
the flow starts correctly without requiring a human to complete authentication.

| Suite | Requires | Notes |
|---|---|---|
| SpsIntegration | SPS appliance (`-SpsAppliance`, `-SpsPassword`) | Only suite needing separate infrastructure |
| BrowserAuthentication | Nothing extra | Tests error paths + verifies listener starts (timeout expected) |
| DeviceCodeAuthentication | Nothing extra | Tests grant toggle + requires verification-URL evidence; tester runs non-interactive (`-n`) emitting `DEVICE_CODE_DATA`; live approval is opt-in via `SGDN_DEVICECODE_SCRIPTED_APPROVAL=1` |
| A2A* suites | Nothing extra | Creates own certs, users, registrations via setup |
| CertificateAuth | Nothing extra | Uses embedded test certificates |
| Streaming | Nothing extra | Tests streaming download paths |
| All others | Nothing extra | Standard password/PKCE auth against appliance |

**When running a full regression**, exclude only `SpsIntegration` (unless an SPS appliance
is available):

```powershell
pwsh -File Test\TestFramework\Invoke-SafeguardTests.ps1 `
    -Appliance <address> -AdminPassword <password> -SkipBuild `
    -ExcludeSuite SpsIntegration
```
