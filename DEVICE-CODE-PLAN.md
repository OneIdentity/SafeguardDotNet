---
title: "OAuth 2.0 Device Authorization Grant (RFC 8628)"
status: verified
severity: enhancement
domain: authentication
owners:
  - petrsnd
created: 2026-05-28
updated: 2026-05-28
github_issue: "OneIdentity/SafeguardDotNet#226"
rfc_reference: "https://datatracker.ietf.org/doc/html/rfc8628"
verified_against:
  appliance: "192.168.117.15"
  firmware: "SPP 8.2.0.21662"
  rsts_source: "E:\\source\\SPP\\rSTS\\HttpService\\OAuth2\\OAuthTokenService.cs"
summary:
  definition: >
    Add support for the OAuth 2.0 Device Authorization Grant (RFC 8628) to SafeguardDotNet,
    enabling authentication in headless environments without a local browser.
  cause: >
    No SDK support exists for device code flow despite RSTS already supporting the grant type.
    The only headless option (PkceNoninteractiveLogin) requires passing credentials directly.
  planned_resolution: >
    Create a new optional NuGet package OneIdentity.SafeguardDotNet.DeviceCodeLogin following
    existing package patterns. The SDK handles the RFC 8628 flow internally and delegates
    display of the verification URI/code to the caller via a callback.
packages:
  new:
    - OneIdentity.SafeguardDotNet.DeviceCodeLogin
  existing_referenced:
    - OneIdentity.SafeguardDotNet
    - OneIdentity.SafeguardDotNet.PkceNoninteractiveLogin
    - OneIdentity.SafeguardDotNet.BrowserLogin
---

# OAuth 2.0 Device Authorization Grant (RFC 8628)

## 1. Definition

Implement the OAuth 2.0 Device Authorization Grant (RFC 8628) as a new optional NuGet
package in the SafeguardDotNet SDK. This enables authentication from environments that lack
a local browser:

- Docker containers
- Remote SSH sessions
- Headless VMs and CI runners
- IoT/embedded devices

The flow displays a URL and user code. The user authenticates from any browser on any
device, and the token is delivered back to the requesting application automatically.

## 2. Context & Constraints

### Current State

| Package | Auth Method | Browser Required | Credentials in Code |
|---------|-------------|-----------------|-------------------|
| `BrowserLogin` | PKCE via system browser | Yes | No |
| `PkceNoninteractiveLogin` | PKCE via direct rSTS calls | No | Yes (username/password) |
| *(proposed)* `DeviceCodeLogin` | Device Authorization Grant | No | No |

### Constraints

- Must target `netstandard2.0` (same as all other packages)
- Must follow existing project structure, naming conventions, and code style
- Must not break existing packages or public API
- Display rendering (console output, GUI, etc.) is **out of scope** — the calling
  application is responsible for presenting the verification URI and user code
- The Safeguard appliance must have the Device Code grant type enabled (disabled by default)
- All `SecureString` handling must follow existing disposal patterns
- TLS 1.2 enforcement on all HTTP connections
- `ignoreSsl` is dev-only; never recommend for production

### Prerequisites

- Safeguard appliance firmware ≥ 8.2 (RSTS includes DeviceLogin endpoint)
- The "Device Code" grant type must be enabled on the appliance:
  - **API**: `PUT /service/core/v4/Settings/Allowed%20OAuth2%20Grant%20Types`
    with body `{"Value":"ResourceOwner, DeviceCode"}`
  - **UI**: Safeguard Access → OAuth 2.0 Grant Types → check "Device Code"
  - When disabled, the endpoint returns HTTP 400: `"OAuth2DeviceCodeNotAllowed"`

## 3. Cause / Root Cause Analysis

The SDK currently provides two PKCE-based authentication options:
1. `BrowserLogin` — requires a local browser, unusable in headless environments
2. `PkceNoninteractiveLogin` — headless but requires passing credentials directly,
   which is insecure (credentials in env vars or config), and cannot leverage SSO/MFA
   from an external identity provider

Device Code Flow solves both problems: it is headless-compatible AND does not require
the calling application to handle credentials. The user authenticates interactively on
a separate device, making SSO and MFA work naturally.

## 4. Options & Trade-offs

### Option A: Standalone Package (Recommended)

Create `OneIdentity.SafeguardDotNet.DeviceCodeLogin` as a new independent project,
mirroring the pattern of existing login packages.

**Pros:**
- Follows established pattern — consistent with `BrowserLogin` and `PkceNoninteractiveLogin`
- Optional dependency — consumers who don't need it don't pull it in
- Clean separation of concerns
- Independent release cycle

**Cons:**
- One more package to maintain and publish
- Some minor code duplication (HTTP client setup)

### Option B: Add to Core SDK

Add device code support directly in `SafeguardDotNet` as another `Safeguard.Connect()` overload.

**Pros:**
- No additional package
- Simpler dependency graph

**Cons:**
- Breaks the established pattern (login methods are optional packages)
- Forces all consumers to pull in device code code even if unused
- Inconsistent with current architecture

### Option C: Shared Login Library + Thin Package

Create a shared library with common OAuth logic, then thin wrappers for each flow.

**Pros:**
- Reduces duplication across login packages

**Cons:**
- Major refactor of existing packages
- Scope creep beyond the issue request
- Could be done as a follow-up

**Decision:** Option A — standalone package, consistent with existing patterns.

## 5. Planned Resolution (Decision & Rationale)

### Architecture

```
┌─────────────────────────────────────────────────────────────┐
│  Calling Application                                         │
│  ┌────────────────────────────────────────────────────────┐ │
│  │ DeviceCodeLogin.Connect(appliance, parameters)          │ │
│  └────────────────┬───────────────────────────────────────┘ │
└───────────────────┼─────────────────────────────────────────┘
                    │
    ┌───────────────▼──────────────────────────────────────┐
    │  SafeguardDotNet.DeviceCodeLogin Package              │
    │                                                       │
    │  1. POST /RSTS/oauth2/DeviceLogin                     │
    │     Content-Type: application/json                     │
    │     Body: {"client_id":"...","scope":"..."}            │
    │     → receive device_code, user_code,                 │
    │       verification_uri, verification_uri_complete,    │
    │       expires_in                                      │
    │                                                       │
    │  2. Invoke DisplayCallback(uri, code, complete_uri)   │
    │     → caller displays to user                         │
    │                                                       │
    │  3. Poll POST /RSTS/oauth2/token                      │
    │     Content-Type: application/json                     │
    │     Body: {"grant_type":"urn:ietf:params:oauth:       │
    │            grant-type:device_code",                    │
    │            "device_code":"...", "client_id":"..."}     │
    │     → handle: authorization_pending, slow_down,       │
    │              access_denied, expired_token              │
    │                                                       │
    │  4. Exchange RSTS access_token → Safeguard user token │
    │     POST /service/core/v4/Token/LoginResponse         │
    │     Body: {"StsAccessToken":"<rsts_access_token>"}    │
    │     → returns {"Status":"Success",                    │
    │               "UserToken":"<safeguard_token>"}        │
    │                                                       │
    │  5. Safeguard.Connect(appliance, userToken)           │
    │     → return ISafeguardConnection                     │
    └───────────────────────────────────────────────────────┘
```

### Verified RSTS API Specification

> **Source**: `rSTS/HttpService/OAuth2/OAuthTokenService.cs` + live appliance testing (SPP 8.2.0.21662)

#### Step 1: Device Authorization Request

```
POST https://{appliance}/RSTS/oauth2/DeviceLogin
Content-Type: application/json
Accept: application/json

{"client_id":"SafeguardDotNet","scope":"rsts:sts:primaryproviderid:local"}
```

**⚠️ CRITICAL**: NO trailing slash on the URL. WCF returns 405 if a trailing slash is present.

**Response** (HTTP 200):
```json
{
  "device_code": "XKKXXVPQNgONIhDENuhF0ZphOJ9vnhWHh6g2AN9NkyDJGmcRFOtZ7PtlA",
  "expires_in": 300,
  "user_code": "XKK-XXV-PQN",
  "verification_uri": "https://192.168.117.15/RSTS/DeviceLogin",
  "verification_uri_complete": "https://192.168.117.15/RSTS/Login?device=XKKXXVPQN"
}
```

**Response field details:**
| Field | Type | Description |
|-------|------|-------------|
| `device_code` | string | 57 chars (9-char user_code prefix + 48-char random suffix). Used for polling. |
| `user_code` | string | 9 uppercase consonants formatted as `XXX-XXX-XXX`. Charset: `BCDFGHJKLMNPQRSTVWXZ` |
| `verification_uri` | string | URL for manual code entry (always `https://{appliance}/RSTS/DeviceLogin`) |
| `verification_uri_complete` | string | URL with code pre-filled (`/RSTS/Login?device={code_no_dashes}`) |
| `expires_in` | int | Always 300 (5 minutes). Hard-coded in RSTS. |
| ~~`interval`~~ | — | **NOT RETURNED by RSTS**. Use RFC 8628 default: 5 seconds. |

**Error responses:**
- Grant type disabled: HTTP 400 with `"OAuth2DeviceCodeNotAllowed"` message
- Invalid client_id (when RelyingPartyApplications configured): HTTP 400 with `"DeviceCodeFlowInvalidClientID"`

#### Step 2: User Authentication (out-of-band)

User opens `verification_uri_complete` in any browser:
```
https://{appliance}/RSTS/Login?device=XKKXXVPQN
```

The RSTS Login page detects the `device` query parameter and presents the standard
authentication flow. On successful auth, RSTS internally stores an OAuth authorization
code in a MemoryCache entry keyed by the user_code (expires in 10 minutes for error
messaging, but functionally valid for 5 minutes).

#### Step 3: Token Polling

```
POST https://{appliance}/RSTS/oauth2/token
Content-Type: application/json
Accept: application/json

{
  "grant_type": "urn:ietf:params:oauth:grant-type:device_code",
  "device_code": "XKKXXVPQNgONIhDENuhF0ZphOJ9vnhWHh6g2AN9NkyDJGmcRFOtZ7PtlA",
  "client_id": "SafeguardDotNet"
}
```

> **Note**: Both `application/json` and `application/x-www-form-urlencoded` work for the
> token endpoint. Use JSON for consistency with the existing `AgentBasedLoginUtils.ApiRequest()`
> helper which always sends JSON.

**Pending response** (HTTP 400):
```json
{"error":"authorization_pending","error_description":"","success":false}
```

**Success response** (HTTP 200):
```json
{
  "access_token": "<JWT>",
  "token_type": "Bearer",
  "expires_in": 600
}
```

**Error responses:**
| `error` value | HTTP | Meaning | SDK action |
|---------------|------|---------|-----------|
| `authorization_pending` | 400 | User hasn't authenticated yet | Wait `interval` seconds, poll again |
| `slow_down` | 400 | Polling too fast | Increase interval by 5s (note: RSTS never returns this, but handle per RFC) |
| `access_denied` | 400 | User denied or code not found in cache | Throw `SafeguardDotNetException` |
| `expired_token` | 400 | Code expired (>5 minutes) | Throw `SafeguardDotNetException` |

**Implementation note**: RSTS does NOT enforce `slow_down` in practice. The `slow_down`
value exists in the `DeviceCodeStatusResponse` enum but is never returned by
`CheckForRedeemedDeviceCode()`. Still, implement the handler per RFC 8628 for correctness.

#### Step 4: Exchange RSTS Token → Safeguard UserToken

Use `Safeguard.AgentBasedLoginUtils.PostLoginResponse()` (same as BrowserLogin and
PkceNoninteractiveLogin). This is already implemented in the core SDK:

```csharp
// From Safeguard.cs AgentBasedLoginUtils:
var data = JsonConvert.SerializeObject(new { StsAccessToken = rstsAccessToken.ToInsecureString() });
var json = ApiRequest(HttpMethod.Post, $"{safeguardCoreUrl}/Token/LoginResponse", data);
// Returns: {"Status":"Success","UserToken":"<token>"}
```

**Important**: `AgentBasedLoginUtils.CreateHttpClient()` ALWAYS bypasses SSL validation
(this is by design — the SSL handling is applied at the connection level via
`Safeguard.Connect()`). This means you don't need to pass `ignoreSsl` to the token
exchange step.

#### Step 5: Create Connection

```csharp
using var accessToken = responseObject.GetValue("UserToken")?.ToString().ToSecureString();
return Safeguard.Connect(appliance, accessToken, apiVersion, ignoreSsl);
```

This matches the exact pattern in `DefaultBrowserLogin.Connect()` (line 63) and
`PkceNoninteractiveLogin.Connect()` (line 137).

### Public API Design

```csharp
namespace OneIdentity.SafeguardDotNet.DeviceCodeLogin;

using System;
using System.Threading;
using System.Threading.Tasks;

/// <summary>
/// Contains the device authorization response information displayed to the user.
/// </summary>
public class DeviceCodeInfo
{
    /// <summary>The URI the user must visit to authenticate (for manual code entry).</summary>
    public string VerificationUri { get; set; }

    /// <summary>The code the user must enter at the verification URI. Format: XXX-XXX-XXX.</summary>
    public string UserCode { get; set; }

    /// <summary>
    /// Complete URI with the user code pre-filled. The user can simply click/open this
    /// URL without manually typing the code. Always provided by Safeguard RSTS.
    /// </summary>
    public string VerificationUriComplete { get; set; }

    /// <summary>Lifetime in seconds before the codes expire (always 300 from RSTS).</summary>
    public int ExpiresIn { get; set; }
}

/// <summary>
/// Parameters for the Device Code authentication flow.
/// </summary>
public class DeviceCodeLoginParameters
{
    /// <summary>
    /// Callback invoked when the user must visit a URL and enter a code.
    /// The calling application is responsible for displaying this information
    /// to the user (e.g., Console.WriteLine, GUI dialog, etc.).
    /// This callback is required; passing null will throw ArgumentException.
    /// </summary>
    public Action<DeviceCodeInfo> DisplayCallback { get; set; }

    /// <summary>
    /// Optional identity provider scope. Format: "rsts:sts:primaryproviderid:{provider}".
    /// If not specified, defaults to "rsts:sts:primaryproviderid:local".
    /// Note: RSTS accepts but does not functionally use this value for device code flow.
    /// </summary>
    public string Scope { get; set; }

    /// <summary>
    /// OAuth2 client identifier for the device authorization request.
    /// Default: "SafeguardDotNet". Only change if the appliance has
    /// RelyingPartyApplications configured with a specific client_id.
    /// </summary>
    public string ClientId { get; set; } = "SafeguardDotNet";

    /// <summary>
    /// Polling interval in seconds between token requests. Default: 5 (RFC 8628 default).
    /// Will be automatically increased if the server returns "slow_down".
    /// </summary>
    public int PollingIntervalSeconds { get; set; } = 5;
}

/// <summary>
/// Provides device code-based authentication to Safeguard using OAuth 2.0
/// Device Authorization Grant (RFC 8628).
/// </summary>
public static class DeviceCodeLogin
{
    /// <summary>
    /// Connect to Safeguard API using the Device Authorization Grant.
    /// Blocks until the user completes authentication or the code expires.
    /// </summary>
    /// <param name="appliance">Network address of the Safeguard appliance.</param>
    /// <param name="parameters">Device code flow parameters including the display callback.</param>
    /// <param name="apiVersion">Target API version to use.</param>
    /// <param name="ignoreSsl">Ignore server certificate validation (dev only).</param>
    /// <returns>Reusable Safeguard API connection.</returns>
    /// <exception cref="ArgumentException">Thrown when DisplayCallback is null or appliance is empty.</exception>
    /// <exception cref="SafeguardDotNetException">Thrown when authentication fails, code expires, or API error.</exception>
    public static ISafeguardConnection Connect(
        string appliance,
        DeviceCodeLoginParameters parameters,
        int apiVersion = Safeguard.DefaultApiVersion,
        bool ignoreSsl = false);

    /// <summary>
    /// Connect to Safeguard API using the Device Authorization Grant (async).
    /// Returns when the user completes authentication, the code expires,
    /// or the cancellation token is triggered.
    /// </summary>
    /// <param name="appliance">Network address of the Safeguard appliance.</param>
    /// <param name="parameters">Device code flow parameters including the display callback.</param>
    /// <param name="apiVersion">Target API version to use.</param>
    /// <param name="ignoreSsl">Ignore server certificate validation (dev only).</param>
    /// <param name="cancellationToken">Cancellation token to abort the flow.</param>
    /// <returns>Reusable Safeguard API connection.</returns>
    /// <exception cref="ArgumentException">Thrown when DisplayCallback is null or appliance is empty.</exception>
    /// <exception cref="SafeguardDotNetException">Thrown when authentication fails, code expires, or API error.</exception>
    /// <exception cref="OperationCanceledException">Thrown when cancellation is requested.</exception>
    public static Task<ISafeguardConnection> ConnectAsync(
        string appliance,
        DeviceCodeLoginParameters parameters,
        int apiVersion = Safeguard.DefaultApiVersion,
        bool ignoreSsl = false,
        CancellationToken cancellationToken = default);
}
```

### Usage Example

```csharp
var connection = DeviceCodeLogin.Connect(
    "safeguard.example.com",
    new DeviceCodeLoginParameters
    {
        DisplayCallback = info =>
        {
            Console.WriteLine($"To sign in, visit: {info.VerificationUriComplete}");
            Console.WriteLine($"Or go to {info.VerificationUri} and enter code: {info.UserCode}");
        }
    });

// Use connection...
var me = connection.InvokeMethod(Service.Core, Method.Get, "Me");
connection.LogOut();
```

## 6. Way of Working

This section defines how agents should implement this plan.

### Branch

- **Branch**: `feature/226-device-code-flow`

### Commit Protocol (Human-Controlled)

Agents do NOT commit directly. The workflow is:

1. Agent completes a task and stages the files (`git add`)
2. Agent signals the user: "Ready to commit. Staged files: `<list>`. Suggested message: `<short message>`"
3. User reviews staged code, adjusts if needed, and commits manually
4. User tells the agent "committed" — agent updates the status table and proceeds

**Commit messages**: Simple, no Co-authored-by trailer. User controls the final message.

### Task Execution Rules

1. **Work sequentially** — complete one task at a time, in order.
2. **Consult Section 10 (Implementation Reference)** for exact code to write.
3. **Consult Section 11 (Gotchas)** before writing any code.
4. **Update the Status table (Section 7)** after user confirms commit — set status to
   `✅ Done`.
5. **If a task fails** (build error, test failure), set status to `❌ Blocked` with a note.
   Report the issue to the user and wait for guidance.
6. **After each phase**, run `dotnet build SafeguardDotNet.Core.sln /p:SignFiles=false`
   and ensure 0 errors, 0 warnings before proceeding.

### Continuation Protocol

When signaling "ready to continue" after a commit, agents must show:
1. The current **Status table** (completed vs remaining tasks)
2. The **next step** to be executed (task number, description, files)

### Context Preservation

This plan is designed for background agents that may lose context between sessions.
Each task is self-contained: the Implementation Reference (Section 10) provides complete
code, the Gotchas (Section 11) list critical constraints, and the Status table tracks
what's done. A new agent can pick up where the last one left off by reading this file.

## 7. Implementation Status

> **Last updated**: 2026-05-28

### Phase 1: Core Library

| # | Task | Files | Status |
|---|------|-------|--------|
| 1.1 | Create project structure | `SafeguardDotNet.DeviceCodeLogin/SafeguardDotNet.DeviceCodeLogin.csproj` | ⬜ Pending |
| 1.2 | Implement `DeviceCodeInfo` | `SafeguardDotNet.DeviceCodeLogin/DeviceCodeInfo.cs` | ⬜ Pending |
| 1.3 | Implement `DeviceCodeLoginParameters` | `SafeguardDotNet.DeviceCodeLogin/DeviceCodeLoginParameters.cs` | ⬜ Pending |
| 1.4 | Implement `DeviceCodeLogin` class | `SafeguardDotNet.DeviceCodeLogin/DeviceCodeLogin.cs` | ⬜ Pending |
| 1.5 | Create package README | `SafeguardDotNet.DeviceCodeLogin/README.md` | ⬜ Pending |

**Phase 1 gate**: `dotnet build SafeguardDotNet.Core.sln /p:SignFiles=false` → 0 errors, 0 warnings

### Phase 2: CLI Tester Tool

| # | Task | Files | Status |
|---|------|-------|--------|
| 2.1 | Create tester project | `Test/SafeguardDotNetDeviceCodeLoginTester/SafeguardDotNetDeviceCodeLoginTester.csproj` | ⬜ Pending |
| 2.2 | Implement CLI entry point | `Test/SafeguardDotNetDeviceCodeLoginTester/Program.cs` | ⬜ Pending |

**Phase 2 gate**: `dotnet build SafeguardDotNet.Core.sln /p:SignFiles=false` → 0 errors, 0 warnings

### Phase 3: Unit Tests

| # | Task | Files | Status |
|---|------|-------|--------|
| 3.1 | Create unit test project | `Test/SafeguardDotNetUnitTest/SafeguardDotNetUnitTest.csproj` | ⬜ Pending |
| 3.2 | Test device authorization request | `Test/SafeguardDotNetUnitTest/DeviceCodeLoginTests.cs` | ⬜ Pending |
| 3.3 | Test polling loop scenarios | `Test/SafeguardDotNetUnitTest/DeviceCodeLoginTests.cs` | ⬜ Pending |
| 3.4 | Test error handling | `Test/SafeguardDotNetUnitTest/DeviceCodeLoginTests.cs` | ⬜ Pending |
| 3.5 | Test cancellation | `Test/SafeguardDotNetUnitTest/DeviceCodeLoginTests.cs` | ⬜ Pending |

**Phase 3 gate**: `dotnet test Test/SafeguardDotNetUnitTest/` → all tests pass

### Phase 4: Integration Test Suite

| # | Task | Files | Status |
|---|------|-------|--------|
| 4.1 | Create test suite | `Test/TestFramework/Suites/Suite-DeviceCodeAuthentication.ps1` | ⬜ Pending |
| 4.2 | Implement error path tests | (same file) | ⬜ Pending |
| 4.3 | Implement happy path test (interactive) | (same file) | ⬜ Pending |

**Phase 4 gate**: PowerShell test suite loads without syntax errors

### Phase 5: Solution & CI

| # | Task | Files | Status |
|---|------|-------|--------|
| 5.1 | Add projects to solution | `SafeguardDotNet.Core.sln` | ⬜ Pending |
| 5.2 | Update CI pipeline | `build.yml`, `pipeline-templates/build-steps.yml` | ⬜ Pending |
| 5.3 | Verify version stamping | `versionnumber.ps1` | ⬜ Pending |
| 5.4 | Update root README | `README.md` | ⬜ Pending |

**Phase 5 gate**: Full solution build + `dotnet test` pass

## 8. Test Plan

### Unit Tests (Automated, No Appliance Required)

These tests mock HTTP responses to verify SDK logic in isolation:

| Test Case | Description | Expected Outcome |
|-----------|-------------|-----------------|
| `DeviceAuth_ValidRequest_SendsCorrectPayload` | Verify POST body format to `/RSTS/oauth2/DeviceLogin` | Request is JSON `{"client_id":"SafeguardDotNet","scope":"..."}`, no trailing slash in URL |
| `DeviceAuth_ValidResponse_ParsesAllFields` | Parse actual RSTS response | All fields populated in `DeviceCodeInfo` including `VerificationUriComplete` |
| `DeviceAuth_InvokesDisplayCallback` | Callback is called with correct data | `DisplayCallback` invoked exactly once with parsed `DeviceCodeInfo` |
| `DeviceAuth_GrantDisabled_ThrowsException` | HTTP 400 "OAuth2DeviceCodeNotAllowed" | Throws `SafeguardDotNetException` with clear error message about enabling grant |
| `DeviceAuth_ServerError_ThrowsException` | HTTP 500 from device auth endpoint | Throws `SafeguardDotNetException` with status code |
| `Poll_AuthorizationPending_ContinuesPolling` | Token endpoint returns `{"error":"authorization_pending"}` | Loop continues, no exception |
| `Poll_SlowDown_IncreasesInterval` | Token endpoint returns `{"error":"slow_down"}` | Polling interval increases by 5 seconds |
| `Poll_Success_ReturnsAccessToken` | Token endpoint returns `{"access_token":"..."}` | RSTS token extracted correctly as SecureString |
| `Poll_AccessDenied_ThrowsException` | Token endpoint returns `{"error":"access_denied"}` | Throws `SafeguardDotNetException` with clear message |
| `Poll_ExpiredToken_ThrowsException` | Token endpoint returns `{"error":"expired_token"}` | Throws `SafeguardDotNetException` indicating code expired |
| `Poll_CancellationRequested_ThrowsOperationCanceled` | CancellationToken triggered mid-poll | Throws `OperationCanceledException` |
| `Poll_RespectsInterval_WaitsBeforeNextRequest` | Verify polling waits 5 seconds between requests | No request made before interval elapses |
| `TokenExchange_ValidRstsToken_ReturnsConnection` | Mock PostLoginResponse returns `{"Status":"Success","UserToken":"..."}` | Returns valid `ISafeguardConnection` |
| `TokenExchange_FailedStatus_ThrowsException` | PostLoginResponse returns non-"Success" status | Throws `SafeguardDotNetException` |
| `Connect_NullDisplayCallback_ThrowsArgumentException` | No callback provided | `ArgumentException` thrown before any network call |
| `Connect_EmptyAppliance_ThrowsArgumentException` | Empty/null appliance | `ArgumentException` thrown |
| `Connect_DefaultScope_UsesLocalProvider` | No explicit scope set | Request body contains `"scope":"rsts:sts:primaryproviderid:local"` |
| `Connect_CustomClientId_SentInRequests` | Custom `ClientId` set in parameters | Both device auth and token polling use the custom client_id |

### Integration Tests (Live Appliance Required)

| Test Case | Tags | Human Interaction | Description |
|-----------|------|-------------------|-------------|
| `DeviceCode_HappyPath_Succeeds` | `auth`, `devicecode`, `interactive` | Yes | Full flow: request code, user authenticates in browser, connection established, calls `/Me` |
| `DeviceCode_GrantDisabled_ReturnsError` | `auth`, `devicecode` | No | With Device Code grant disabled, verify clear error message |
| `DeviceCode_InvalidAppliance_ReturnsError` | `auth`, `devicecode` | No | Non-existent appliance returns connection error |
| `DeviceCode_ExpiredCode_ReturnsError` | `auth`, `devicecode` | No | Let code expire without authenticating, verify timeout error |

### Manual Test Scenarios

| Scenario | Steps | Expected |
|----------|-------|----------|
| Docker container | Run tester tool inside Docker container, authenticate from host browser | Connection succeeds, `/Me` returns user info |
| SSH session | Run tester via SSH, authenticate from local browser | Connection succeeds |
| Cancel mid-flow | Start flow, press Ctrl+C before authenticating | Clean error, no hanging process |

## 9. Verified Facts & Remaining Considerations

### Verified (from source code + live appliance testing)

| # | Question | Answer | Source |
|---|----------|--------|--------|
| 1 | Endpoint path | `POST /RSTS/oauth2/DeviceLogin` — NO trailing slash (405 if present) | `OAuthTokenService.cs:548`, live test |
| 2 | Content type | `application/json` with WCF WrappedRequest body: `{"client_id":"...","scope":"..."}` | `OAuthTokenService.cs:549` |
| 3 | Client ID | Accepts any string if no RelyingPartyApplications configured; validated if configured | `OAuthTokenManager.cs:603` |
| 4 | Scope format | `rsts:sts:primaryproviderid:local` — accepted but NOT functionally used by RSTS | `OAuthTokenService.cs:596` |
| 5 | Token endpoint | `POST /RSTS/oauth2/token` — same as other grants, accepts JSON or form-urlencoded | Live test confirmed |
| 6 | Two-step exchange | RSTS access_token → `POST /service/core/v4/Token/LoginResponse` → UserToken | Live test confirmed |
| 7 | Polling response on pending | HTTP 400 with `{"error":"authorization_pending","error_description":"","success":false}` | Live test confirmed |
| 8 | Expires in | Always 300 seconds (5 minutes), hard-coded in RSTS | `OAuthTokenManager.cs:615` |
| 9 | No `interval` in response | RSTS does not return `interval` field; use RFC default 5 seconds | Live test confirmed |
| 10 | User code format | 9 uppercase consonants (charset `BCDFGHJKLMNPQRSTVWXZ`), displayed as `XXX-XXX-XXX` | `Common.cs:316-319` |
| 11 | Device code format | 57 chars: first 9 = user_code (lookup key), remaining 48 = random | `OAuthTokenManager.cs:727` |
| 12 | SSL handling pattern | Use `HttpClientHandler` with `SslProtocols.Tls12` + conditional `ServerCertificateCustomValidationCallback` | `PkceNoninteractiveLogin.cs:365-377` |
| 13 | `AgentBasedLoginUtils.CreateHttpClient()` | ALWAYS bypasses SSL (hardcoded) — no need to pass `ignoreSsl` for token exchange | `Safeguard.cs` source |
| 14 | verification_uri_complete | Always `https://{appliance}/RSTS/Login?device={user_code_no_dashes}` | `OAuthTokenService.cs:577` |
| 15 | Grant type enable/disable | Setting: `Allowed OAuth2 Grant Types` flag enum includes `DeviceCode` | `OAuthTokenService.cs:557` |

### Assumptions (Still Valid)

1. The `access_token` returned from the polling endpoint is a standard RSTS JWT that
   `PostLoginResponse()` can exchange without modification
2. The `AgentBasedLoginUtils.PostLoginResponse()` method works with device-code-obtained
   tokens the same way it works with PKCE-obtained tokens (both go through
   `CreateAccessTokenFromAuthCode` in RSTS)
3. No rate limiting on the device code polling endpoint (unlike the LoginController
   which has aggressive per-user rate limiting)

### Risks

| Risk | Likelihood | Impact | Mitigation |
|------|-----------|--------|-----------|
| WCF trailing-slash 405 confuses developers | Medium | Low | Document prominently; SDK handles internally |
| Device Code grant not supported on older firmware (<8.2) | Medium | Low | Document minimum firmware; throw clear error with instructions |
| Happy-path integration test hard to automate | High | Low | Mark as `interactive` tag; provide manual test procedure |
| `RelyingPartyApplications` validation breaks default `client_id` | Low | Medium | Document; make `ClientId` configurable (already in design) |

### Design Decisions

1. **`validationCallback` overload**: Not included in initial release. The `ignoreSsl`
   parameter covers the dev scenario. A `RemoteCertificateValidationCallback` overload
   can be added later if customers request it without breaking changes.

2. **Timeout override**: Not included as a separate parameter. The code expires in 300
   seconds server-side regardless. Callers can use `CancellationToken` with
   `CancellationTokenSource.CancelAfter()` for client-side timeout. This is simpler
   and more .NET-idiomatic.

3. **Sync vs Async**: Provide both `Connect()` and `ConnectAsync()`. The sync version
   calls `ConnectAsync().GetAwaiter().GetResult()` internally (matching the pattern
   in `AgentBasedLoginUtils.ApiRequest()` and `PkceNoninteractiveLogin.Connect()`).

## 10. Implementation Reference

### Complete Implementation Pseudocode

This section provides the exact implementation logic for agents to follow.
All HTTP endpoints, payloads, and response handling are **verified** against
the live appliance and RSTS source code.

```csharp
// DeviceCodeLogin.cs — Complete implementation logic

public static ISafeguardConnection Connect(
    string appliance,
    DeviceCodeLoginParameters parameters,
    int apiVersion = Safeguard.DefaultApiVersion,
    bool ignoreSsl = false)
{
    return ConnectAsync(appliance, parameters, apiVersion, ignoreSsl, CancellationToken.None)
        .GetAwaiter().GetResult();
}

public static async Task<ISafeguardConnection> ConnectAsync(
    string appliance,
    DeviceCodeLoginParameters parameters,
    int apiVersion = Safeguard.DefaultApiVersion,
    bool ignoreSsl = false,
    CancellationToken cancellationToken = default)
{
    // === Validation ===
    if (string.IsNullOrEmpty(appliance))
        throw new ArgumentException("Appliance network address is required.", nameof(appliance));
    if (parameters?.DisplayCallback == null)
        throw new ArgumentException("DisplayCallback is required.", nameof(parameters));

    var clientId = parameters.ClientId ?? "SafeguardDotNet";
    var scope = parameters.Scope ?? "rsts:sts:primaryproviderid:local";

    using var http = CreateHttpClient(ignoreSsl);

    // === Step 1: Request device code ===
    Log.Debug("Requesting device authorization from {Appliance}", appliance);

    // CRITICAL: No trailing slash! WCF returns 405 with trailing slash.
    var deviceAuthUrl = $"https://{appliance}/RSTS/oauth2/DeviceLogin";
    var requestBody = JsonConvert.SerializeObject(new { client_id = clientId, scope = scope });
    var content = new StringContent(requestBody, Encoding.UTF8, "application/json");

    var response = await http.PostAsync(deviceAuthUrl, content, cancellationToken);
    var responseBody = await response.Content.ReadAsStringAsync();

    if (!response.IsSuccessStatusCode)
    {
        throw new SafeguardDotNetException(
            $"Device authorization request failed: {response.StatusCode} {responseBody}",
            response.StatusCode, responseBody);
    }

    var deviceResponse = JObject.Parse(responseBody);
    var deviceCode = deviceResponse["device_code"]?.ToString();
    var userCode = deviceResponse["user_code"]?.ToString();
    var verificationUri = deviceResponse["verification_uri"]?.ToString();
    var verificationUriComplete = deviceResponse["verification_uri_complete"]?.ToString();
    var expiresIn = deviceResponse["expires_in"]?.Value<int>() ?? 300;

    // === Step 2: Display to user via callback ===
    parameters.DisplayCallback(new DeviceCodeInfo
    {
        VerificationUri = verificationUri,
        UserCode = userCode,
        VerificationUriComplete = verificationUriComplete,
        ExpiresIn = expiresIn,
    });

    // === Step 3: Poll token endpoint ===
    Log.Debug("Polling token endpoint for device code redemption");

    var tokenUrl = $"https://{appliance}/RSTS/oauth2/token";
    var intervalSeconds = parameters.PollingIntervalSeconds > 0 ? parameters.PollingIntervalSeconds : 5;
    var deadline = DateTime.UtcNow.AddSeconds(expiresIn);
    SecureString rstsAccessToken = null;

    while (DateTime.UtcNow < deadline)
    {
        cancellationToken.ThrowIfCancellationRequested();

        await Task.Delay(TimeSpan.FromSeconds(intervalSeconds), cancellationToken);

        var pollBody = JsonConvert.SerializeObject(new
        {
            grant_type = "urn:ietf:params:oauth:grant-type:device_code",
            device_code = deviceCode,
            client_id = clientId,
        });
        var pollContent = new StringContent(pollBody, Encoding.UTF8, "application/json");
        var pollResponse = await http.PostAsync(tokenUrl, pollContent, cancellationToken);
        var pollResponseBody = await pollResponse.Content.ReadAsStringAsync();
        var pollJson = JObject.Parse(pollResponseBody);

        if (pollResponse.IsSuccessStatusCode)
        {
            // Success! Extract access_token
            rstsAccessToken = pollJson["access_token"]?.ToString().ToSecureString();
            break;
        }

        // HTTP 400 — check error field
        var error = pollJson["error"]?.ToString();
        switch (error)
        {
            case "authorization_pending":
                continue; // Normal — user hasn't authenticated yet
            case "slow_down":
                intervalSeconds += 5; // RFC 8628: increase interval by 5 seconds
                continue;
            case "access_denied":
                throw new SafeguardDotNetException(
                    "Device code authentication was denied.", pollResponse.StatusCode, pollResponseBody);
            case "expired_token":
                throw new SafeguardDotNetException(
                    "Device code has expired. Please try again.", pollResponse.StatusCode, pollResponseBody);
            default:
                throw new SafeguardDotNetException(
                    $"Unexpected error during device code polling: {error}",
                    pollResponse.StatusCode, pollResponseBody);
        }
    }

    if (rstsAccessToken == null)
    {
        throw new SafeguardDotNetException("Device code expired before user authenticated.");
    }

    // === Step 4: Exchange RSTS token for Safeguard UserToken ===
    Log.Debug("Exchanging RSTS access token for Safeguard user token");

    using (rstsAccessToken)
    {
        var responseObject = Safeguard.AgentBasedLoginUtils.PostLoginResponse(
            appliance, rstsAccessToken, apiVersion);

        var statusValue = responseObject.GetValue("Status")?.ToString();
        if (string.IsNullOrEmpty(statusValue) || statusValue != "Success")
        {
            throw new SafeguardDotNetException($"Error exchanging RSTS token, status: {statusValue}");
        }

        // === Step 5: Create connection ===
        using var accessToken = responseObject.GetValue("UserToken")?.ToString().ToSecureString();
        return Safeguard.Connect(appliance, accessToken, apiVersion, ignoreSsl);
    }
}

// === Helper: Create HttpClient with SSL handling ===
// Pattern from PkceNoninteractiveLogin.cs:360-380
private static HttpClient CreateHttpClient(bool ignoreSsl)
{
    var handler = new HttpClientHandler()
    {
        SslProtocols = System.Security.Authentication.SslProtocols.Tls12,
    };

    if (ignoreSsl)
    {
#pragma warning disable S4830 // Intentional SSL bypass when user explicitly opts in
        handler.ServerCertificateCustomValidationCallback = (message, cert, chain, errors) => true;
#pragma warning restore S4830
    }

    return new HttpClient(handler);
}
```

### Project File Template

Based on `SafeguardDotNet.PkceNoninteractiveLogin.csproj`:

```xml
<Project Sdk="Microsoft.NET.Sdk">

  <PropertyGroup>
    <TargetFramework>netstandard2.0</TargetFramework>
    <LangVersion>latest</LangVersion>
    <RootNamespace>OneIdentity.SafeguardDotNet.DeviceCodeLogin</RootNamespace>
    <PackageId>OneIdentity.SafeguardDotNet.DeviceCodeLogin</PackageId>
    <Authors>One Identity LLC</Authors>
    <Copyright>(c) 2026 One Identity LLC. All rights reserved.</Copyright>
    <PackageRequireLicenseAcceptance>true</PackageRequireLicenseAcceptance>
    <PackageLicenseExpression>Apache-2.0</PackageLicenseExpression>
    <PackageProjectUrl>https://github.com/OneIdentity/SafeguardDotNet</PackageProjectUrl>
    <PackageIcon>Content\images\SafeguardLogo.png</PackageIcon>
    <PackageReadmeFile>README.md</PackageReadmeFile>
    <RepositoryUrl>https://github.com/OneIdentity/SafeguardDotNet</RepositoryUrl>
    <Version>9999.9999.9999</Version>
    <Description>Device Code Login for One Identity Safeguard Web API .NET SDK</Description>
    <AssemblyVersion>9999.9999.9999.9999</AssemblyVersion>
    <FileVersion>9999.9999.9999.9999</FileVersion>
    <AssemblyName>OneIdentity.SafeguardDotNet.DeviceCodeLogin</AssemblyName>
    <RepositoryType>git</RepositoryType>
    <IncludeSymbols>true</IncludeSymbols>
    <SymbolPackageFormat>snupkg</SymbolPackageFormat>
    <PackageTags>safeguard;credentials;vault;sdk;oauth;device-code;rfc8628</PackageTags>
    <PackageReleaseNotes>
      Device Code Login for One Identity Safeguard Web API .NET SDK

      Allows custom application to use the Safeguard Web API by authenticating to
      Safeguard using OAuth 2.0 Device Authorization Grant (RFC 8628). This enables
      authentication from headless environments without a local browser.
    </PackageReleaseNotes>
  </PropertyGroup>

  <ItemGroup>
    <None Include="..\SafeguardLogo.png" Link="SafeguardLogo.png" Pack="true" PackagePath="Content\images\" />
    <None Include="README.md" Pack="true" PackagePath="\" />
  </ItemGroup>

  <ItemGroup>
    <PackageReference Include="Serilog" Version="4.3.0" />
    <PackageReference Include="Newtonsoft.Json" Version="13.0.4" />
  </ItemGroup>

  <ItemGroup>
    <ProjectReference Include="..\SafeguardDotNet\SafeguardDotNet.csproj" />
  </ItemGroup>

  <Target Name="SignAssemblies" AfterTargets="PostBuildEvent">
    <Exec Condition="'$(SignFiles)'=='true'" Command="&quot;$(SignToolPath)&quot; sign /debug /v /fd SHA256 /tr http://ts.ssl.com /td sha256 /sha1 $(CertThumbprint) &quot;$(TargetDir)*.dll&quot;" />
  </Target>

</Project>
```

### CLI Tester Template

Based on `Test/SafeguardDotNetPkceNoninteractiveLoginTester/Program.cs` pattern:

```csharp
// Test/SafeguardDotNetDeviceCodeLoginTester/Program.cs
using System;
using System.Net;
using OneIdentity.SafeguardDotNet;
using OneIdentity.SafeguardDotNet.DeviceCodeLogin;
using Serilog;

Log.Logger = new LoggerConfiguration()
    .MinimumLevel.Debug()
    .WriteTo.Console()
    .CreateLogger();

if (args.Length < 1)
{
    Console.WriteLine("Usage: SafeguardDotNetDeviceCodeLoginTester <appliance> [ignoreSsl]");
    return;
}

var appliance = args[0];
var ignoreSsl = args.Length > 1 && args[1].Equals("true", StringComparison.OrdinalIgnoreCase);

try
{
    using var connection = DeviceCodeLogin.Connect(
        appliance,
        new DeviceCodeLoginParameters
        {
            DisplayCallback = info =>
            {
                Console.WriteLine();
                Console.WriteLine("═══════════════════════════════════════════════════════");
                Console.WriteLine("  To sign in, open a browser and visit:");
                Console.WriteLine($"  {info.VerificationUriComplete}");
                Console.WriteLine();
                Console.WriteLine($"  Or go to: {info.VerificationUri}");
                Console.WriteLine($"  And enter code: {info.UserCode}");
                Console.WriteLine();
                Console.WriteLine($"  Code expires in {info.ExpiresIn} seconds.");
                Console.WriteLine("═══════════════════════════════════════════════════════");
                Console.WriteLine();
            },
        },
        ignoreSsl: ignoreSsl);

    Console.WriteLine("Successfully connected!");
    var me = connection.InvokeMethod(Service.Core, Method.Get, "Me");
    Console.WriteLine($"Logged in as: {me}");
}
catch (SafeguardDotNetException ex)
{
    Console.Error.WriteLine($"Error: {ex.Message}");
    if (ex.HasResponse)
        Console.Error.WriteLine($"Response: {ex.Response}");
}
```

## 11. Implementation Gotchas & Critical Notes

> **These are hard-won lessons from live testing. Agents MUST follow these.**

### ⚠️ URL Trailing Slash (CRITICAL)

The device authorization endpoint is WCF-hosted. WCF routing with `UriTemplate = "/DeviceLogin"`
does NOT accept a trailing slash. If you make a request to `/RSTS/oauth2/DeviceLogin/` you will
get **HTTP 405 Method Not Allowed**. The URL MUST be `/RSTS/oauth2/DeviceLogin` (no trailing slash).

### ⚠️ JSON Body Format (NOT form-urlencoded)

The `/RSTS/oauth2/DeviceLogin` endpoint uses WCF `WebMessageBodyStyle.WrappedRequest` which
means the body is JSON: `{"client_id":"...", "scope":"..."}`. This is DIFFERENT from the RFC 8628
specification which suggests `application/x-www-form-urlencoded`. The RSTS implementation
chose JSON for the device authorization request.

The token endpoint (`/RSTS/oauth2/token`) accepts BOTH JSON and form-urlencoded. Use JSON
for consistency with `AgentBasedLoginUtils.ApiRequest()`.

### ⚠️ No `interval` in Response

RSTS does not return the `interval` field in the device code response. Per RFC 8628 Section 3.2,
when `interval` is absent the client MUST use a default of 5 seconds.

### ⚠️ AgentBasedLoginUtils Always Bypasses SSL

The static `CreateHttpClient()` in `Safeguard.AgentBasedLoginUtils` ALWAYS sets
`ServerCertificateCustomValidationCallback = true` regardless of any `ignoreSsl` parameter.
This means `PostLoginResponse()` (Step 4) will work against self-signed cert appliances
without any special handling. The final `Safeguard.Connect()` call properly respects `ignoreSsl`.

### ⚠️ Build Requirements

- Build command: `dotnet build SafeguardDotNet.Core.sln /p:SignFiles=false`
- Must pass with **0 errors, 0 warnings** (strict Roslyn analyzers via `Directory.Build.props`)
- StyleCop rules enforced: no `#region`, braces required, naming conventions
- Private static fields: `s_` prefix (e.g., `s_defaultPollingInterval`)
- Private instance fields: `_` prefix
- XML doc comments required on all public types/members
- `GenerateDocumentationFile` is enabled

### ⚠️ Version Numbers

Version placeholders `9999.9999.9999` / `9999.9999.9999.9999` are CI markers. Do NOT change them.
They are replaced at build time by `versionnumber.ps1`.

### ⚠️ Solution Integration

After creating the project, add it to `SafeguardDotNet.Core.sln`:
```
dotnet sln SafeguardDotNet.Core.sln add SafeguardDotNet.DeviceCodeLogin/SafeguardDotNet.DeviceCodeLogin.csproj
dotnet sln SafeguardDotNet.Core.sln add Test/SafeguardDotNetDeviceCodeLoginTester/SafeguardDotNetDeviceCodeLoginTester.csproj
```

## 12. Related Work Items / Links

- **GitHub Issue:** [OneIdentity/SafeguardDotNet#226 — Add support for OAuth 2.0 Device Authorization Grant](https://github.com/OneIdentity/SafeguardDotNet/issues/226)
- **RFC:** [RFC 8628 — OAuth 2.0 Device Authorization Grant](https://datatracker.ietf.org/doc/html/rfc8628)
- **Existing patterns:** `SafeguardDotNet.BrowserLogin/`, `SafeguardDotNet.PkceNoninteractiveLogin/`
- **RSTS source:** `rSTS/HttpService/OAuth2/OAuthTokenService.cs` (DeviceLogin endpoint, line 548)
- **RSTS source:** `rSTS/HttpService/OAuth2/OAuthTokenManager.cs` (CreateDeviceLoginCode, line 601)
- **RSTS source:** `rSTS/HttpService/Common.cs` (DeviceCodeFlowPath = "DeviceLogin", line 304)
- **RSTS token flow:** `Safeguard.AgentBasedLoginUtils.PostLoginResponse()` in `SafeguardDotNet/Safeguard.cs`
- **SSL pattern:** `PkceNoninteractiveLogin.CreateHttpClient()` at line 360
- **Live appliance verified:** SPP 8.2.0.21662 at 192.168.117.15
