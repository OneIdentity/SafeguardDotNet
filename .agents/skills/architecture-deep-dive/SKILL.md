---
name: architecture-deep-dive
description: >-
  Use when working on SDK internals, authentication mechanisms, connection
  classes, PKCE login flow, rSTS protocol details, event listeners, A2A
  integration, SPS integration, or exploring the Safeguard API via Swagger.
  Covers the entry point, auth strategy pattern, decorator pattern, rSTS
  step flow, and SignalR event architecture.
---

# Architecture Deep Dive

## Exploring the Safeguard API

The appliance exposes Swagger UI for each service at:
- `https://<appliance>/service/core/swagger` — Core service (assets, users, policies, requests)
- `https://<appliance>/service/appliance/swagger` — Appliance service (networking, diagnostics)
- `https://<appliance>/service/notification/swagger` — Notification service (events)
- `https://<appliance>/service/event/swagger` — Event service (SignalR streaming)

Use Swagger to discover endpoints, required fields, query parameters, and response schemas.
The default API version is **v4** (`Safeguard.DefaultApiVersion = 4`). Pass `apiVersion: 3`
to any connection method for legacy v3. Both coexist in Safeguard 7.x+.

## Entry point (`Safeguard.cs`)

The static `Safeguard` class is the SDK's public entry point. It provides:
- **18 `Connect()` overloads** — anonymous, access token, password, certificate (thumbprint/file/memory)
- **`Safeguard.Event.GetPersistentEventListener()`** — persistent SignalR event listeners
- **`Safeguard.A2A.GetContext()`** — certificate-only A2A context
- **`Safeguard.AgentBasedLoginUtils`** — PKCE helpers (code verifier, code challenge, CSRF tokens)
- **`Safeguard.Persist()`** — wraps a connection in `PersistentSafeguardConnection` for auto-refresh

## Authentication strategy pattern (`Authentication/`)

All authenticators implement `IAuthenticationMechanism`. When adding a new authentication
method:
1. Implement `IAuthenticationMechanism` in `SafeguardDotNet/Authentication/`
2. Add `Safeguard.Connect()` overload(s) in `Safeguard.cs`
3. Use the private `GetConnection()` helper to ensure token refresh on initial creation

### Authenticator implementations

| Class | Auth method | Key detail |
|-------|------------|------------|
| `PasswordAuthenticator` | Username/password via ROG | ROG disabled by default on appliances |
| `CertificateAuthenticator` | Client certificate | Supports thumbprint, file path, or in-memory |
| `AccessTokenAuthenticator` | Pre-existing access token | No refresh capability |
| `AnonymousAuthenticator` | Unauthenticated | Limited API access |
| `ManagementServiceAuthenticator` | Management service | For DR and support operations |

## Connection classes

- **`SafeguardConnection`** — Base `ISafeguardConnection` implementation. Makes HTTP calls via
  `InvokeMethod()` / `InvokeMethodFull()`. Implements `ICloneable`.
- **`PersistentSafeguardConnection`** — Decorator that checks `GetAccessTokenLifetimeRemaining() <= 0`
  before each call and auto-refreshes tokens.
- **`SafeguardManagementServiceConnection`** — For management service (disaster recovery, support).

### Adding a new connection type

1. Implement `ISafeguardConnection` (or extend `SafeguardConnection`)
2. Track `_disposed` field and check it in all public methods
3. Ensure `ICloneable` support if the connection should be copyable
4. Apply `ignoreSsl` / `validationCallback` consistently to all HTTP clients

## PKCE non-interactive login (`SafeguardDotNet.PkceNoninteractiveLogin/`)

Simulates the browser-based PKCE OAuth2 flow by directly interacting with rSTS endpoints.
Supports primary (password) and secondary (MFA/TOTP) authentication.

Two public `Connect()` overloads:
```csharp
// Without MFA
PkceNoninteractiveLogin.Connect(appliance, provider, username, password, apiVersion, ignoreSsl)

// With MFA (secondaryPassword is the TOTP code or RADIUS response)
PkceNoninteractiveLogin.Connect(appliance, provider, username, password, secondaryPassword, apiVersion, ignoreSsl)
```

## rSTS login flow (critical implementation detail)

The rSTS login controller at `/RSTS/UserLogin/LoginController` uses a `loginRequestStep`
query parameter. The non-interactive PKCE module drives this flow programmatically:

| Step | Constant | Purpose | Key response |
|------|----------|---------|-------------|
| 1 | `StepInit` | Provider initialization | Provider list, CSRF token |
| 3 | `StepPrimaryAuth` | Primary auth (password) | `SecondaryProviderID` if MFA required |
| 7 | `StepSecondaryInit` | Init secondary provider | `Message` (prompt), `State` (MFA context) |
| 5 | `StepSecondaryAuth` | Submit MFA code | Empty on success, 203 with error JSON on failure |
| 6 | `StepGenerateClaims` | Generate claims | `RelyingPartyUrl` with authorization code |

### HTTP status codes from rSTS

- **200** — Success
- **203** — rSTS challenge/error (NOT a standard HTTP error; body is JSON with `Message`/`State`)
- **400** — Hard error (plain text body, e.g., "Invalid password." or "Access denied.")

### Appliance error message configuration

Detailed error messages (e.g., "Invalid password.", "User is unknown.") can be enabled or
disabled on the appliance. When disabled, all auth failures return the generic "Access
denied." message. Code and test assertions must handle both cases.

### rSTS rate limiting

The rSTS login controller has aggressive per-user rate limiting. Multiple authentication
requests in quick succession trigger `"There have been too many authentication requests for
this user"` with a cooldown window of several minutes. This affects PKCE flows but NOT the
Resource Owner Grant token endpoint. When writing code or tests that perform multiple auth
attempts, minimize the count per user and space them out.

## Event listeners (`Event/`)

- **`SafeguardEventListener`** — Standard SignalR listener. Does NOT survive 30+ second outages.
- **`PersistentSafeguardEventListenerBase`** — Base class with exponential backoff reconnect.
- **`PersistentSafeguardEventListener`** — Production-grade persistent listener.
- **`PersistentSafeguardA2AEventListener`** — Persistent A2A-specific variant.
- Use `GetPersistentEventListener()` for production deployments.

### Event listener architecture

All listeners use ASP.NET Core SignalR client. Key implementation details:
- `EventHandlerRegistry` manages handler registration per event name
- Persistent listeners auto-reconnect with exponential backoff on disconnect
- SSL/TLS settings must be applied to the SignalR `HubConnection` consistently
  with the parent `SafeguardConnection`

## A2A (`A2A/`)

Certificate-only authentication for automated credential retrieval. Key types:
- `ISafeguardA2AContext` — Main A2A context interface
- `A2ARetrievableAccount` — Account configured for A2A retrieval (implements `IDisposable`)
- `BrokeredAccessRequest` — Access request brokering
- `ApiKeySecret` — API key with `SecureString` value (implements `IDisposable`)

A2A connections are always certificate-based. There is no username/password option.

## SPS integration (`Sps/`)

Integration with Safeguard for Privileged Sessions:
- `ISafeguardSessionsConnection` / `SafeguardSessionsConnection`
- Joined via `ISafeguardConnection.JoinSps()`
- Requires a separate SPS appliance address and credentials
- Tests require the `-SpsAppliance` and `-SpsCredentials` parameters
