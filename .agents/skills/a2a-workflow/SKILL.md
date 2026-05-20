---
name: a2a-workflow
description: Use when working with Safeguard A2A certificate auth, credential retrieval, brokering, or A2A event listeners.
---

# A2A Workflow
Safeguard A2A (Application-to-Application) is the SDK surface for unattended,
certificate-based integrations. In this repo, `Safeguard.A2A.GetContext(...)`
creates an `ISafeguardA2AContext` that talks to `/service/A2A/v<apiVersion>/...`
with a client certificate plus an A2A API key. It is used for retrieving passwords,
SSH keys, API key secrets, brokering access requests, and subscribing to A2A
credential-change events.
## 1. What A2A is (one-paragraph context)

A2A is the automation-friendly side of Safeguard. Unlike normal `Safeguard.Connect()`
flows that authenticate a user and then send bearer tokens, A2A uses a client
certificate to establish trust and an `Authorization: A2A <apiKey>` header to scope
credential retrieval or brokering to a configured registration. The SDK models this
with `ISafeguardA2AContext`, `SafeguardA2AContext`, `A2ARetrievableAccount`,
`BrokeredAccessRequest`, and `ApiKeySecret`.
## 2. Setup flow (certificate registration, API key creation)

The repository does not create A2A registrations for you; that setup happens on the
Safeguard appliance. The codebase shows the expected appliance-side shape.

### Appliance-side prerequisites

1. Register a client certificate for the integration.
2. Create one or more A2A registrations tied to that certificate user.
3. Assign retrievable accounts and/or brokering rights.
4. Generate the A2A API key that will be used for retrieval or brokering.

### SDK context creation patterns

`Safeguard.A2A.GetContext(...)` supports the same three certificate sources used by
other certificate-based SDK entry points:

- certificate store thumbprint
- PFX/PKCS#12 file + password
- in-memory certificate bytes + password

Examples:

```csharp
using var context = Safeguard.A2A.GetContext(
    appliance,
    thumbprint,
    apiVersion: 4,
    ignoreSsl: true);
```

```csharp
using var context = Safeguard.A2A.GetContext(
    appliance,
    certificatePath,
    certificatePassword,
    apiVersion: 4,
    ignoreSsl: true);
```

```csharp
var bytes = File.ReadAllBytes(certificatePath);
using var context = Safeguard.A2A.GetContext(
    appliance,
    bytes,
    certificatePassword,
    apiVersion: 4,
    ignoreSsl: true);
```

Validation-callback overloads also exist when you want custom certificate validation
instead of `ignoreSsl`.

### Enumerating registrations and API keys

`Samples\SampleA2aService\SampleService.cs` shows a practical discovery flow:

1. Create a normal certificate-backed `ISafeguardConnection`
2. Query `Service.Core` `A2ARegistrations`
3. Filter by `CertificateUserThumbprint`
4. Query `A2ARegistrations/{id}/RetrievableAccounts`
5. Read the returned `ApiKey` values and cache them as `SecureString`

That sample uses:

```csharp
var a2AJson = _connection.InvokeMethod(
    Service.Core,
    Method.Get,
    "A2ARegistrations",
    parameters: new Dictionary<string, string>
    {
        ["filter"] = $"CertificateUserThumbprint ieq '{thumbprint}'",
    });
```

Important setup notes pulled from the repo:

- `ISafeguardA2AContext.GetRetrievableAccounts()` is documented as a Safeguard v2.8+
  feature that must be enabled in the A2A configuration.
- The sample comments note that enumerating registrations by certificate user may
  require auditor permission.
- `SampleA2aService` throws if no API keys are found after enumeration.

## 3. Credential retrieval (programmatic access)

### Primary retrieval methods on `ISafeguardA2AContext`

| Method | Purpose |
|---|---|
| `GetRetrievableAccounts()` / `GetRetrievableAccounts(filter)` | Discover accessible accounts and API keys |
| `RetrievePassword(apiKey)` | Fetch a password as `SecureString` |
| `SetPassword(apiKey, password)` | Rotate/update a password |
| `RetrievePrivateKey(apiKey, keyFormat)` | Fetch an SSH private key |
| `SetPrivateKey(apiKey, privateKey, password, keyFormat)` | Upload/update an SSH private key |
| `RetrieveApiKeySecret(apiKey)` | Fetch API key secret material as `IList<ApiKeySecret>` |

### Transport details

`SafeguardA2AContext` uses these routes internally:

- `GET Core/A2ARegistrations`
- `GET Core/A2ARegistrations/{id}/RetrievableAccounts`
- `GET A2A/Credentials?type=Password`
- `PUT A2A/Credentials/Password`
- `GET A2A/Credentials?type=PrivateKey&keyFormat=<format>`
- `PUT A2A/Credentials/SshKey?keyFormat=<format>`
- `GET A2A/Credentials?type=ApiKey`

The context sends:

- `Accept: application/json`
- `Authorization: A2A <apiKey>` when an API key is required
- the client certificate on the TLS connection

### Typical password retrieval pattern

```csharp
using var context = Safeguard.A2A.GetContext(appliance, thumbprint, apiVersion: 4, ignoreSsl: true);
using var password = context.RetrievePassword(apiKey.ToSecureString());

var clearText = password.ToInsecureString();
```

### Discovering retrievable accounts

`Test\SafeguardDotNetA2aTool` uses `GetRetrievableAccounts()` in two modes:

- no filter -> enumerate everything visible to the registration
- SCIM-style filter -> e.g. `AccountName eq 'admin'`

The filter is applied server-side to each registration's retrievable-accounts endpoint.

### API key secret retrieval

`RetrieveApiKeySecret()` returns `ApiKeySecret` objects whose `ClientSecret` is a
`SecureString`. Dispose them when you are done.

### Secure disposal expectations

- `ApiKeySecret` implements `IDisposable`
- `A2ARetrievableAccount.ApiKey` is treated as sensitive data
- certificate passwords and retrieved credentials should stay in `SecureString`
- top-level services such as `SampleA2aService` dispose listeners, connections, and
  A2A contexts during shutdown

## 4. Brokering (if supported)

Yes. `ISafeguardA2AContext.BrokerAccessRequest()` posts a `BrokeredAccessRequest`
object to `A2A/AccessRequests`.

### Minimum required fields

`SafeguardA2AContext` enforces these before the HTTP call:

- one of `ForUserId` or `ForUserName`
- one of `AssetId` or `AssetName`

If either is missing, it throws `SafeguardDotNetException` before contacting the
server.

### Useful optional fields from `BrokeredAccessRequest`

- `AccessType` (`Password`, `Ssh`, `Rdp`)
- `AccountId` / `AccountName`
- `AccountAssetId` / `AccountAssetName`
- `ReasonCodeId` / `ReasonCode`
- `ReasonComment`
- `TicketNumber`
- `RequestedFor`
- `RequestedDuration`

`Test\SafeguardDotNetAccessRequestBrokerTool` shows the intended calling pattern:

```csharp
using var context = CreateA2AContext(opts);
var accessRequest = GetBrokeredAccessRequestObject(opts);
var json = context.BrokerAccessRequest(opts.ApiKey.ToSecureString(), accessRequest);
```

The tool accepts either IDs or names for user, asset, account, and reason code, then
maps numeric strings to the `*Id` properties.

## 5. Event listeners / SignalR (if supported)

Yes. A2A supports both non-persistent and persistent SignalR listeners.

### Context-based listener APIs

| Method | Recovery behavior |
|---|---|
| `GetA2AEventListener(apiKey, handler)` | Does **not** recover from a 30+ second outage |
| `GetA2AEventListener(apiKeys, handler)` | Same, but for multiple API keys |
| `GetPersistentA2AEventListener(apiKey, handler)` | Reconnects automatically |
| `GetPersistentA2AEventListener(apiKeys, handler)` | Reconnects automatically |

### Static helper APIs

`Safeguard.A2A.Event.GetPersistentA2AEventListener(...)` exposes the same persistent
listener pattern directly from:

- thumbprint-based certificate auth
- certificate file + password
- in-memory certificate bytes + password
- optional validation-callback overloads
- single API key or multiple API keys

### Event names actually registered

The implementation registers handlers for three A2A events:

- `AssetAccountPasswordUpdated`
- `AssetAccountSshKeyUpdated`
- `AccountApiKeySecretUpdated`

This is worth knowing because some XML comments still describe only the password
update event.

### Reconnect behavior

Persistent A2A listeners are backed by `PersistentSafeguardA2AEventListener`, which
inherits the shared reconnect loop from `PersistentSafeguardEventListenerBase`:

- reconnect work runs in the background
- failures log a warning and sleep for 5 seconds
- the listener retries until reconnection succeeds or stop/dispose is requested

Use the persistent variant for Windows services, daemon-style workloads, or anything
that must survive appliance/network interruptions.

### Sample patterns in this repo

- `Samples\SampleA2aService\SampleService.cs` starts one persistent listener per API key
- `Test\SafeguardDotNetEventTool` supports single-key, multi-key, and "discover all keys"
  flows before starting a listener
- both patterns call `Start()` explicitly after creating the listener

## 6. Error scenarios and troubleshooting

### Common argument/setup failures

- No certificate input -> the CLI tools throw `InvalidOperationException("Must specify CertificateFile or Thumbprint")`
- Null `apiKey`, `password`, `privateKey`, or `accessRequest` -> `ArgumentException`
- Empty API key set for multi-key listeners -> `ArgumentException`
- Missing user or asset in brokered requests -> `SafeguardDotNetException`

### HTTP/API failures

`SafeguardA2AContext.ApiRequest()` throws `SafeguardDotNetException` when Safeguard
returns a non-success HTTP status. The exception includes status and raw response
content, so inspect `HttpStatusCode`, `ErrorMessage`, and `Response`.

### Timeouts and retries

- one-shot retrieval/brokering calls do **not** include an automatic retry loop
- timeout surfaces as `SafeguardDotNetException("Request timeout to ...")`
- retry policy for `RetrievePassword()`, `RetrievePrivateKey()`, or `BrokerAccessRequest()`
  is the caller's responsibility
- only persistent SignalR listeners auto-reconnect

### SSL troubleshooting

- `ignoreSsl` bypasses certificate validation and is intended for dev/test only
- production integrations should prefer trusted certificates or a validation callback
- the same certificate source pattern is reused across normal SDK connections and A2A

### Registration discovery troubleshooting

If registration enumeration fails in the sample flow, check:

- whether the certificate thumbprint matches the A2A registration's certificate user
- whether the registration has retrievable accounts configured
- whether the appliance version/config supports `GetRetrievableAccounts()`
- whether the caller has permission to enumerate `A2ARegistrations`

If you only need retrieval and already have a valid API key, skip the Core registration
lookup and call the A2A context methods directly.
