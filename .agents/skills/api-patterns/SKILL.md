---
name: api-patterns
description: Use when making standard Safeguard Web API calls with ISafeguardConnection and related SDK helpers.
---

# API Patterns

Use this skill when you need to turn a Safeguard REST operation into the normal
SafeguardDotNet calling pattern. The SDK keeps the public surface intentionally
small: choose a connection factory from `Safeguard`, then dispatch with
`ISafeguardConnection.InvokeMethod()`, `InvokeMethodFull()`, `InvokeMethodCsv()`,
or the A2A-specific context.

## 1. Service/endpoint enumeration

`Service` in `SafeguardDotNetTypes.cs` is the dispatch switch for standard API calls:

| Service | What it is for | Standard base URL |
|---|---|---|
| `Service.Core` | Cluster-wide product APIs: users, assets, policies, requests, A2A registrations | `https://<appliance>/service/core/v<apiVersion>/` |
| `Service.Appliance` | Appliance-local operations such as maintenance and diagnostics | `https://<appliance>/service/appliance/v<apiVersion>/` |
| `Service.Notification` | Anonymous/read-only status style endpoints | `https://<appliance>/service/notification/v<apiVersion>/` |
| `Service.A2A` | Reserved enum member; `SafeguardConnection` rejects it for normal `InvokeMethod()` calls | Use `Safeguard.A2A.GetContext()` instead |
| `Service.Management` | DR/support operations on the management service | Call `connection.GetManagementServiceConnection()` first |

Operational rules:

- `Safeguard.DefaultApiVersion` is `4`.
- `SafeguardConnection` only routes `Core`, `Appliance`, and `Notification`.
- `Service.A2A` throws `SafeguardDotNetException("You must call the A2A service using the A2A specific method")`.
- Management requests require a derived connection created with
  `ISafeguardConnection.GetManagementServiceConnection(string networkAddress)`.
- Swagger is still the easiest endpoint catalog: browse
  `https://<address>/service/<service>/swagger` and then translate the operation into
  `Service + Method + relativeUrl`.

## 2. URL construction or method dispatch

`SafeguardConnection` builds absolute service roots in its constructor and combines
those with your relative endpoint path at request time.

### Method surface

Only four HTTP verbs are exposed by the public `Method` enum:

- `Method.Get`
- `Method.Post`
- `Method.Put`
- `Method.Delete`

Use the simplest dispatcher that matches the task:

- `InvokeMethod()` -> body string only
- `InvokeMethodFull()` -> `FullResponse` with `StatusCode`, `Headers`, and `Body`
- `InvokeMethodCsv()` -> forces `Accept: text/csv`
- `connection.Streaming.*` -> file upload/download flows, not normal JSON CRUD

### Relative URL rules

- Pass paths like `Me`, `Assets`, or `Users/123/Password`.
- Do **not** include the service prefix or API version; the SDK adds those.
- Do **not** include a leading `/`. The implementation strips one as a compatibility
  workaround, but new code should avoid relying on that cleanup.

### Query parameters and headers

Use the optional dictionaries instead of string-building URLs by hand:

```csharp
var query = new Dictionary<string, string>
{
    ["filter"] = "CertificateUserThumbprint ieq '756766BB590D7FA9CA9E1971A4AE41BB9CEC82F1'",
};

var headers = new Dictionary<string, string>
{
    ["X-Correlation-ID"] = Guid.NewGuid().ToString(),
};

var json = connection.InvokeMethod(
    Service.Core,
    Method.Get,
    "A2ARegistrations",
    parameters: query,
    additionalHeaders: headers);
```

Implementation details that matter:

- `SafeguardConnection.AddQueryParameters()` URL-escapes both keys and values.
- If you do not set `Accept`, `InvokeMethodFull()` assumes JSON and adds
  `Accept: application/json`.
- `POST` and `PUT` bodies are always sent as UTF-8 `application/json`.
- `InvokeMethodCsv()` injects `Accept: text/csv` before dispatching.

### When you need the full envelope

Use `InvokeMethodFull()` when callers need headers or status code in addition to
JSON content:

```csharp
var response = connection.InvokeMethodFull(
    Service.Core,
    Method.Get,
    "Me");

Console.WriteLine((int)response.StatusCode);
Console.WriteLine(response.Body);
```

The `Test\SafeguardDotNetTool` CLI mirrors this pattern behind its `-f` switch.

## 3. Authentication context for API calls

The SDK has multiple connection factories on `Safeguard`:

- anonymous: `Safeguard.Connect(appliance)`
- username/password: `Safeguard.Connect(appliance, provider, username, password, ...)`
- client certificate by thumbprint, file, or byte array
- existing access token: `Safeguard.Connect(appliance, accessToken, ...)`

What happens after connect:

- Non-anonymous calls add `Authorization: Bearer <token>` automatically.
- Anonymous connections skip the bearer header and are limited to endpoints that
  really support anonymous access.
- SSL behavior lives on the authentication mechanism and is reused by the HTTP
  client and event listeners.
- `LogOut()` posts to `Core/Token/Logout` and then clears the cached token.

For long-running automation, wrap the connection:

```csharp
using var baseConnection = Safeguard.Connect(appliance, "local", username, password, apiVersion: 4, ignoreSsl: true);
using var connection = Safeguard.Persist(baseConnection);

var me = connection.InvokeMethod(Service.Core, Method.Get, "Me");
```

`PersistentSafeguardConnection` checks `GetAccessTokenLifetimeRemaining() <= 0`
before each call and runs `RefreshAccessToken()` automatically. That is the only
built-in retry-like behavior for standard API traffic.

## 4. CRUD examples (standard patterns)

### Read

```csharp
var meJson = connection.InvokeMethod(Service.Core, Method.Get, "Me");
```

For an anonymous health-style call, use the notification service instead:

```csharp
using var anon = Safeguard.Connect(appliance, apiVersion: 4, ignoreSsl: true);
var statusJson = anon.InvokeMethod(Service.Notification, Method.Get, "Status");
```

### Create

The repository README uses this pattern to create an asset:

```csharp
var createdAsset = connection.InvokeMethod(
    Service.Core,
    Method.Post,
    "Assets",
    JsonConvert.SerializeObject(new
    {
        Name = "linux.blue.vas",
        NetworkAddress = "linux.blue.vas",
        Description = "A new linux asset",
        PlatformId = 188,
        AssetPartitionId = -1,
    }));
```

### Update

Two common update styles appear in the repo:

```csharp
connection.InvokeMethod(
    Service.Core,
    Method.Put,
    $"Users/{userId}/Password",
    JsonConvert.SerializeObject("MyNewUser123"));
```

```csharp
context.SetPassword(apiKey, newPassword);
context.SetPrivateKey(apiKey, privateKey, passphrase, KeyFormat.OpenSsh);
```

### Delete

The transport pattern is identical; choose `Method.Delete` and a relative URL that
Swagger confirms supports deletion:

```csharp
connection.InvokeMethod(Service.Core, Method.Delete, $"Assets/{assetId}");
```

### Action-style POST endpoints

Not every `POST` is a create. Samples use action endpoints such as:

```csharp
connection.InvokeMethod(Service.Core, Method.Post, $"AccessRequests/{accessRequestId}/Approve");
connection.InvokeMethod(Service.Core, Method.Post, $"AccessRequests/{accessRequestId}/Deny");
```

Treat these as command endpoints discovered from Swagger or existing samples, not as
plain resource creation.

## 5. Error handling and retry behavior

Every standard HTTP failure is normalized to `SafeguardDotNetException`.

What you get back on failure:

- `HttpStatusCode` when the server replied
- `Response` with the raw body
- `ErrorCode` parsed from JSON `Code` when present
- `ErrorMessage` parsed from JSON `Message` or `error`, otherwise the raw response text

Common failure sources:

- non-success HTTP status -> `SafeguardDotNetException(message, status, response)`
- `HttpRequestException` -> wrapped as `SafeguardDotNetException(..., innerException)`
- request timeout / cancellation -> `SafeguardDotNetException("Request timeout to ...")`
- disposed objects -> `ObjectDisposedException`
- unsupported service usage -> `SafeguardDotNetException`

Recommended handling pattern:

```csharp
try
{
    var json = connection.InvokeMethod(Service.Core, Method.Get, "Me");
}
catch (SafeguardDotNetException ex)
{
    Log.Error("Status={Status} Code={Code} Message={Message} Body={Body}",
        ex.HttpStatusCode,
        ex.ErrorCode,
        ex.ErrorMessage,
        ex.Response);
    throw;
}
```

Retry guidance:

- There is **no** general HTTP retry loop in `SafeguardConnection`.
- Caller code must decide whether a failed GET/POST/PUT/DELETE is safe to retry.
- `Safeguard.Persist()` only handles expired access tokens, not transient 5xx/429 errors.
- Persistent SignalR listeners reconnect separately; that behavior does not apply to
  one-shot REST calls.

## 6. Swagger/OpenAPI integration

This repository does **not** generate a typed client from OpenAPI. The workflow is:

1. Open Swagger at `https://<address>/service/<service>/swagger`.
2. Find the operation, verb, path, query parameters, and body schema.
3. Map the service name to the SDK `Service` enum.
4. Pass the path after `/v<apiVersion>/` as `relativeUrl`.
5. Serialize the request body with `JsonConvert.SerializeObject(...)` when needed.

Useful repository-backed examples:

- `README.md` shows create/update examples for core resources.
- `Samples\SampleA2aService\SampleService.cs` shows filtered `A2ARegistrations`
  enumeration through `Service.Core`.
- `Test\SafeguardDotNetTool` is the generic reproducer for ad hoc API dispatch.

If an endpoint belongs to `/service/a2a/...`, switch mental models: consult Swagger,
then implement it through `Safeguard.A2A.GetContext()` and `ISafeguardA2AContext`
instead of `ISafeguardConnection`.
