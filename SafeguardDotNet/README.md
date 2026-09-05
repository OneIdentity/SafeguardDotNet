# SafeguardDotNet

One Identity Safeguard Web API .NET SDK

## Overview

SafeguardDotNet provides a comprehensive .NET SDK for interacting with the One Identity Safeguard for Privileged Passwords API. This library simplifies authentication, API calls, and event handling, allowing you to integrate Safeguard functionality into your .NET applications with minimal code.

## Key Features

- **Multiple Authentication Methods**
  - Username/Password authentication
  - Client certificate authentication (PFX/PEM or certificate store)
  - API token authentication
  - Anonymous access for public endpoints

- **Full API Coverage**
  - Access all Safeguard services (Core, Appliance, A2A, Notification)
  - Support for v3 and v4 APIs (v4 is default)
  - Simple method invocation with `InvokeMethod()`

- **A2A (Application-to-Application) Support**
  - Certificate-based password retrieval for automated integrations
  - Access request brokering on behalf of users
  - No manual approval workflow required for configured A2A registrations

- **Real-Time Event Notifications**
  - Subscribe to Safeguard events via SignalR
  - Persistent event listeners with auto-reconnect capabilities
  - Role-based notifications for assets, accounts, access requests, and more

- **Production-Ready Features**
  - Automatic token refresh for long-running connections
  - Built-in logging via Serilog integration
  - Comprehensive error handling with `SafeguardDotNetException`

- **Modern Serialization (v9.0+)**
  - `System.Text.Json` with source-generated serializers
  - Trim- and Native-AOT-friendly: usable from `PublishAot=true` consumers
  - Reduced dependency footprint — no Newtonsoft.Json, no RestSharp,
    no Microsoft.AspNet.WebApi.Client

## Quick Start

### Installation

```powershell
dotnet add package OneIdentity.SafeguardDotNet
```

### Basic Usage

```csharp
using OneIdentity.SafeguardDotNet;
using System.Security;

// Connect with username/password
SecureString password = GetPasswordSecurely();
var connection = Safeguard.Connect("safeguard.company.com", "local", "Admin", password);

// Call the API
string userData = connection.InvokeMethod(Service.Core, Method.Get, "Me");
Console.WriteLine(userData);
```

### Certificate Authentication

```csharp
// Using certificate thumbprint from store
var connection = Safeguard.Connect("safeguard.company.com", "756766BB590D7FA9CA9E1971A4AE41BB9CEC82F1");

// Using PFX file
SecureString certPassword = GetPasswordSecurely();
var connection = Safeguard.Connect("safeguard.company.com", @"C:\certs\client.pfx", certPassword);
```

### A2A Password Retrieval

```csharp
// Get A2A context with certificate
var a2aContext = Safeguard.A2A.GetContext("safeguard.company.com", @"C:\certs\a2a.pfx", certPassword, apiKey);

// Retrieve password
var password = a2aContext.RetrievePassword();
```

### Event Notifications

```csharp
// Create persistent event listener (auto-reconnects)
var listener = connection.GetPersistentEventListener();

listener.RegisterEventHandler("AssetAccountPasswordUpdated", (eventName, eventBody) => {
    Console.WriteLine($"Password changed: {eventBody}");
});

listener.Start();
```

## API Versions

SafeguardDotNet defaults to the **v4 API**. To use v3:

```csharp
var connection = Safeguard.Connect("safeguard.company.com", "local", "Admin", password, apiVersion: 3);
```

Safeguard 7.X+ hosts both v3 and v4 APIs simultaneously.

## Target Framework

- **netstandard2.0** — runs on .NET Framework 4.6.1+, .NET Core 2.0+, .NET 5/6/8/10+
- Annotated for **trimming and Native AOT** so consumers publishing with
  `PublishTrimmed=true` or `PublishAot=true` get a clean build with no
  `IL2026` / `IL3050` warnings from the SDK

## Upgrading to 9.0

Version 9.0 replaces Newtonsoft.Json with `System.Text.Json` throughout the
SDK. Most callers are unaffected, but a few public surface changes are
source-breaking:

- `A2ARegistration.Id` is now `int` (was `string`) to match the API contract.
- `Safeguard.PostLoginResponseAsync` now returns `string` instead of
  `Newtonsoft.Json.Linq.JObject`. This is an rSTS plumbing helper used
  internally by the login modules — most consumers go through
  `Safeguard.Connect(...)` or `ExchangeRstsTokenForConnectionAsync` and are
  unaffected. Direct callers can parse the response with
  `JsonDocument.Parse(...)` or a typed deserialization of their choice.
- `Newtonsoft.Json` and `Microsoft.AspNet.WebApi.Client` are no longer
  transitive dependencies — if your project relied on them implicitly, add an
  explicit `PackageReference`.

Bug fixes shipped alongside the migration:

- `UtcDateTimeJsonConverter` now returns `DateTime` values in UTC.
- `CustomTimeSpanJsonConverter` correctly parses the appliance's `D:H:M`
  `TimeSpan` format.

## TLS Versions

Starting with version 9.1, SafeguardDotNet no longer hard-pins TLS 1.2. By default the
connection lets the operating system negotiate the best mutually supported protocol, which
means TLS 1.3 is used automatically when both the client OS and the appliance support it
(Safeguard for Privileged Passwords 9.0 and later). Connections continue to use HTTP/1.1.

If you need to constrain the negotiated protocol, every `Connect`, `A2A.GetContext`, and
login-module entry point accepts optional `minTlsVersion` / `maxTlsVersion` parameters. Leave
them `null` (the default) to negotiate, or pin a bound to enforce a policy:

```csharp
// Negotiate the best protocol (default; enables TLS 1.3 where available)
var connection = Safeguard.Connect("safeguard.company.com", "local", "Admin", password);

// Require TLS 1.3 or newer
var strict = Safeguard.Connect("safeguard.company.com", "local", "Admin", password,
    minTlsVersion: SafeguardTlsVersion.Tls13);

// Pin to exactly TLS 1.2 (e.g. to talk to an older appliance)
var legacy = Safeguard.Connect("safeguard.company.com", "local", "Admin", password,
    minTlsVersion: SafeguardTlsVersion.Tls12, maxTlsVersion: SafeguardTlsVersion.Tls12);
```

The same `minTlsVersion` / `maxTlsVersion` parameters flow through event listeners and the
A2A SignalR connections, so the enforced protocol is applied consistently. Supplying a
`minTlsVersion` that is newer than `maxTlsVersion` throws an `ArgumentException`.

Certificate and A2A authentication work over TLS 1.3 with no special configuration. Some
Safeguard SDKs require connecting through a dedicated SNI hostname to perform client-certificate
authentication over TLS 1.3, because their TLS stacks cannot do post-handshake authentication
(PHA); SafeguardDotNet does not need that workaround, because .NET performs PHA correctly.

## Documentation

- [GitHub Repository](https://github.com/OneIdentity/SafeguardDotNet)
- [Safeguard API Documentation](https://support.oneidentity.com/safeguard-for-privileged-passwords/)
- [Sample Projects](https://github.com/OneIdentity/SafeguardDotNet/tree/master/Samples)

## Support

This project is supported through:
- [One Identity GitHub Issues](https://github.com/OneIdentity/SafeguardDotNet/issues)
- [One Identity Community](https://www.oneidentity.com/community/)

## License

Licensed under [Apache 2.0](https://github.com/OneIdentity/SafeguardDotNet/blob/master/LICENSE)

Copyright (c) 2026 One Identity LLC. All rights reserved.
