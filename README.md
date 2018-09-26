[![Build status](https://ci.appveyor.com/api/projects/status/wgd68b7qrwhc7oc3?svg=true)](https://ci.appveyor.com/project/petrsnd/safeguarddotnet)

# SafeguardDotNet

One Identity Safeguard Web API C# SDK

## Introduction

All functionality in Safeguard is available via the Safeguard API. There is
nothing that can be done in the Safeguard UI that cannot also be performed
using the Safeguard API programmatically.

SafeguardDotNet is provided to facilitate calling the Safeguard API from .NET.
It is meant to remove the complexity of dealing with authentication via
Safeguard's embedded secure token service (STS). It also facilitates
authentication using client certificates, which is the recommended
authentication mechanism for automated processes. The basic usage is to call
`Connect()` to establish a connection to Safeguard, then you can call
`InvokeMethod()` multiple times using the same authenticated connection.

SafeguardDotNet also provides an easy way to call Safeguard A2A from .NET. The
A2A service requires client certificate authentication for retrieving passwords
for application integration. When Safeguard A2A is properly configured,
specified passwords can be retrieved with a single method call without
requiring access request workflow approvals. Safeguard A2A is protected by
API keys and IP restrictions in addition to client certificate authentication.

SafeguardDotNet includes an SDK for listening to Safeguard's powerful, real-time
event notification system. Safeguard provides role-based event notifications
via SignalR to subscribed clients. If a Safeguard user is an Asset Administrator
events related to the creation, modification, or deletion of Assets and Asset
Accounts will be sent to that user. When used with a certificate user, this
provides an opportunity for reacting programmatically to any data modification
in Safeguard. Events are also supported for access request workflow and for
A2A password changes.

SafeguardDotNet uses RestSharp and Json.NET to call the Safeguard API. It
includes calls to Serilog, and if your calling application provides a sink you
will get log information automatically.

## Getting Started

A simple code example for calling the Safeguard API:

```C#
SecureString password = GetPasswordSomehow(); // default password is "Admin123"
var connection = Safeguard.Connect("10.5.32.162", "local", "Admin", password);
Console.WriteLine(connection.InvokeMethod(Service.Core, Method.Get, "Me"));
```

Certificates may be used in two different ways, either via a PFX (PKCS12) file
or using a SHA-1 thumbprint identifying a certificate in the User or Computer
personal store.

```C#
SecureString certificatePassword = GetPasswordSomehow();
var connection = Safeguard.Connect("10.5.32.162", "C:\cert.pfx", certificatePassword);
Console.WriteLine(connection.InvokeMethod(Service.Core, Method.Get, "Me"));
```

```C#
SecureString certificatePassword = GetPasswordSomehow();
var connection = Safeguard.Connect("10.5.32.162", "756766BB590D7FA9CA9E1971A4AE41BB9CEC82F1");
Console.WriteLine(connection.InvokeMethod(Service.Core, Method.Get, "Me"));
```

A final method that is available is using an existing Safeguard API token.

```C#
SecureString apiToken = GetTokenSomehow();
var connection = Safeguard.Connect("10.5.32.162", apiToken);
Console.WriteLine(connection.InvokeMethod(Service.Core, Method.Get, "Me"));
```

Calling the simple 'Me' endpoint provides information about the currently logged
on user.

## About the Safeguard API

The Safeguard API is a REST-based Web API. Safeguard API endpoints are called
using HTTP operators and JSON (or XML) requests and responses. The Safeguard API
is documented using Swagger. You may use Swagger UI to call the API directly or
to read the documentation about URLs, parameters, and payloads.

To access the Swagger UI use a browser to navigate to:
`https://<address>/service/<service>/swagger`

- `<address>` = Safeguard network address
- `<service>` = Safeguard service to use

The Safeguard API is made up of multiple services: core, appliance, notification,
and a2a.

|Service|Description|
|-|-|
|core|Most product functionality is found here. All cluster-wide operations: access request workflow, asset management, policy management, etc.|
|appliance|Appliance specific operations, such as setting IP address, maintenance, backups, support bundles, appliance management|
|notification|Anonymous, unauthenticated operations. This service is available even when the appliance isn't fully online|
|a2a|Application integration specific operations. Fetching passwords, making access requests on behalf of users, etc.|

Each of these services provides a separate Swagger endpoint.

You may use the `Authorize` button at the top of the screen to get an API token
to call the Safeguard API directly using Swagger.
