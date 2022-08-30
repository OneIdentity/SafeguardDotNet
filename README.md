[![Build status](https://ci.appveyor.com/api/projects/status/wgd68b7qrwhc7oc3?svg=true)](https://ci.appveyor.com/project/petrsnd/safeguarddotnet)
[![nuget](https://img.shields.io/nuget/v/OneIdentity.SafeguardDotNet.svg)](https://www.nuget.org/packages/OneIdentity.SafeguardDotNet/)
[![GitHub](https://img.shields.io/github/license/OneIdentity/SafeguardDotNet.svg)](https://github.com/OneIdentity/SafeguardDotNet/blob/master/LICENSE)

# SafeguardDotNet

One Identity Safeguard Web API C# SDK

-----------

<p align="center">
<i>Check out our <a href="Samples">sample projects</a> to get started with your own custom integration to Safeguard!</i>
</p>

-----------

## Support

One Identity open source projects are supported through [One Identity GitHub issues](https://github.com/OneIdentity/SafeguardDotNet/issues) and the [One Identity Community](https://www.oneidentity.com/community/). This includes all scripts, plugins, SDKs, modules, code snippets or other solutions. For assistance with any One Identity GitHub project, please raise a new Issue on the [One Identity GitHub project](https://github.com/OneIdentity/SafeguardDotNet/issues) page. You may also visit the [One Identity Community](https://www.oneidentity.com/community/) to ask questions.  Requests for assistance made through official One Identity Support will be referred back to GitHub and the One Identity Community forums where those requests can benefit all users.

## Default API Update

SafeguardDotNet will use v4 API by default starting with version 7.0. It is
possible to continue using the v3 API by passing in the apiVersion parameter
when creating a connection or A2A context.

Safeguard for Privileged Passwords 7.X hosts both the v3 and v4 APIs. New coding
projects should target the v4 API, and existing projects can be migrated over time.
Notification will be given to customers many releases in advance of any plans to
remove the v3 API. There are currently no plans to remove the v3 API.

```C#
// Use v3 instead of v4
var connection = Safeguard.Connect("safeguard.sample.corp", "local", "Admin", password, 3);
var a2aContext = Safeguard.A2A.GetContext("safeguard.sample.corp", thumbprint, 3);
```

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
var connection = Safeguard.Connect("safeguard.sample.corp", "local", "Admin", password);
Console.WriteLine(connection.InvokeMethod(Service.Core, Method.Get, "Me"));
```

Certificates may be used in two different ways, either via a PFX (PKCS12) file
or using a SHA-1 thumbprint identifying a certificate in the User or Computer
personal store.

```C#
SecureString certificatePassword = GetPasswordSomehow();
var connection = Safeguard.Connect("safeguard.sample.corp", "C:\cert.pfx", certificatePassword);
Console.WriteLine(connection.InvokeMethod(Service.Core, Method.Get, "Me"));
```

```C#
var connection = Safeguard.Connect("safeguard.sample.corp", "756766BB590D7FA9CA9E1971A4AE41BB9CEC82F1");
Console.WriteLine(connection.InvokeMethod(Service.Core, Method.Get, "Me"));
```

A final authentication method that is available is using an existing Safeguard API token.

```C#
SecureString apiToken = GetTokenSomehow();
var connection = Safeguard.Connect("safeguard.sample.corp", apiToken);
Console.WriteLine(connection.InvokeMethod(Service.Core, Method.Get, "Me"));
```

Calling the simple 'Me' endpoint provides information about the currently logged
on user.

### Visual Studio 2017

A three minute video demonstrating how to get started calling the Safeguard API from a Visual Studio 2017 project.

[Visual Studio 2017 video](https://www.youtube.com/watch?v=kK90UyOeZac)

[![Visual Studio 2017 video](https://img.youtube.com/vi/kK90UyOeZac/0.jpg)](https://www.youtube.com/watch?v=kK90UyOeZac)

### Visual Studio Code

A four minute video demonstrating how to get started calling the Safeguard API from a Visual Studio Code project.

[Visual Studio Code video](https://www.youtube.com/watch?v=gV7iHUun9kA)

[![Visual Studio Code video](https://img.youtube.com/vi/gV7iHUun9kA/0.jpg)](https://www.youtube.com/watch?v=gV7iHUun9kA)

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

To call the a2a service you should begin by using `Safeguard.A2A.GetContext()` rather than
`Safeguard.Connect()`.

### Examples

Most functionality is in the core service as mentioned above.  The notification service
provides read-only information for status, etc.

#### Anonymous Call for Safeguard Status

```C#
var connection = Safeguard.Connect("safeguard.sample.corp");
Console.WriteLine(connection.InvokeMethod(Service.Notification, Method.Get, "Status"));
```

#### Create a New Linux Asset

```C#
// Assume connection is already made
var json = connection.InvokeMethod(Service.Core, Method.Post, "Assets",
    JsonConvert.SerializeObject(new {
        Name = "linux.blue.vas",
        NetworkAddress = "linux.blue.vas",
        Description = "A new linux asset",
        PlatformId = 188, // Ubuntu Other
        AssetPartitionId = -1
    }));
Console.WriteLine(json);
```

#### Create a New User and Set the Password

```C#
// Assume connection is already made
var userJson = connection.InvokeMethod(Service.Core, Method.Post, "Users",
    JsonConvert.SerializeObject(new {
        PrimaryAuthenticationProviderId = -1,
        UserName = "MyNewUser"
    }));
var userObj = JsonConvert.DeserializeAnonymousType(userJson, new { Id = 0 });
connection.InvokeMethod(Service.Core, Method.Put, $"Users/{userObj.Id}/Password",
    JsonConvert.SerializeObject("MyNewUser123");
```

## Using SafeguardDotNet from a New Visual Studio Code Project

First, create a directory with the name you want to give your project and change directory into it.

Run:
```PowerShell
PS> dotnet new console
```

This will create a `console` project.  You can see other project types by running `dotnet new`.

Run:
```PowerShell
PS> dotnet add package OneIdentity.SafeguardDotNet
```

This will add the latest OneIdentity.SafeguardDotNet NuGet package into your project.

Run:
```PowerShell
PS> dotnet restore
```

This will restore NuGet packages into your project so you can get code completion in the editor

Finally, run:
```PowerShell
PS> code .
```

This will open the Visual Studio Code editor so you can begin adding code to your project.

Add the using directive at the top of your file to call SafeguardDotNet:
```C#
using OneIdentity.SafeguardDotNet;
```
