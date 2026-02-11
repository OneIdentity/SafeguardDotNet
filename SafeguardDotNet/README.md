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

- **netstandard2.0** - Compatible with .NET Framework 4.6.1+, .NET Core 2.0+, .NET 5+, and .NET 6+

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
