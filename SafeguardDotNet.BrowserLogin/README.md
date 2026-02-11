# SafeguardDotNet.BrowserLogin

Browser-based authentication for One Identity Safeguard Web API .NET SDK

## Overview

SafeguardDotNet.BrowserLogin provides browser-based OAuth authentication for the Safeguard API. This package enables your .NET applications to authenticate users through their default system browser, supporting modern authentication flows including federated identity providers.

## When to Use This Package

Use SafeguardDotNet.BrowserLogin when you need:
- Interactive user authentication via web browser
- Support for federated authentication providers (SAML, OAuth, etc.)
- Modern authentication flows with PKCE (Proof Key for Code Exchange)

## Key Features

- **Browser-Based Authentication** - Uses the system's default browser for OAuth login
- **Cross-Platform Support** - Works on Windows, Linux, and macOS with .NET Core/.NET 5+
- **Federated Identity** - Supports all Safeguard authentication providers including SAML, OAuth, and LDAP
- **Secure Token Handling** - Implements OAuth best practices with PKCE
- **Seamless Integration** - Works with the main SafeguardDotNet SDK

## Prerequisites

- **SafeguardDotNet** package (included as dependency)
- .NET Standard 2.0+ compatible runtime

## Installation

```powershell
dotnet add package OneIdentity.SafeguardDotNet.BrowserLogin
```

This package automatically includes the main `OneIdentity.SafeguardDotNet` package as a dependency.

## Quick Start

```csharp
using OneIdentity.SafeguardDotNet;
using OneIdentity.SafeguardDotNet.BrowserLogin;

// Authenticate user via browser
var connection = Safeguard.ConnectBrowser("safeguard.company.com");

// Use the authenticated connection
string userData = connection.InvokeMethod(Service.Core, Method.Get, "Me");
Console.WriteLine($"Logged in as: {userData}");
```

### With Specific Authentication Provider

```csharp
var connection = DefaultBrowserLogin.Connect("myspp.petrsnd.test", ignoreSsl: false);
```

### Advanced Options

```csharp
// Configure an alternate listing port (default: 8400 [same as Microsoft])
var connection = DefaultBrowserLogin.Connect("safeguard.company.com", port: 8080);
```

## How It Works

1. **Initiate Login** - Application calls `DefaultBrowserLogin.Connect()`
2. **Browser Opens** - Default browser navigates to Safeguard login page
3. **User Authenticates** - User logs in through their chosen provider
4. **Callback Received** - OAuth callback redirects to localhost listener
5. **Connection Established** - Application receives authenticated connection

The entire process is handled automatically by the library.

## Target Framework

- **netstandard2.0** - Compatible with .NET Framework 4.6.1+, .NET Core 2.0+, .NET 5+, and .NET 6+

## Related Packages

- **OneIdentity.SafeguardDotNet** - Main SDK (automatically included)
- **OneIdentity.SafeguardDotNet.GuiLogin** - WebView2-based login for .NET Framework applications
- **OneIdentity.SafeguardDotNet.PkceNoninteractiveLogin** - Noninteractive PKCE login to simulate browser agent

## Documentation

- [GitHub Repository](https://github.com/OneIdentity/SafeguardDotNet)
- [Sample Projects](https://github.com/OneIdentity/SafeguardDotNet/tree/master/Samples)
- [Safeguard Documentation](https://support.oneidentity.com/safeguard-for-privileged-passwords/)

## Support

This project is supported through:
- [One Identity GitHub Issues](https://github.com/OneIdentity/SafeguardDotNet/issues)
- [One Identity Community](https://www.oneidentity.com/community/)

## License

Licensed under [Apache 2.0](https://github.com/OneIdentity/SafeguardDotNet/blob/master/LICENSE)

Copyright (c) 2026 One Identity LLC. All rights reserved.
