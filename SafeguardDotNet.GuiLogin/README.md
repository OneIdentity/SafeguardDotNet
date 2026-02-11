# SafeguardDotNet.GuiLogin

WinForms GUI authentication for One Identity Safeguard Web API .NET SDK

## Overview

SafeguardDotNet.GuiLogin provides a Windows Forms-based OAuth authentication dialog for the Safeguard API. This package enables .NET Framework applications to authenticate users through an embedded browser control with a native Windows interface.

## When to Use This Package

Use SafeguardDotNet.GuiLogin when you need:
- Desktop Windows applications with GUI authentication
- .NET Framework 4.8.1+ applications
- Embedded browser experience within your application
- Native Windows Forms integration

**Note:** For cross-platform applications or .NET Core/.NET 5+, use [SafeguardDotNet.BrowserLogin](https://www.nuget.org/packages/OneIdentity.SafeguardDotNet.BrowserLogin/) instead.

## Key Features

- **Native Windows GUI** - WinForms dialog with embedded browser control
- **OAuth Authentication** - Supports all Safeguard authentication providers
- **In-Application Experience** - Login dialog stays within your application
- **Federated Identity** - Works with SAML, OAuth, LDAP, and other providers
- **Seamless Integration** - Compatible with main SafeguardDotNet SDK

## Prerequisites

- **.NET Framework 4.8.1** or higher
- Windows operating system
- SafeguardDotNet package (not included - must reference separately)

## Installation

```powershell
Install-Package OneIdentity.SafeguardDotNet.GuiLogin
```

**Important:** You must also reference the main SafeguardDotNet package:

```powershell
Install-Package OneIdentity.SafeguardDotNet
```

## Quick Start

```csharp
using OneIdentity.SafeguardDotNet;
using OneIdentity.SafeguardDotNet.GuiLogin;

// Authenticate user with GUI dialog
var connection = LoginWindow.Connect("safeguard.company.com", ignoreSsl: false);

// Use the authenticated connection
string userData = connection.InvokeMethod(Service.Core, Method.Get, "Me");
Console.WriteLine($"Logged in as: {userData}");
```

## How It Works

1. **Show Dialog** - Application calls `Safeguard.ConnectGui()` which displays WinForms dialog
2. **Embedded Browser** - Dialog contains WebView2 control showing Safeguard login page
3. **User Authenticates** - User logs in through their chosen identity provider
4. **Capture Token** - Dialog captures OAuth token from redirect
5. **Return Connection** - Application receives authenticated `ISafeguardConnection`

The dialog handles all OAuth flow details automatically.

## Target Framework

- **.NET Framework 4.8.1** (Windows only)

## Package Structure

This package uses `.nuspec` packaging to support .NET Framework 4.8.1 dependencies and framework assemblies:
- System.Windows.Forms
- System.Web
- Newtonsoft.Json
- Serilog

## Related Packages

- **OneIdentity.SafeguardDotNet** - Main SDK (must be referenced separately)
- **OneIdentity.SafeguardDotNet.BrowserLogin** - Cross-platform browser-based login for .NET Core/.NET 5+
- **OneIdentity.SafeguardDotNet.PkceNoninteractiveLogin** - Noninteractive PKCE login to simulate browser agent

## Comparison: GuiLogin vs BrowserLogin

| Feature | GuiLogin | BrowserLogin |
|---------|----------|--------------|
| Platform | Windows only | Cross-platform |
| Framework | .NET Framework 4.8.1 | .NET Standard 2.0 |
| UI | Embedded WinForms dialog | System default browser |
| Use Case | Desktop Windows apps | Console, Web, Cross-platform apps |

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
