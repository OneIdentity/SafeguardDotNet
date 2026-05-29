# SafeguardDotNet.DeviceCodeLogin

OAuth 2.0 Device Authorization Grant (RFC 8628) authentication for the Safeguard Web API.

## Overview

This library enables authentication to Safeguard from environments that lack a local browser:

- Docker containers
- Remote SSH sessions
- Headless VMs and CI runners
- IoT/embedded devices

The flow displays a URL and user code. The user authenticates from any browser on any device, and the token is delivered back to the requesting application automatically.

## Key Features

- **No Browser Required**: Authenticate from any headless environment
- **No Credentials in Code**: Unlike PkceNoninteractiveLogin, no username/password needed
- **SSO/MFA Compatible**: User authenticates normally in their browser, supporting any identity provider
- **Async Support**: Both `Connect()` and `ConnectAsync()` with `CancellationToken`
- **Standard RFC 8628**: Implements the OAuth 2.0 Device Authorization Grant

## Prerequisites

- Safeguard appliance firmware ≥ 8.2
- Device Code grant type must be enabled on the appliance:
  - **UI**: Settings → OAuth 2.0 Grant Types → check "Device Code"
  - **API**: `PUT /service/core/v4/Settings/Allowed%20OAuth2%20Grant%20Types` with body `{"Value":"ResourceOwner, DeviceCode"}`

## Usage Example

```csharp
using OneIdentity.SafeguardDotNet;
using OneIdentity.SafeguardDotNet.DeviceCodeLogin;

// Synchronous
using var connection = DeviceCodeLogin.Connect(
    "safeguard.example.com",
    new DeviceCodeLoginParameters
    {
        DisplayCallback = info =>
        {
            Console.WriteLine($"To sign in, visit: {info.VerificationUriComplete}");
            Console.WriteLine($"Or go to {info.VerificationUri} and enter code: {info.UserCode}");
        }
    });

var me = connection.InvokeMethod(Service.Core, Method.Get, "Me");
```

### Async with cancellation

```csharp
using var cts = new CancellationTokenSource(TimeSpan.FromMinutes(3));

using var connection = await DeviceCodeLogin.ConnectAsync(
    "safeguard.example.com",
    new DeviceCodeLoginParameters
    {
        DisplayCallback = info =>
        {
            Console.WriteLine($"Visit: {info.VerificationUriComplete}");
            Console.WriteLine($"Code: {info.UserCode}");
        }
    },
    cancellationToken: cts.Token);
```

## Comparison with Other Login Packages

| Feature | BrowserLogin | PkceNoninteractiveLogin | DeviceCodeLogin |
|---------|-------------|-------------------------|-----------------|
| Browser Required | Yes (local) | No | No |
| Credentials in Code | No | Yes (username/password) | No |
| SSO/MFA Support | Yes | Limited | Yes |
| Headless Compatible | No | Yes | Yes |
| Async API | No | No | Yes |
| Use Case | Desktop apps | Automation with known creds | Headless with user auth |

## Configuration

| Parameter | Default | Description |
|-----------|---------|-------------|
| `DisplayCallback` | *(required)* | Callback to display the verification URL and code to the user |
| `ClientId` | `"SafeguardDotNet"` | OAuth2 client ID (change only if appliance has RelyingPartyApplications configured) |
| `Scope` | `"rsts:sts:primaryproviderid:local"` | Identity provider scope |
| `PollingIntervalSeconds` | `5` | Seconds between token polling requests (auto-increases on `slow_down`) |

## Dependencies

- SafeguardDotNet (core SDK)
- Serilog (logging)
- Newtonsoft.Json

## Testing

See `Test/SafeguardDotNetDeviceCodeLoginTester` for a CLI tool that demonstrates the full flow.

## License

Apache 2.0. See [LICENSE](../LICENSE) file for details.
