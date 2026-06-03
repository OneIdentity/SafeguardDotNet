# SafeguardDotNet.PkceNoninteractiveLogin

PKCE-based non-interactive authentication for the Safeguard Web API without launching a browser.

## Overview

This library provides OAuth2/PKCE authentication to Safeguard by allowing applications to manually handle the authentication flow without launching a browser. This is useful for:

- Automated testing scenarios
- Custom authentication workflows
- Integration with non-browser-based UI frameworks
- Scenarios where browser automation is required

## Key Features

- **Manual PKCE Flow Control**: Generate code verifier/challenge and build authorization URLs
- **No Browser Launch**: Unlike BrowserLogin, this doesn't automatically open a browser
- **Flexible Integration**: Programmatically obtain authorization codes through custom mechanisms
- **Standard OAuth2/PKCE**: Follows OAuth2 Authorization Code Flow with PKCE (RFC 7636)

## Usage Example

The library drives the OAuth2/PKCE authorization-code flow internally by
posting directly to the rSTS login endpoints — no browser, no TCP listener,
and no caller-supplied authorization code are required. The caller supplies
the appliance address and credentials; everything else (code verifier/
challenge generation, authorization, code redemption, token exchange) is
handled by `Connect` / `ConnectAsync`.

```csharp
using System.Security;
using OneIdentity.SafeguardDotNet;
using OneIdentity.SafeguardDotNet.PkceNoninteractiveLogin;

SecureString password = GetPasswordSecurely();

using var connection = PkceNoninteractiveLogin.Connect(
    appliance: "safeguard.example.com",
    provider:  "local",
    username:  "Admin",
    password:  password,
    ignoreSsl: false);

var me = connection.InvokeMethod(Service.Core, Method.Get, "Me");
```

### Multi-factor authentication

If the identity provider requires a second factor (TOTP, RADIUS, etc.), pass
the one-time code as `secondaryPassword`:

```csharp
SecureString password = GetPasswordSecurely();
SecureString totp = GetOneTimeCodeSecurely();

using var connection = PkceNoninteractiveLogin.Connect(
    "safeguard.example.com", "local", "Admin", password, totp);
```

### Async with cancellation

```csharp
using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(60));
SecureString password = GetPasswordSecurely();

using var connection = await PkceNoninteractiveLogin.ConnectAsync(
    "safeguard.example.com", "local", "Admin", password,
    secondaryPassword: null,
    apiVersion: Safeguard.DefaultApiVersion,
    ignoreSsl: false,
    cancellationToken: cts.Token);
```

## Comparison with BrowserLogin

| Feature | BrowserLogin | PkceNoninteractiveLogin |
|---------|-------------|-------------------------|
| Browser Launch | Automatic | None — flow is driven over HTTP |
| TCP Listener | Built-in | Not needed |
| Credentials | Entered in browser by user | Supplied by caller (username/password, optional MFA code) |
| Use Case | Interactive desktop apps | Automated testing, CI/CD, headless integrations |

## Dependencies

- SafeguardDotNet (core SDK)
- SafeguardDotNet.LoginCommon (shared OAuth utilities)
- Serilog (logging)

## Testing

See `Test/SafeguardDotNetPkceNoninteractiveLoginTester` for a reference implementation that demonstrates both interactive and non-interactive testing modes.

## License

Apache 2.0. See [LICENSE](../LICENSE) file for details.
