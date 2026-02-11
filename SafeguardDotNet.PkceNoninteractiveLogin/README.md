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

```csharp
using OneIdentity.SafeguardDotNet.PkceNoninteractiveLogin;

// Step 1: Generate PKCE parameters
var codeVerifier = PkceNoninteractiveLogin.GenerateCodeVerifier();
var codeChallenge = PkceNoninteractiveLogin.GenerateCodeChallenge(codeVerifier);

// Step 2: Build authorization URL
var authUrl = PkceNoninteractiveLogin.BuildAuthorizationUrl(
    "safeguard.example.com",
    codeChallenge,
    username: "admin");

// Step 3: Your custom code to authenticate and obtain authorization code
// (e.g., using Selenium, Playwright, or other automation tools)
var authorizationCode = YourCustomAuthenticationMethod(authUrl);

// Step 4: Connect to Safeguard
var connection = PkceNoninteractiveLogin.Connect(
    "safeguard.example.com",
    authorizationCode,
    codeVerifier);

// Step 5: Use the connection
var userData = connection.InvokeMethod(Service.Core, Method.Get, "Me");
```

## Comparison with BrowserLogin

| Feature | BrowserLogin | PkceNoninteractiveLogin |
|---------|-------------|-------------------------|
| Browser Launch | Automatic | Manual (caller controlled) |
| TCP Listener | Built-in | Not included |
| Authorization Code | Captured automatically | Must be obtained by caller |
| Use Case | Interactive desktop apps | Automated testing, custom flows |

## Dependencies

- SafeguardDotNet (core SDK)
- SafeguardDotNet.LoginCommon (shared OAuth utilities)
- Serilog (logging)

## Testing

See `Test/SafeguardDotNetPkceNoninteractiveLoginTester` for a reference implementation that demonstrates both interactive and non-interactive testing modes.

## License

Apache 2.0. See [LICENSE](../LICENSE) file for details.
