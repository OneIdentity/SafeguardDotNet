# AGENTS.md — SafeguardDotNet

.NET SDK for the One Identity Safeguard Web API. Published as NuGet packages on
[NuGet.org](https://www.nuget.org/packages/OneIdentity.SafeguardDotNet).

Targets `netstandard2.0`. Root namespace: `OneIdentity.SafeguardDotNet`. Dependencies:
Newtonsoft.Json, Serilog, Microsoft.AspNetCore.SignalR.Client.

## Project structure

```
SafeguardDotNet/
|-- SafeguardDotNet/                           # Core SDK library (netstandard2.0)
|   |-- Safeguard.cs                           # Entry point: Connect(), A2A, Event
|   |-- ISafeguardConnection.cs                # Primary connection interface
|   |-- SafeguardConnection.cs                 # Base connection implementation
|   |-- PersistentSafeguardConnection.cs       # Auto-refreshing token decorator
|   |-- SafeguardDotNetException.cs            # All SDK errors thrown as this type
|   |-- ExtensionMethods.cs                    # SecureString <-> string conversions
|   |-- Authentication/                        # IAuthenticationMechanism strategy pattern
|   |-- Event/                                 # SignalR event listeners
|   |-- A2A/                                   # Application-to-Application (certificate-only)
|   `-- Sps/                                   # Safeguard for Privileged Sessions
|-- SafeguardDotNet.PkceNoninteractiveLogin/   # PKCE login without a browser (MFA support)
|-- SafeguardDotNet.BrowserLogin/              # PKCE login via system browser
|-- SafeguardDotNet.GuiLogin/                  # WinForms embedded browser (.NET Framework)
|-- SafeguardDotNet.LoginCommon/               # Shared login utilities
|-- Test/                                      # CLI test tools + PowerShell test framework
|-- Samples/                                   # Example projects
|-- Directory.Build.props                      # Shared MSBuild props (analyzers, code style)
|-- build.yml                                  # Azure Pipelines CI/CD definition
`-- data/                                      # Data files (certificates, etc.)
```

## Setup and build

| Solution | Purpose | Build tool |
|---|---|---|
| `SafeguardDotNet.Core.sln` | SDK + login modules + test tools + samples | `dotnet build` |
| `SafeguardDotNet.Framework.sln` | GuiLogin + GuiTester (.NET Framework 4.8.1) | `msbuild` |
| `SafeguardDotNet.sln` | NuGet restore only — not for building |

```powershell
# Day-to-day local build (most common)
dotnet build SafeguardDotNet.Core.sln /p:SignFiles=false

# Build just the SDK
dotnet build SafeguardDotNet\SafeguardDotNet.csproj /p:SignFiles=false
```

**Always pass `/p:SignFiles=false` for local builds.** CI uses Azure Key Vault for signing.

The build must complete with **0 errors, 0 warnings**. Strict analysis is enforced via
`Directory.Build.props` (StyleCop.Analyzers, SonarAnalyzer.CSharp, `EnforceCodeStyleInBuild`).

## Linting

Linting is integrated into the build via Roslyn analyzers — no separate lint command.

Key rules enforced:

| Rule | What it means |
|------|---------------|
| SA1124 | No `#region` directives |
| SA1117 | Split parameters must each be on their own line |
| SA1306/IDE1006 | Private static fields: `s_` prefix, camelCase |
| SA1501 | No single-line statement blocks (always use braces) |
| S2737 | No empty catch clauses |
| IDE0063 | Prefer simplified `using` declarations |
| IDE0078 | Prefer pattern matching |
| IDE0054 | Prefer compound assignment |
| CA5350 | HMACSHA1 flagged — use `#pragma warning disable` if needed |

## Code conventions

### Naming

- Private static fields: `s_` prefix (e.g., `s_defaultTimeout`)
- Private instance fields: `_` prefix (e.g., `_disposed`)
- Public properties / constants: PascalCase

### SecureString for credentials

All passwords and tokens use `SecureString`. Convert via `ExtensionMethods.cs`:
`"secret".ToSecureString()` / `secure.ToInsecureString()`. Types holding `SecureString`
implement `IDisposable`.

### Dispose pattern

Connection classes track `_disposed`. All public instance methods must check and throw
`ObjectDisposedException` if disposed.

### Error handling

All SDK errors throw `SafeguardDotNetException` with `HttpStatusCode`, `ErrorCode`,
`ErrorMessage`, and `Response`. Include status code and response body when throwing.

### SSL/TLS

TLS 1.2 enforced on all `HttpClientHandler` instances. `ignoreSsl` bypasses cert validation
(dev only). `validationCallback` for custom validation. Apply consistently to `HttpClient`
and SignalR connections. **Never recommend `ignoreSsl` for production.**

### XML documentation

`GenerateDocumentationFile` is enabled. All public types need XML doc comments. The StyleCop
`xmlHeader` rule is disabled — do not add XML file headers.

### Versioning

Version markers `9999.9999.9999` / `9999.9999.9999.9999` in `.csproj`/`.nuspec` are replaced
at CI build time by `versionnumber.ps1`. **Do not change these markers manually.**

### NuGet packages

Four packages published per release: `OneIdentity.SafeguardDotNet`,
`OneIdentity.SafeguardDotNet.BrowserLogin`, `OneIdentity.SafeguardDotNet.PkceNoninteractiveLogin`,
`OneIdentity.SafeguardDotNet.GuiLogin`. Each includes a `.snupkg` symbols package.

## CI/CD

Azure Pipelines (`build.yml` + `pipeline-templates/`). Two jobs: **PRValidation** (no
signing) and **BuildAndPublish** (signing + NuGet publish on master/release). Never assume
Key Vault secrets exist locally.

## Security

- Never commit secrets, tokens, or credentials
- `SecureString` data must not be logged or serialized
- Test credentials only in runner parameters, never hardcoded
- `ignoreSsl` / `-x` is dev-only — always warn about production use

## Keeping this file current

After completing tasks, suggest updates for new pitfalls, test suites, patterns, stale
information, or corrections. Skills (below) should be updated alongside this file.

## On-demand skills

The following skills contain deeper reference material loaded only when relevant.
Read the `SKILL.md` when your current task matches the trigger.

| Skill | When to read | File |
|-------|-------------|------|
| Testing Guide | Running tests, writing tests, test failures, live appliance setup | `.agents/skills/testing-guide/SKILL.md` |
| Architecture Deep Dive | SDK internals, auth mechanisms, PKCE/rSTS, events, A2A, SPS, Swagger | `.agents/skills/architecture-deep-dive/SKILL.md` |
