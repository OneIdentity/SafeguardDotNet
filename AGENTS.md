# AGENTS.md — SafeguardDotNet

.NET SDK for the One Identity Safeguard Web API. Targets `netstandard2.0`.
Root namespace: `OneIdentity.SafeguardDotNet`.

## Project structure

- `SafeguardDotNet\` — core SDK: `Safeguard.cs`, connections, auth, events, A2A, SPS
- `SafeguardDotNet.PkceNoninteractiveLogin\`, `BrowserLogin\`, `GuiLogin\`, `LoginCommon\` — login flows
- `Test\` — CLI tools plus the PowerShell integration test framework
- `Samples\` — example integrations
- `build.yml`, `pipeline-templates\`, `Directory.Build.props` — build, versioning, analyzers

## Setup and build

| Solution | Purpose | Command |
|---|---|---|
| `SafeguardDotNet.Core.sln` | SDK, login modules, test tools, samples | `dotnet build SafeguardDotNet.Core.sln /p:SignFiles=false` |
| `SafeguardDotNet.Framework.sln` | GuiLogin + GuiTester (.NET Framework 4.8.1) | `msbuild SafeguardDotNet.Framework.sln /p:SignFiles=false` |
| `SafeguardDotNet\SafeguardDotNet.csproj` | SDK only | `dotnet build SafeguardDotNet\SafeguardDotNet.csproj /p:SignFiles=false` |

Always build with **0 errors and 0 warnings**. Keep `/p:SignFiles=false` for local work;
CI handles signing.

## Linting

Linting is part of the build through `Directory.Build.props`; there is no separate command.
Pay attention to the analyzer set from StyleCop and Sonar, especially:

- no `#region`
- one parameter per line when wrapping
- `s_` for private static fields and `_` for private instance fields
- no empty `catch` blocks and no single-line statement blocks

## Testing

Tests are live-appliance based. Use the CLI tools in `Test\` or
`Test\TestFramework\Invoke-SafeguardTests.ps1`, and read
`.agents/skills/testing-guide/SKILL.md` before running suites or changing coverage.

## Code conventions

- Use `SecureString` for passwords, tokens, and secrets; convert with `ExtensionMethods`
- Dispose objects that hold `SecureString`, certificates, listeners, or connections
- Public instance methods on disposable connection types must guard `_disposed`
- Throw `SafeguardDotNetException` for SDK/API failures and preserve status/response details
- Keep TLS 1.2 behavior and SSL validation handling consistent across `HttpClient` and SignalR
- `GenerateDocumentationFile` is enabled; public APIs need XML docs, but no XML file headers

## CI/CD

See `.agents/skills/build-and-release/SKILL.md` for pipeline stages, signing,
packaging, publishing, releases, and required service connections.

## Security

- Never commit credentials, tokens, or certificate material
- Never log or serialize secret `SecureString` values
- Test credentials belong in runner parameters, not source files
- `ignoreSsl` / `-x` is for dev/test only

## Versioning

- `Safeguard.DefaultApiVersion` is `4`; use `apiVersion: 3` only for legacy support
- Keep the `9999.9999.9999` and `9999.9999.9999.9999` placeholders in project metadata
- `pipeline-templates\versionnumber.ps1` stamps tag builds (`v<major>.<minor>.<patch>`) and prerelease builds from `semanticVersion`

## On-demand skills

| Skill | When to read | File |
|---|---|---|
| Architecture | SDK internals, auth, PKCE/rSTS, events, management, SPS | `.agents/skills/architecture/SKILL.md` |
| API Patterns | Standard REST calls, service selection, CRUD, headers, Swagger | `.agents/skills/api-patterns/SKILL.md` |
| A2A Workflow | Certificate-based A2A setup, retrieval, brokering, listeners | `.agents/skills/a2a-workflow/SKILL.md` |
| Build and Release | Azure Pipelines flow, version stamping, signing, publishing | `.agents/skills/build-and-release/SKILL.md` |
| Testing Guide | Live appliance setup, suites, failures, test authoring | `.agents/skills/testing-guide/SKILL.md` |

## Keeping this file current

Keep this file short, and move deep workflow/reference material into skills. Update the
routing table whenever skills are added, removed, or renamed.
