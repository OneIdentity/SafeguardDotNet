# Contributing to SafeguardDotNet

Thanks for your interest in improving SafeguardDotNet, the C# .NET SDK for
the One Identity Safeguard Web API.

## Reporting issues

- **Bugs and feature requests:** open a GitHub Issue.
- **Security vulnerabilities:** do **not** open a public issue — follow
  [SECURITY.md](SECURITY.md).

## Prerequisites

- The [.NET SDK](https://dotnet.microsoft.com/download) (supporting
  `netstandard2.0` for the library and `net10.0` for the test tooling).
- Visual Studio 2022 or later / MSBuild for the .NET Framework 4.8.1
  GuiLogin solution (Windows only).
- A live Safeguard for Privileged Passwords appliance to run the
  integration test suites.

## Building

Build locally with signing disabled (CI handles signing). The build must
produce **zero errors and zero warnings**:

    dotnet build SafeguardDotNet.Core.sln /p:SignFiles=false

The GuiLogin/GuiTester solution targets .NET Framework 4.8.1 (Windows):

    msbuild SafeguardDotNet.Framework.sln /p:SignFiles=false

## Testing

The functional test suites run against a live appliance via the PowerShell
test framework:

    ./Test/TestFramework/Invoke-SafeguardTests.ps1

## Coding conventions

Linting runs as part of the build: `Directory.Build.props` enables
StyleCop.Analyzers and SonarAnalyzer.CSharp with `TreatWarningsAsErrors`,
and all public APIs require XML doc comments. A clean `dotnet build` is the
lint gate.

See [AGENTS.md](AGENTS.md) for the full architecture and conventions.

## Submitting changes

1. Fork the repository and create a feature branch.
2. Keep commits focused with clear messages.
3. Ensure `dotnet build SafeguardDotNet.Core.sln /p:SignFiles=false`
   completes with no errors or warnings.
4. Open a pull request describing the behavior you changed and the tests
   that prove it.