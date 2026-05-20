---
name: build-and-release
description: Use when reproducing SafeguardDotNet CI/CD, version stamping, signing, packaging, or release publishing.
---

# Build and Release

Use this skill for Azure Pipelines changes, local CI reproduction, package version
questions, or release troubleshooting. SafeguardDotNet has a split build: legacy
.NET Framework projects are built with MSBuild first, then the modern SDK-style
projects are built and packed with the dotnet CLI.

## 1. Pipeline architecture (files, stages, triggers)

### Primary files

| File | Purpose |
|---|---|
| `build.yml` | Top-level pipeline definition, triggers, and job selection |
| `pipeline-templates\global-variables.yml` | Shared semantic version and tag/prerelease flags |
| `pipeline-templates\job-variables.yml` | Solution paths and build configuration |
| `pipeline-templates\build-steps.yml` | Shared restore/build/pack/artifact flow used by both jobs |
| `pipeline-templates\versionnumber.ps1` | Replaces placeholder versions and sets Azure Pipeline variables |
| `Directory.Build.props` | Analyzer/code-style requirements enforced during build |

### Triggers

`build.yml` runs on:

- pushes to `main`, `master`, and `release-*`
- tags matching `v*`
- pull requests targeting `main`, `master`, and `release-*`

It deliberately ignores documentation-only changes:

- `**/*.md`
- `LICENSE`
- `docs/`
- `.github/CODEOWNERS`

### Jobs

#### `PRValidation`

Runs only when `Build.Reason == PullRequest`.

- imports `job-variables.yml`
- sets `signFiles: false`
- uses `windows-latest`
- runs only `pipeline-templates\build-steps.yml`
- does **not** fetch signing or publishing secrets

#### `BuildAndPublish`

Runs for non-PR builds after merges and tags.

- imports `job-variables.yml`
- sets `signFiles: true`
- uses `windows-latest`
- pulls signing secrets from Azure Key Vault
- installs/configures SSL.com eSignerCKA
- resolves x86 `signtool.exe`
- runs the shared `build-steps.yml`
- pulls the NuGet.org API key
- pushes packages to NuGet.org
- creates a GitHub release with package assets

### Shared build flow from `build-steps.yml`

1. Run `versionnumber.ps1`
2. Dump environment variables for diagnostics
3. Ensure the .NET Framework 4.8.1 Developer Pack exists
4. Install NuGet tooling
5. Restore `SafeguardDotNet.Framework.sln` with NuGet.exe
6. Restore `SafeguardDotNet\SafeguardDotNet.csproj` with `dotnet restore`
7. Resolve the x86 Windows SDK `signtool.exe` path
8. Build `SafeguardDotNet.Framework.sln` with MSBuild
9. Install .NET SDK `10.0.x`
10. Build `SafeguardDotNet.Core.sln` with `dotnet build`
11. Verify Authenticode signatures when signing is enabled
12. Pack three SDK-style projects with `dotnet pack`
13. Pack `SafeguardDotNet.GuiLogin.nuspec` with NuGet
14. Publish the artifact staging directory as build artifacts

## 2. Version strategy (how version numbers are derived)

### Source of truth

`pipeline-templates\global-variables.yml` currently sets:

```yaml
semanticVersion: '8.2.3'
```

The pipeline also computes:

- `isTagBuild` -> true when `Build.SourceBranch` starts with `refs/tags/`
- `isPrerelease` -> false for tag builds, true otherwise

### Placeholder markers in source

The repo keeps placeholder values in source control and stamps real versions in CI:

| File(s) | Package marker | Assembly marker |
|---|---|---|
| `SafeguardDotNet\SafeguardDotNet.csproj` | `9999.9999.9999` | `9999.9999.9999.9999` |
| `SafeguardDotNet.BrowserLogin\SafeguardDotNet.BrowserLogin.csproj` | `9999.9999.9999` | `9999.9999.9999.9999` |
| `SafeguardDotNet.PkceNoninteractiveLogin\SafeguardDotNet.PkceNoninteractiveLogin.csproj` | `9999.9999.9999` | `9999.9999.9999.9999` |
| `SafeguardDotNet.GuiLogin\SafeguardDotNet.GuiLogin.nuspec` | `9999.9999.9999` | n/a |
| `SafeguardDotNet.GuiLogin\Properties\AssemblyInfo.cs` | n/a | `9999.9999.9999.9999` |

Do not hand-edit these markers for normal development.

### `versionnumber.ps1` rules

The script computes:

- `BuildNumber = BuildId % 65534`
- validates tag builds against `^v\d+\.\d+\.\d+$`

For tag builds:

- package version = tag without leading `v`
- assembly version = `<tagVersion>.<BuildNumber>`
- release tag = original Git tag (for example `v8.2.3`)

For non-tag builds:

- package version = `<semanticVersion>-pre<BuildNumber>`
- assembly version = `<semanticVersion>.<BuildNumber>`
- release tag = `dev/v<packageVersion>`

The script also exports Azure variables:

- `AssemblyVersion`
- `PackageVersion`
- `ReleaseTag`

## 3. Build commands (local reproduction)

### Day-to-day developer build

For normal SDK work, this is the common local command:

```powershell
dotnet build SafeguardDotNet.Core.sln /p:SignFiles=false
```

### Closer reproduction of pipeline behavior

Use these commands when you need something nearer to CI, while still skipping
cloud signing dependencies:

```powershell
nuget restore SafeguardDotNet.Framework.sln

dotnet restore SafeguardDotNet\SafeguardDotNet.csproj

msbuild SafeguardDotNet.Framework.sln /p:Configuration=Release /p:SignFiles=false

dotnet build SafeguardDotNet.Core.sln --configuration Release /p:SignFiles=false

dotnet pack SafeguardDotNet\SafeguardDotNet.csproj --configuration Release --include-symbols -p:SymbolPackageFormat=snupkg --output .\artifacts --no-build

dotnet pack SafeguardDotNet.BrowserLogin\SafeguardDotNet.BrowserLogin.csproj --configuration Release --include-symbols -p:SymbolPackageFormat=snupkg --output .\artifacts --no-build

dotnet pack SafeguardDotNet.PkceNoninteractiveLogin\SafeguardDotNet.PkceNoninteractiveLogin.csproj --configuration Release --include-symbols -p:SymbolPackageFormat=snupkg --output .\artifacts --no-build

nuget pack SafeguardDotNet.GuiLogin\SafeguardDotNet.GuiLogin.nuspec -Properties Configuration=Release -Symbols -SymbolPackageFormat snupkg -OutputDirectory .\artifacts
```

Important local constraints:

- Always pass `/p:SignFiles=false` locally unless you have the exact signing setup.
- The pipeline installs the .NET Framework 4.8.1 Developer Pack explicitly; local
  Windows machines must have it to build `SafeguardDotNet.Framework.sln`.
- `Directory.Build.props` enforces StyleCop and Sonar analyzers, so warning-free
  builds are expected.

### What not to reproduce locally unless necessary

Avoid trying to mimic these pipeline-only steps on a normal workstation unless you
already own the required access:

- Azure Key Vault secret retrieval
- SSL.com eSignerCKA certificate loading
- x86 signtool-based Authenticode signing with CI credentials
- NuGet.org push
- GitHub release publication

## 4. Publishing targets (registry, signing)

### Authenticode signing

Signing is assembly-level, not package-level.

- The release job downloads and installs SSL.com eSignerCKA.
- It configures the signing account using Azure Key Vault secrets.
- It loads the certificate into `Cert:\CurrentUser\My`.
- It resolves an **x86** `signtool.exe` because the eSignerCKA PKCS#11 DLL is 32-bit only.
- Each SDK-style project has a `SignAssemblies` target that signs `$(TargetDir)*.dll`
  when `SignFiles=true`.
- `build-steps.yml` verifies every built `OneIdentity.SafeguardDotNet*.dll` signature.

There is an explicit pipeline note that NuGet package signing is **not** performed:

- eSignerCKA exposes only a 32-bit PKCS#11 DLL on Windows
- available NuGet signing tools are 64-bit
- the DLLs inside the packages are already Authenticode-signed instead

### Produced packages

Release builds publish four packages plus symbol packages:

| Artifact | Packaging command |
|---|---|
| `OneIdentity.SafeguardDotNet` | `dotnet pack SafeguardDotNet\SafeguardDotNet.csproj` |
| `OneIdentity.SafeguardDotNet.BrowserLogin` | `dotnet pack SafeguardDotNet.BrowserLogin\SafeguardDotNet.BrowserLogin.csproj` |
| `OneIdentity.SafeguardDotNet.PkceNoninteractiveLogin` | `dotnet pack SafeguardDotNet.PkceNoninteractiveLogin\SafeguardDotNet.PkceNoninteractiveLogin.csproj` |
| `OneIdentity.SafeguardDotNet.GuiLogin` | `nuget pack SafeguardDotNet.GuiLogin\SafeguardDotNet.GuiLogin.nuspec` |
| symbol packages | `--include-symbols -p:SymbolPackageFormat=snupkg` or `-Symbols -SymbolPackageFormat snupkg` |

### Publication targets

After packing:

- `PublishBuildArtifacts@1` uploads the artifact staging directory as `SafeguardDotNet`
- `NuGetCommand@2` pushes `*.nupkg` to `https://api.nuget.org/v3/index.json`
- `GitHubRelease@1` creates a release in `OneIdentity/SafeguardDotNet`
- GitHub release assets include both `*.nupkg` and `*.snupkg`

## 5. Service connections / secrets required

The release path depends on external connections and secrets that are unavailable in
normal local development.

### Azure service connections and Key Vaults

| Connection / subscription | Used for | Secrets / resource |
|---|---|---|
| `OneIdentity.Infrastructure.SPPCodeSigning` | Access the signing vault | `SPPCodeSigning` Key Vault |
| `SafeguardOpenSource` | Access release publishing secrets | `SafeguardBuildSecrets` Key Vault |

### Secrets referenced in YAML

| Secret | Purpose |
|---|---|
| `SPPCodeSigning-Password` | SSL.com eSignerCKA account password |
| `SPPCodeSigning-TotpPrivateKey` | SSL.com eSignerCKA TOTP seed/private key |
| `NugetOrgApiKey` | NuGet.org push credential |

### Other external dependencies

- GitHub service connection: `PangaeaBuild-GitHub`
- SSL.com signing account user: `ssl.oid.safeguardpp@groups.quest.com`
- Microsoft-hosted `windows-latest` image with NuGet, MSBuild, and dotnet tooling

### Release caveats

- PR validation intentionally avoids secrets; forked PRs cannot access them.
- Never assume Key Vault access or signing credentials exist on a developer machine.
- If a build issue only reproduces with `signFiles=true`, investigate the release job,
  not the default local build path.
