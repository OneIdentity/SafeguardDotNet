Write-Host "prebuild: Executing prebuild script"

Push-Location $PSScriptRoot

if (Test-Path .\artifacts)
{
    Write-Host "prebuild: Cleaning .\artifacts"
    Remove-Item .\artifacts -Force -Recurse
}

Write-Host "prebuild: Setting version numbers"
# SafeguardDotNet
$ProjectFile = (Join-Path $PSScriptRoot "SafeguardDotNet\SafeguardDotNet.csproj")
# SafeguardDotNet.GuiLogin
$GuiProjectFile = (Join-Path $PSScriptRoot "SafeguardDotNet.GuiLogin\SafeguardDotNet.GuiLogin.csproj")
$GuiNuspec = (Join-Path $PSScriptRoot "SafeguardDotNet.GuiLogin\SafeguardDotNet.GuiLogin.nuspec")

$PackageCodeMarker = "9999.9999.9999"
$AssemblyCodeMarker = "9999.9999.9999.9999"
$PackageVersion = "$($env:APPVEYOR_BUILD_VERSION)"
if (($PackageVersion.Split("-"))[1] -eq "release")
{
    # Set package version to three digit release number for actual releases
    $PackageVersion = "$(($PackageVersion.Split("-"))[0])"
}
$AssemblyVersion = "$(($PackageVersion.Split("-"))[0]).0"

# SafeguardDotNet
(Get-Content $ProjectFile -Raw).replace($AssemblyCodeMarker, $AssemblyVersion) | Set-Content -Encoding UTF8 $ProjectFile
(Get-Content $ProjectFile -Raw).replace($PackageCodeMarker, $PackageVersion) | Set-Content -Encoding UTF8 $ProjectFile
# SafeguardDotNet.GuiLogin
(Get-Content $GuiProjectFile -Raw).replace($AssemblyCodeMarker, $AssemblyVersion) | Set-Content -Encoding UTF8 $GuiProjectFile
(Get-Content $GuiNuspec -Raw).replace($PackageCodeMarker, $PackageVersion) | Set-Content -Encoding UTF8 $GuiNuspec

Write-Host "prebuild: Restoring packages"
& dotnet restore --no-cache

Pop-Location