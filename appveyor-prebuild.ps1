Write-Host "prebuild: Executing prebuild script"

Push-Location $PSScriptRoot

if (Test-Path .\artifacts)
{
    Write-Host "prebuild: Cleaning .\artifacts"
    Remove-Item .\artifacts -Force -Recurse
}

Write-Host "prebuild: Setting version numbers"
$ProjectFile = (Join-Path $PSScriptRoot "SafeguardDotNet\SafeguardDotNet.csproj")
$PackageCodeMarker = "9999.9999.9999"
$AssemblyCodeMarker = "9999.9999.9999.9999"
$PackageVersion = "$($env:APPVEYOR_BUILD_VERSION)"
$AssemblyVersion = "$(($PackageVersion.Split("-"))[0]).0"

(Get-Content $ProjectFile -Raw).replace($AssemblyCodeMarker, $AssemblyVersion) | Set-Content -Encoding UTF8 $ProjectFile
(Get-Content $ProjectFile -Raw).replace($PackageCodeMarker, $PackageVersion) | Set-Content -Encoding UTF8 $ProjectFile

Write-Host "prebuild: Restoring packages"
& dotnet restore --no-cache

Pop-Location