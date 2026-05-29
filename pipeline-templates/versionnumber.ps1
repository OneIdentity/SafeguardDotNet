[CmdletBinding()]
Param(
    [Parameter(Mandatory=$true, Position=0)]
    [string]$SourceDir,
    [Parameter(Mandatory=$true, Position=1)]
    [string]$SemanticVersion,
    [Parameter(Mandatory=$true, Position=2)]
    [string]$BuildId,
    [Parameter(Mandatory=$true, Position=3)]
    [bool]$IsPrerelease,
    [Parameter(Mandatory=$false, Position=4)]
    [string]$TagName = "",
    [Parameter(Mandatory=$false, Position=5)]
    [string]$IsTagBuild = "False"
)

$local:IsTagBuildBool = $IsTagBuild -eq "True"

Write-Host "SemanticVersion = $SemanticVersion"
Write-Host "BuildId = $BuildId"
Write-Host "TagName = $TagName"
Write-Host "IsTagBuild = $IsTagBuild"

# Build number must be between 0 - 65534
$local:BuildNumber = $BuildId % 65534

Write-Host "BuildNumber = $($local:BuildNumber)"

$local:PackageCodeMarker = "9999.9999.9999"
$local:AssemblyCodeMarker = "9999.9999.9999.9999"

if ($local:IsTagBuildBool)
{
    # Validate tag format
    if ($TagName -notmatch '^v\d+\.\d+\.\d+$')
    {
        Write-Error "ERROR: Tag '$TagName' does not match expected format 'v<major>.<minor>.<patch>'. Aborting release build."
        exit 1
    }
    $local:TagVersion = $TagName -replace '^v', ''
    $local:PackageVersion = $local:TagVersion
    $local:AssemblyVersion = "${local:TagVersion}.$($local:BuildNumber)"
    $local:ReleaseTag = $TagName
    Write-Host "Tag build detected, using tag name as version"
}
else
{
    $local:AssemblyVersion = "${SemanticVersion}.$($local:BuildNumber)"
    $local:PackageVersion = "${SemanticVersion}-pre$($local:BuildNumber)"
    $local:ReleaseTag = "dev/v$($local:PackageVersion)"
    Write-Host "Dev build"
}
Write-Host "PackageCodeMarker = $($local:PackageCodeMarker)"
Write-Host "AssemblyCodeMarker = $($local:AssemblyCodeMarker)"
Write-Host "PackageVersion = $($local:PackageVersion)"
Write-Host "AssemblyVersion = $($local:AssemblyVersion)"

$local:RepoRoot = $SourceDir

Write-Host "Replacing markers in SafeguardDotNet"
$local:ProjectFile = (Join-Path $local:RepoRoot "SafeguardDotNet\SafeguardDotNet.csproj")
(Get-Content $local:ProjectFile -Raw).replace($local:AssemblyCodeMarker, $local:AssemblyVersion).TrimEnd() | Set-Content -Encoding UTF8 $local:ProjectFile
(Get-Content $local:ProjectFile -Raw).replace($local:PackageCodeMarker, $local:PackageVersion).TrimEnd() | Set-Content -Encoding UTF8 $local:ProjectFile

Write-Host "Replacing markers in SafeguardDotNet.BrowserLogin"
$local:ProjectFile = (Join-Path $local:RepoRoot "SafeguardDotNet.BrowserLogin\SafeguardDotNet.BrowserLogin.csproj")
(Get-Content $local:ProjectFile -Raw).replace($local:AssemblyCodeMarker, $local:AssemblyVersion).TrimEnd() | Set-Content -Encoding UTF8 $local:ProjectFile
(Get-Content $local:ProjectFile -Raw).replace($local:PackageCodeMarker, $local:PackageVersion).TrimEnd() | Set-Content -Encoding UTF8 $local:ProjectFile

Write-Host "Replacing markers in SafeguardDotNet.PkceNoninteractiveLogin"
$local:ProjectFile = (Join-Path $local:RepoRoot "SafeguardDotNet.PkceNoninteractiveLogin\SafeguardDotNet.PkceNoninteractiveLogin.csproj")
(Get-Content $local:ProjectFile -Raw).replace($local:AssemblyCodeMarker, $local:AssemblyVersion).TrimEnd() | Set-Content -Encoding UTF8 $local:ProjectFile
(Get-Content $local:ProjectFile -Raw).replace($local:PackageCodeMarker, $local:PackageVersion).TrimEnd() | Set-Content -Encoding UTF8 $local:ProjectFile

Write-Host "Replacing markers in SafeguardDotNet.DeviceCodeLogin"
$local:ProjectFile = (Join-Path $local:RepoRoot "SafeguardDotNet.DeviceCodeLogin\SafeguardDotNet.DeviceCodeLogin.csproj")
(Get-Content $local:ProjectFile -Raw).replace($local:AssemblyCodeMarker, $local:AssemblyVersion).TrimEnd() | Set-Content -Encoding UTF8 $local:ProjectFile
(Get-Content $local:ProjectFile -Raw).replace($local:PackageCodeMarker, $local:PackageVersion).TrimEnd() | Set-Content -Encoding UTF8 $local:ProjectFile

Write-Host "Replacing markers in SafeguardDotNet.GuiLogin"
$local:GuiAssemblyInfoFile = (Join-Path $local:RepoRoot "SafeguardDotNet.GuiLogin\Properties\AssemblyInfo.cs")
$local:GuiNuspec = (Join-Path $local:RepoRoot "SafeguardDotNet.GuiLogin\SafeguardDotNet.GuiLogin.nuspec")
(Get-Content $local:GuiAssemblyInfoFile -Raw).replace($local:AssemblyCodeMarker, $local:AssemblyVersion).TrimEnd() | Set-Content -Encoding UTF8 $local:GuiAssemblyInfoFile
(Get-Content $local:GuiNuspec -Raw).replace($local:PackageCodeMarker, $local:PackageVersion).TrimEnd() | Set-Content -Encoding UTF8 $local:GuiNuspec


Write-Output "##vso[task.setvariable variable=AssemblyVersion;]$($local:AssemblyVersion)"
Write-Output "##vso[task.setvariable variable=PackageVersion;]$($local:PackageVersion)"
Write-Output "##vso[task.setvariable variable=ReleaseTag;]$($local:ReleaseTag)"
