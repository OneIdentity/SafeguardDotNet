[CmdletBinding()]
Param(
    [Parameter(Mandatory=$true, Position=0)]
    [string]$SourceDir,
    [Parameter(Mandatory=$true, Position=1)]
    [string]$SemanticVersion,
    [Parameter(Mandatory=$true, Position=2)]
    [string]$BuildId
)

Write-Host "SemanticVersion = $SemanticVersion"
Write-Host "BuildId = $BuildId"

$local:BuildNumber = ($BuildId - 105000)
Write-Host "BuildNumber = $($local:BuildNumber)"

$local:VersionString = "${SemanticVersion}.$($local:BuildNumber)"
$local:TemplateVersion = "9999.9999.9999.9999"
Write-Host "VersionString = $($local:VersionString)"
Write-Host "TemplateVersion = $($local:TemplateVersion)"

Write-Host "Searching for files with version info in '$SourceDir'"
(Get-ChildItem -Recurse -Include @("AssemblyInfo.cs","*.csproj")) | Where-Object { (Get-Content -Raw $_.Fullname) -like "*$($local:TemplateVersion)*" } | ForEach-Object {
    $local:Path = $_.FullName
    Write-Host "Replacing version information in '$($local:Path)'"
    (Get-Content $local:Path -Raw).replace($local:TemplateVersion, $local:VersionString) | Set-Content $local:Path

    Write-Output "*****"
    Get-Content $local:Path
    Write-Output "*****"
}

Write-Output "##vso[task.setvariable variable=VersionString;]$($local:VersionString)"
