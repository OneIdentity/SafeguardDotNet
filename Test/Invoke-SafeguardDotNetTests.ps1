Param(
    [Parameter(Mandatory=$true, Position=0)]
    [string]$Appliance
)

$ErrorActionPreference = "Stop"

function Test-ForDotNetTool {
    if (-not (Test-Command "dotnet.exe")) {
        throw "This test tool requires the dotnet.exe command line tool"
    }
}

function Invoke-DotNetBuild {
    Param(
        [Parameter(Mandatory=$true, Position=0)]
        [string]$Directory
    )

    try
    {
        Push-Location $Directory
        & dotnet.exe build
    }
    finally
    {
        Pop-Location
    }
}

function Invoke-DotNetRun {
    Param(
        [Parameter(Mandatory=$true, Position=0)]
        [string]$Directory,
        [Parameter(Mandatory=$true, Position=1)]
        [string]$Password,
        [Parameter(Mandatory=$false, Position=2)]
        [string]$Command
    )

    try
    {
        Push-Location $Directory
        $local:Expression = "`"$Password`" | & dotnet.exe run -- $Command"
        Write-Host "Executing: $($local:Expression)"
        $local:Output = (Invoke-Expression $local:Expression)
        if ($local:Output -match "Error" -or $local:Output -match "Exception")
        {
            throw $local:Output
        }
        $local:Obj = (ConvertFrom-Json $local:Output)
        $local:Obj
    }
    finally
    {
        Pop-Location
    }
}

function Get-StringEscapedBody {
    Param(
        [Parameter(Mandatory=$true, Position=0)]
        [hashtable]$Body
    )

    # quoting with the Invoke-Expression is complicated
    # luckily our API will handle single quotes in JSON strings
    (ConvertTo-Json $Body -Compress).Replace("`"","'")
}

$script:ToolDir = (Resolve-Path "$PSScriptRoot\SafeguardDotNetTool")
$script:A2aToolDir = (Resolve-Path "$PSScriptRoot\SafeguardDotNetA2aTool")
$script:AccessRequestBrokerToolDir = (Resolve-Path "$PSScriptRoot\SafeguardDotNetAccessRequestBrokerTool")
$script:EventToolDir = (Resolve-Path "$PSScriptRoot\SafeguardDotNetEventTool")

Write-Host -ForegroundColor Yellow "Building projects..."
Test-ForDotNetTool
Invoke-DotNetBuild $script:ToolDir
Invoke-DotNetBuild $script:A2aToolDir
Invoke-DotNetBuild $script:AccessRequestBrokerToolDir
Invoke-DotNetBuild $script:EventToolDir

Write-Host -ForegroundColor Yellow "Testing whether can connect to Safeguard ($Appliance) as bootstrap admin..."
Invoke-DotNetRun $script:ToolDir "Admin123" "-a $Appliance -u Admin -x -s Core -m Get -U Me -p"

Write-Host -ForegroundColor Yellow "Setting up a test user (SafeguardDotNetTest)..."
$local:Body = @{
    PrimaryAuthenticationProviderId = -1;
    UserName = "SafeguardDotNetTest";
    AdminRoles = @('GlobalAdmin','Auditor','AssetAdmin','ApplianceAdmin','PolicyAdmin','UserAdmin','HelpdeskAdmin','OperationsAdmin')
}
Invoke-DotNetRun $script:ToolDir "Admin123" "-a 10.5.32.162 -u Admin -x -s Core -m Post -U Users -p -b `"$(Get-StringEscapedBody $local:Body)`""
#Invoke-DotNetRun $script:ToolDir "Admin123" "-a 10.5.32.162 -u Admin -x -s Core -m Post -U Users -b '{`"PrimaryAuthenticationProviderId`":-1,`"UserName`":`"SafeguardDotNetTest`",`"AdminRoles`":[`"GlobalAdmin`","Auditor","AssetAdmin","ApplianceAdmin","PolicyAdmin","UserAdmin","HelpdeskAdmin","OperationsAdmin"]}'
