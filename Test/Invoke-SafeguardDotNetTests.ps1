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
        if ($local:Output -is [array])
        {
            # sometimes dotnet run adds weird debug output strings
            # we just want the string with the JSON in it
            $local:Output | ForEach-Object { 
                if ($_ -match "Error" -or $_ -match "Exception")
                {
                    throw $local:Output
                }
                try
                {
                    $local:Obj = (ConvertFrom-Json $_)
                    $local:IsJson = $true
                }
                catch
                {
                    $local:IsJson = $false
                }
            }
            if ($local:IsJson)
            {
                $local:Obj
            }
            else
            {
                [string]::Join("`n",$local:Output)
            }
        }
        elseif ($local:Output -match "Error" -or $local:Output -match "Exception")
        {
            throw $local:Output
        }
        elseif ($local:Output)
        {
            $local:Obj = (ConvertFrom-Json $local:Output)
            $local:Obj
        }
        # Crappy conditionals should have detected anything but empty output by here
    }
    finally
    {
        Pop-Location
    }
}

function Test-ReturnsSuccess {
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
        [bool](Invoke-DotNetRun $Directory $Password $Command)
    }
    catch
    {
        $false
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

$script:TestDataDir = (Resolve-Path "$PSScriptRoot\TestData")
$script:CertDir = (Resolve-Path "$($script:TestDataDir)\CERTS")
$script:UserCert = (Resolve-Path "$($script:CertDir)\UserCert.pem")
$script:UserPfx = (Resolve-Path "$($script:CertDir)\UserCert.pfx")
$script:RootCert = (Resolve-Path "$($script:CertDir)\RootCA.pem")
$script:CaCert = (Resolve-Path "$($script:CertDir)\IntermediateCA.pem")

$script:UserThumbprint = (Get-PfxCertificate $script:UserCert).Thumbprint
$script:RootThumbprint = (Get-PfxCertificate $script:RootCert).Thumbprint
$script:CaThumbprint = (Get-PfxCertificate $script:CaCert).Thumbprint

Write-Host -ForegroundColor Yellow "Building projects..."
Test-ForDotNetTool
Invoke-DotNetBuild $script:ToolDir
Invoke-DotNetBuild $script:A2aToolDir
Invoke-DotNetBuild $script:AccessRequestBrokerToolDir
Invoke-DotNetBuild $script:EventToolDir


### SafeguardDotNetTool Tests

Write-Host -ForegroundColor Yellow "Testing whether can connect to Safeguard ($Appliance) as bootstrap admin..."
Invoke-DotNetRun $script:ToolDir "Admin123" "-a $Appliance -u Admin -x -s Core -m Get -U Me -p"

Write-Host -ForegroundColor Yellow "Setting up a test user (SafeguardDotNetTest)..."
if (-not (Test-ReturnsSuccess $script:ToolDir "Admin123" "-a 10.5.32.162 -u Admin -x -s Core -m Get -U `"Users?filter=UserName%20eq%20'SafeguardDotNetTest'`" -p"))
{
    $local:Body = @{
        PrimaryAuthenticationProviderId = -1;
        UserName = "SafeguardDotNetTest";
        AdminRoles = @('GlobalAdmin','Auditor','AssetAdmin','ApplianceAdmin','PolicyAdmin','UserAdmin','HelpdeskAdmin','OperationsAdmin')
    }
    $local:Result = (Invoke-DotNetRun $script:ToolDir "Admin123" "-a 10.5.32.162 -u Admin -x -s Core -m Post -U Users -p -b `"$(Get-StringEscapedBody $local:Body)`"")
    $local:Result
    Invoke-DotNetRun $script:ToolDir "Admin123" "-a 10.5.32.162 -u Admin -x -s Core -m Put -U Users/$($local:Result.Id)/Password -p -b `"'Test123'`""
}
else
{
    Write-Host "'SafeguardDotNetTest' user already exists"
}

Write-Host -ForegroundColor Yellow "Setting up a cert trust chain..."
if (-not (Test-ReturnsSuccess $script:ToolDir "Admin123" "-a 10.5.32.162 -u Admin -x -s Core -m Get -U `"TrustedCertificates?filter=Thumbprint%20eq%20'$($script:RootThumbprint)'`" -p"))
{
    $local:Body = @{
        Base64CertificateData = [string](Get-Content -Raw $script:RootCert)
    }
    Invoke-DotNetRun $script:ToolDir "Test123" "-a 10.5.32.162 -u SafeguardDotNetTest -x -s Core -m Post -U TrustedCertificates -p -b `"$(Get-StringEscapedBody $local:Body)`""
}
else
{
    Write-Host "Root cert already exists"
}
if (-not (Test-ReturnsSuccess $script:ToolDir "Admin123" "-a 10.5.32.162 -u Admin -x -s Core -m Get -U `"TrustedCertificates?filter=Thumbprint%20eq%20'$($script:CaThumbprint)'`" -p"))
{
    $local:Body = @{
        Base64CertificateData = [string](Get-Content -Raw $script:CaCert)
    }
    Invoke-DotNetRun $script:ToolDir "Test123" "-a 10.5.32.162 -u SafeguardDotNetTest -x -s Core -m Post -U TrustedCertificates -p -b `"$(Get-StringEscapedBody $local:Body)`""
}
else
{
    Write-Host "CA cert already exists"
}

Write-Host -ForegroundColor Yellow "Setting up a cert user (SafeguardDotNetCert)..."
if (-not (Test-ReturnsSuccess $script:ToolDir "Test123" "-a 10.5.32.162 -u SafeguardDotNetTest -x -s Core -m Get -U `"Users?filter=UserName%20eq%20'SafeguardDotNetCert'`" -p"))
{
    $local:Body = @{
        PrimaryAuthenticationProviderId = -2;
        UserName = "SafeguardDotNetCert";
        PrimaryAuthenticationIdentity = $script:UserThumbprint
    }
    Invoke-DotNetRun $script:ToolDir "Test123" "-a 10.5.32.162 -u SafeguardDotNetTest -x -s Core -m Post -U Users -p -b `"$(Get-StringEscapedBody $local:Body)`""
}
else
{
    Write-Host "'SafeguardDotNetCert' user already exists"
}

Write-Host -ForegroundColor Yellow "Testing auth as cert user (SafeguardDotNetCert) from PFX file..."
Invoke-DotNetRun $script:ToolDir "a" "-a $Appliance -c $($script:UserPfx) -x -s Core -m Get -U Me -p"

Write-Host -ForegroundColor Yellow "Testing auth as cert user (SafeguardDotNetCert) from User Certificate Store..."
Import-PfxCertificate $script:UserPfx -CertStoreLocation Cert:\CurrentUser\My -Password (ConvertTo-SecureString -AsPlainText 'a' -Force)
Invoke-DotNetRun $script:ToolDir "a" "-a $Appliance -t $($script:UserThumbprint) -x -s Core -m Get -U Me -p"
Remove-Item "Cert:\CurrentUser\My\$($script:UserThumbprint)"

Write-Host -ForegroundColor Yellow "Testing auth as cert user (SafeguardDotNetCert) from Computer Certificate Store..."
Write-Host -ForegroundColor Magenta "TODO: this requires elevation to install the cert"
# TODO: this requires elevation to install the cert

Write-Host -ForegroundColor Yellow "Setting up for asset for A2A..."
if (-not (Test-ReturnsSuccess $script:ToolDir "Test123" "-a 10.5.32.162 -u SafeguardDotNetTest -x -s Core -m Get -U `"Assets?filter=Name%20eq%20'SafeguardDotNetTest'`" -p"))
{
    $local:Body = @{
        Name = "SafeguardDotNetTest";
        Description = "test asset for SafeguardDotNet test script";
        PlatformId = 188;
        AssetPartitionId = -1;
        NetworkAddress = "fake.address.com"
    }
    Invoke-DotNetRun $script:ToolDir "Test123" "-a 10.5.32.162 -u SafeguardDotNetTest -x -s Core -m Post -U Assets -p -b `"$(Get-StringEscapedBody $local:Body)`""
}
else
{
    Write-Host "'SafeguardDotNetTest' asset already exists"
}
$local:Result = (Invoke-DotNetRun $script:ToolDir "Test123" "-a 10.5.32.162 -u SafeguardDotNetTest -x -s Core -m Get -U `"Assets?filter=Name%20eq%20'SafeguardDotNetTest'`" -p")
if (-not (Test-ReturnsSuccess $script:ToolDir "Test123" "-a 10.5.32.162 -u SafeguardDotNetTest -x -s Core -m Get -U `"Assets/$($local:Result.Id)/Accounts?filter=Name%20eq%20'SafeguardDotNetTest'`" -p"))
{
    $local:Body = @{
        Name = "SafeguardDotNetTest";
        AssetId = $local:Result.Id
    }
    $local:Result = (Invoke-DotNetRun $script:ToolDir "Test123" "-a 10.5.32.162 -u SafeguardDotNetTest -x -s Core -m Post -U `"AssetAccounts`" -p -b `"$(Get-StringEscapedBody $local:Body)`"")
    $local:Result
    Invoke-DotNetRun $script:ToolDir "Test123" "-a 10.5.32.162 -u SafeguardDotNetTest -x -s Core -m Put -U `"AssetAccounts/$($local:Result.Id)/Password`" -p -b `"'Test123'`""
}
else
{
    Write-Host "'SafeguardDotNetTest' asset account already exists"
}

Write-Host -ForegroundColor Yellow "Setting up for A2A credential retrieval..."
if (-not (Test-ReturnsSuccess $script:ToolDir "Test123" "-a 10.5.32.162 -u SafeguardDotNetTest -x -s Core -m Get -U `"A2ARegistrations?filter=AppName%20eq%20'SafeguardDotNetTest'`" -p"))
{
    $local:Result = (Invoke-DotNetRun $script:ToolDir "Test123" "-a 10.5.32.162 -u SafeguardDotNetTest -x -s Core -m Get -U `"Users?filter=UserName%20eq%20'SafeguardDotNetCert'`" -p")
    $local:Body = @{
        AppName = "SafeguardDotNetTest";
        Description = "test a2a registration for SafeguardDotNet test script";
        CertificateUserId = $local:Result.Id
    }
    Invoke-DotNetRun $script:ToolDir "Test123" "-a 10.5.32.162 -u SafeguardDotNetTest -x -s Core -m Post -U A2ARegistrations -p -b `"$(Get-StringEscapedBody $local:Body)`""
}
else
{
    Write-Host "'SafeguardDotNetTest' A2A registration already exists"
}
$local:Result = (Invoke-DotNetRun $script:ToolDir "Test123" "-a 10.5.32.162 -u SafeguardDotNetTest -x -s Core -m Get -U `"A2ARegistrations?filter=AppName%20eq%20'SafeguardDotNetTest'`" -p")
if (-not (Test-ReturnsSuccess $script:ToolDir "Test123" "-a 10.5.32.162 -u SafeguardDotNetTest -x -s Core -m Get -U `"A2ARegistrations/$($local:Result.Id)/RetrievableAccounts?filter=AccountName%20eq%20'SafeguardDotNetTest'`" -p"))
{
    $local:A2aId = $local:Result.Id
    $local:Result = (Invoke-DotNetRun $script:ToolDir "Test123" "-a 10.5.32.162 -u SafeguardDotNetTest -x -s Core -m Get -U `"AssetAccounts?filter=Name%20eq%20'SafeguardDotNetTest'`" -p")
    if (-not $local:Result)
    {
        throw "Couldn't find asset account SafeguardDotNetTest to create A2A account retrieval"
    }
    $local:Body = @{
        SystemId = $local:Result.AssetId;
        AccountId = $local:Result.Id
    }
    Invoke-DotNetRun $script:ToolDir "Test123" "-a 10.5.32.162 -u SafeguardDotNetTest -x -s Core -m Post -U `"A2ARegistrations/$($local:A2aId)/RetrievableAccounts`" -p -b `"$(Get-StringEscapedBody $local:Body)`""
}
else
{
    Write-Host "'SafeguardDotNetTest' A2A registration account retrieval already exists"
}


### SafeguardDotNetA2aTool Tests

$local:Result = (Invoke-DotNetRun $script:ToolDir "Test123" "-a 10.5.32.162 -u SafeguardDotNetTest -x -s Core -m Get -U `"A2ARegistrations?filter=AppName%20eq%20'SafeguardDotNetTest'`" -p")
$local:Result = (Invoke-DotNetRun $script:ToolDir "Test123" "-a 10.5.32.162 -u SafeguardDotNetTest -x -s Core -m Get -U `"A2ARegistrations/$($local:Result.Id)/RetrievableAccounts?filter=AccountName%20eq%20'SafeguardDotNetTest'`" -p")
$script:A2aCrApiKey = $local:Result.ApiKey

Write-Host -ForegroundColor Yellow "Calling A2A credential retrieval with Pfx file..."
Invoke-DotNetRun $script:A2aToolDir "a" "-a 10.5.32.162 -x -c $($script:UserPfx) -A `"$($script:A2aCrApiKey)`" -p"

Write-Host -ForegroundColor Yellow "Calling A2A credential retrieval from User Certificate Store..."
Import-PfxCertificate $script:UserPfx -CertStoreLocation Cert:\CurrentUser\My -Password (ConvertTo-SecureString -AsPlainText 'a' -Force)
Invoke-DotNetRun $script:A2aToolDir "a" "-a 10.5.32.162 -x -t $($script:UserThumbprint) -A `"$($script:A2aCrApiKey)`" -p"
Remove-Item "Cert:\CurrentUser\My\$($script:UserThumbprint)"
