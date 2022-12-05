Param(
    [Parameter(Mandatory=$true, Position=0)]
    [string]$Appliance
)

$ErrorActionPreference = "Stop"

function Test-ForDotNetTool {
    if (-not (Get-Command "dotnet.exe" -EA SilentlyContinue)) {
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
        [Parameter(Mandatory=$false, Position=1)]
        [string]$Password,
        [Parameter(Mandatory=$false, Position=2)]
        [string]$Command,
        [Parameter(Mandatory=$false)]
        [switch]$IgnoreOutput
    )

    try
    {
        Push-Location $Directory
        if ($Password)
        {
            $local:Expression = "`"$Password`" | & dotnet.exe run -- $Command"
        }
        else # if there is no password don't try to pass it to stdin
        {
            $local:Expression = "& dotnet.exe run -- $Command"
        }
        Write-Host "Executing: $($local:Expression)"
        if ($IgnoreOutput)
        {
            (Invoke-Expression $local:Expression)
        }
        else
        {
            $local:Output = (Invoke-Expression $local:Expression)
            if ($local:Output -is [array])
            {
                # sometimes dotnet run adds weird debug output strings
                # we just want the string with the JSON in it
                $local:Output | ForEach-Object {
                    if ($_ -match "Error" -or $_ -match "Exception:")
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
    (ConvertTo-Json -Depth 12 $Body -Compress).Replace("`"","'")
}

$script:ToolDir = (Resolve-Path "$PSScriptRoot\SafeguardDotNetTool")
$script:ExceptionTestDir = (Resolve-Path "$PSScriptRoot\SafeguardDotNetExceptionTest")
$script:A2aToolDir = (Resolve-Path "$PSScriptRoot\SafeguardDotNetA2aTool")
$script:AccessRequestBrokerToolDir = (Resolve-Path "$PSScriptRoot\SafeguardDotNetAccessRequestBrokerTool")
$script:EventToolDir = (Resolve-Path "$PSScriptRoot\SafeguardDotNetEventTool")

$script:TestDataDir = (Resolve-Path "$PSScriptRoot\TestData")
$script:CertDir = (Resolve-Path "$($script:TestDataDir)\CERTS")
$script:UserCert = (Resolve-Path "$($script:CertDir)\UserCert.pem")
$script:UserPfx = (Resolve-Path "$($script:CertDir)\UserCert.pfx")
$script:RootCert = (Resolve-Path "$($script:CertDir)\RootCA.pem")
$script:CaCert = (Resolve-Path "$($script:CertDir)\IntermediateCA.pem")

$script:TestObj = "SafeguardDotNetTest"
$script:TestCred = "2309aseflkasdlf209349qauerA"
$script:CertUser = "SafeguardDotNetCert"

$script:UserThumbprint = (Get-PfxCertificate $script:UserCert).Thumbprint
$script:RootThumbprint = (Get-PfxCertificate $script:RootCert).Thumbprint
$script:CaThumbprint = (Get-PfxCertificate $script:CaCert).Thumbprint

Write-Host -ForegroundColor Yellow "Building projects..."
Test-ForDotNetTool
Invoke-DotNetBuild $script:ToolDir
Invoke-DotNetBuild $script:ExceptionTestDir
Invoke-DotNetBuild $script:A2aToolDir
Invoke-DotNetBuild $script:AccessRequestBrokerToolDir
Invoke-DotNetBuild $script:EventToolDir


### SafeguardDotNetTool Tests

Write-Host -ForegroundColor Yellow "Testing whether anonymous notification Status endpoint can be reached on Safeguard ($Appliance)..."
Invoke-DotNetRun $script:ToolDir $null "-a $Appliance -A -x -s Notification -m Get -U Status"

Write-Host -ForegroundColor Yellow "Testing whether can connect to Safeguard ($Appliance) as bootstrap admin..."
Invoke-DotNetRun $script:ToolDir "Admin123" "-a $Appliance -u Admin -x -s Core -m Get -U Me -p"

Write-Host -ForegroundColor Yellow "Testing SafeguardDotNetExceptions against Safeguard ($Appliance)..."
Invoke-DotNetRun $script:ExceptionTestDir "Admin123" "-a $Appliance -u Admin -x -p"

Write-Host -ForegroundColor Yellow "Setting up a test user ($($script:TestObj))..."
if (-not (Test-ReturnsSuccess $script:ToolDir "Admin123" "-a $Appliance -u Admin -x -s Core -m Get -U `"Users?filter=Name%20eq%20'$($script:TestObj)'`" -p"))
{
    $local:Body = @{
        PrimaryAuthenticationProvider = @{ Id = -1 };
        Name = "$($script:TestObj)";
        AdminRoles = @('GlobalAdmin','Auditor','AssetAdmin','ApplianceAdmin','PolicyAdmin','UserAdmin','HelpdeskAdmin','OperationsAdmin')
    }
    $local:Result = (Invoke-DotNetRun $script:ToolDir "Admin123" "-a $Appliance -u Admin -x -s Core -m Post -U Users -p -b `"$(Get-StringEscapedBody $local:Body)`"")
    $local:Result
    Invoke-DotNetRun $script:ToolDir "Admin123" "-a $Appliance -u Admin -x -s Core -m Put -U Users/$($local:Result.Id)/Password -p -b `"'$($script:TestCred)'`""
}
else
{
    Write-Host "'$($script:TestObj)' user already exists"
}

Write-Host -ForegroundColor Yellow "Setting up a cert trust chain..."
if (-not (Test-ReturnsSuccess $script:ToolDir "Admin123" "-a $Appliance -u Admin -x -s Core -m Get -U `"TrustedCertificates?filter=Thumbprint%20eq%20'$($script:RootThumbprint)'`" -p"))
{
    $local:Body = @{
        Base64CertificateData = [string](Get-Content -Raw $script:RootCert)
    }
    Invoke-DotNetRun $script:ToolDir $script:TestCred "-a $Appliance -u $script:TestObj -x -s Core -m Post -U TrustedCertificates -p -b `"$(Get-StringEscapedBody $local:Body)`""
}
else
{
    Write-Host "Root cert already exists"
}
if (-not (Test-ReturnsSuccess $script:ToolDir "Admin123" "-a $Appliance -u Admin -x -s Core -m Get -U `"TrustedCertificates?filter=Thumbprint%20eq%20'$($script:CaThumbprint)'`" -p"))
{
    $local:Body = @{
        Base64CertificateData = [string](Get-Content -Raw $script:CaCert)
    }
    Invoke-DotNetRun $script:ToolDir $script:TestCred "-a $Appliance -u $script:TestObj -x -s Core -m Post -U TrustedCertificates -p -b `"$(Get-StringEscapedBody $local:Body)`""
}
else
{
    Write-Host "CA cert already exists"
}

Write-Host -ForegroundColor Yellow "Setting up a cert user ($($script:CertUser))..."
if (-not (Test-ReturnsSuccess $script:ToolDir $script:TestCred "-a $Appliance -u $script:TestObj -x -s Core -m Get -U `"Users?filter=Name%20eq%20'$($script:CertUser)'`" -p"))
{
    $local:Body = @{
        PrimaryAuthenticationProvider = @{
            Id = -2;
            Identity = $script:UserThumbprint
        };
        Name = "$($script:CertUser)"
    }
    Invoke-DotNetRun $script:ToolDir $script:TestCred "-a $Appliance -u $script:TestObj -x -s Core -m Post -U Users -p -b `"$(Get-StringEscapedBody $local:Body)`""
}
else
{
    Write-Host "'$($script:CertUser)' user already exists"
}

Write-Host -ForegroundColor Yellow "Testing auth as cert user ($($script:CertUser)) from PFX file..."
Invoke-DotNetRun $script:ToolDir "a" "-a $Appliance -c $($script:UserPfx) -x -s Core -m Get -U Me -p"

Write-Host -ForegroundColor Yellow "Testing auth as cert user ($($script:CertUser)) from PFX file as data..."
Invoke-DotNetRun $script:ToolDir "a" "-a $Appliance -c $($script:UserPfx) -d -x -s Core -m Get -U Me -p"

Write-Host -ForegroundColor Yellow "Testing auth as cert user ($($script:CertUser)) from User Certificate Store..."
Import-PfxCertificate $script:UserPfx -CertStoreLocation Cert:\CurrentUser\My -Password (ConvertTo-SecureString -AsPlainText 'a' -Force)
Invoke-DotNetRun $script:ToolDir "a" "-a $Appliance -t $($script:UserThumbprint) -x -s Core -m Get -U Me -p"
Remove-Item "Cert:\CurrentUser\My\$($script:UserThumbprint)"

Write-Host -ForegroundColor Yellow "Testing auth as cert user ($($script:CertUser)) from Computer Certificate Store..."
Write-Host -ForegroundColor Magenta "TODO: this requires elevation to install the cert"
# TODO: this requires elevation to install the cert

Write-Host -ForegroundColor Yellow "Setting up for asset for A2A..."
if (-not (Test-ReturnsSuccess $script:ToolDir $script:TestCred "-a $Appliance -u $script:TestObj -x -s Core -m Get -U `"Assets?filter=Name%20eq%20'$($script:TestObj)'`" -p"))
{
    $local:Body = @{
        Name = "$($script:TestObj)";
        Description = "test asset for SafeguardDotNet test script";
        PlatformId = 188;
        AssetPartitionId = -1;
        NetworkAddress = "fake.address.com"
    }
    Invoke-DotNetRun $script:ToolDir $script:TestCred "-a $Appliance -u $script:TestObj -x -s Core -m Post -U Assets -p -b `"$(Get-StringEscapedBody $local:Body)`""
}
else
{
    Write-Host "'$($script:TestObj)' asset already exists"
}
$local:Result = (Invoke-DotNetRun $script:ToolDir $script:TestCred "-a $Appliance -u $script:TestObj -x -s Core -m Get -U `"Assets?filter=Name%20eq%20'$($script:TestObj)'`" -p")
if (-not (Test-ReturnsSuccess $script:ToolDir $script:TestCred "-a $Appliance -u $script:TestObj -x -s Core -m Get -U `"Assets/$($local:Result.Id)/Accounts?filter=Name%20eq%20'$($script:TestObj)'`" -p"))
{
    $local:Body = @{
        Name = "$($script:TestObj)";
        Asset = @{ Id = $local:Result.Id }
    }
    $local:Result = (Invoke-DotNetRun $script:ToolDir $script:TestCred "-a $Appliance -u $script:TestObj -x -s Core -m Post -U `"AssetAccounts`" -p -b `"$(Get-StringEscapedBody $local:Body)`"")
    $local:Result
    Invoke-DotNetRun $script:ToolDir $script:TestCred "-a $Appliance -u $script:TestObj -x -s Core -m Put -U `"AssetAccounts/$($local:Result.Id)/Password`" -p -b `"'$($script:TestCred)'`""
}
else
{
    Write-Host "'$($script:TestObj)' asset account already exists"
}

Write-Host -ForegroundColor Yellow "Setting up for A2A credential retrieval..."
if (-not (Test-ReturnsSuccess $script:ToolDir $script:TestCred "-a $Appliance -u $script:TestObj -x -s Core -m Get -U `"A2ARegistrations?filter=AppName%20eq%20'$($script:TestObj)'`" -p"))
{
    $local:Result = (Invoke-DotNetRun $script:ToolDir $script:TestCred "-a $Appliance -u $script:TestObj -x -s Core -m Get -U `"Users?filter=Name%20eq%20'$($script:CertUser)'`" -p")
    $local:Body = @{
        AppName = "$($script:TestObj)";
        VisibleToCertificateUsers = $true;
        Description = "test a2a registration for SafeguardDotNet test script";
        CertificateUserId = $local:Result.Id
    }
    Invoke-DotNetRun $script:ToolDir $script:TestCred "-a $Appliance -u $script:TestObj -x -s Core -m Post -U A2ARegistrations -p -b `"$(Get-StringEscapedBody $local:Body)`""
}
else
{
    Write-Host "'$($script:TestObj)' A2A registration already exists"
}
$local:Result = (Invoke-DotNetRun $script:ToolDir $script:TestCred "-a $Appliance -u $script:TestObj -x -s Core -m Get -U `"A2ARegistrations?filter=AppName%20eq%20'$($script:TestObj)'`" -p")
if (-not (Test-ReturnsSuccess $script:ToolDir $script:TestCred "-a $Appliance -u $script:TestObj -x -s Core -m Get -U `"A2ARegistrations/$($local:Result.Id)/RetrievableAccounts?filter=AccountName%20eq%20'$($script:TestObj)'`" -p"))
{
    $local:A2aId = $local:Result.Id
    $local:Result = (Invoke-DotNetRun $script:ToolDir $script:TestCred "-a $Appliance -u $script:TestObj -x -s Core -m Get -U `"AssetAccounts?filter=Name%20eq%20'$($script:TestObj)'`" -p")
    if (-not $local:Result)
    {
        throw "Couldn't find asset account $($script:TestObj) to create A2A account retrieval"
    }
    $local:Body = @{
        AccountId = $local:Result.Id
    }
    Invoke-DotNetRun $script:ToolDir $script:TestCred "-a $Appliance -u $script:TestObj -x -s Core -m Post -U `"A2ARegistrations/$($local:A2aId)/RetrievableAccounts`" -p -b `"$(Get-StringEscapedBody $local:Body)`""
}
else
{
    Write-Host "'$($script:TestObj)' A2A registration account retrieval already exists"
}
Invoke-DotNetRun $script:ToolDir $script:TestCred "-a $Appliance -u $script:TestObj -x -s Appliance -m Post -U `"A2AService/Enable`" -p"


### SafeguardDotNetA2aTool Tests

$local:Result = (Invoke-DotNetRun $script:ToolDir $script:TestCred "-a $Appliance -u $script:TestObj -x -s Core -m Get -U `"A2ARegistrations?filter=AppName%20eq%20'$($script:TestObj)'`" -p")
$local:Result = (Invoke-DotNetRun $script:ToolDir $script:TestCred "-a $Appliance -u $script:TestObj -x -s Core -m Get -U `"A2ARegistrations/$($local:Result.Id)/RetrievableAccounts?filter=AccountName%20eq%20'$($script:TestObj)'`" -p")
$script:A2aCrApiKey = $local:Result.ApiKey

Write-Host -ForegroundColor Yellow "Calling A2A retrievable accounts..."
Invoke-DotNetRun $script:A2aToolDir "a" "-a $Appliance -x -c $($script:UserPfx) -A `"$($script:A2aCrApiKey)`" -R -p"

Write-Host -ForegroundColor Yellow "Calling A2A credential retrieval with Pfx file..."
Invoke-DotNetRun $script:A2aToolDir "a" "-a $Appliance -x -c $($script:UserPfx) -A `"$($script:A2aCrApiKey)`" -p"

Write-Host -ForegroundColor Yellow "Calling A2A credential retrieval with Pfx file as data..."
Invoke-DotNetRun $script:A2aToolDir "a" "-a $Appliance -x -c $($script:UserPfx) -d -A `"$($script:A2aCrApiKey)`" -p"

Write-Host -ForegroundColor Yellow "Calling A2A credential retrieval from User Certificate Store..."
Import-PfxCertificate $script:UserPfx -CertStoreLocation Cert:\CurrentUser\My -Password (ConvertTo-SecureString -AsPlainText 'a' -Force)
Invoke-DotNetRun $script:A2aToolDir "a" "-a $Appliance -x -t $($script:UserThumbprint) -A `"$($script:A2aCrApiKey)`" -p"
Remove-Item "Cert:\CurrentUser\My\$($script:UserThumbprint)"


### Workflow Test

Write-Host -ForegroundColor Yellow "Setting up entitlement for workflow..."
if (-not (Test-ReturnsSuccess $script:ToolDir $script:TestCred "-a $Appliance -u $script:TestObj -x -s Core -m Get -U `"Roles?filter=Name%20eq%20'$($script:TestObj)'`" -p"))
{
    $local:User = (Invoke-DotNetRun $script:ToolDir $script:TestCred "-a $Appliance -u $script:TestObj -x -s Core -m Get -U `"Users?filter=Name%20eq%20'$($script:TestObj)'`" -p")
    $local:Body = @{
        Name = "$($script:TestObj)";
        Description = "test entitlement for SafeguardDotNet test script";
        Members = @(@{Id = $local:User.Id})
    }
    Invoke-DotNetRun $script:ToolDir $script:TestCred "-a $Appliance -u $script:TestObj -x -s Core -m Post -U Roles -p -b `"$(Get-StringEscapedBody $local:Body)`""
}
else
{
    Write-Host "'$($script:TestObj)' entitlement already exists"
}
$local:Result = (Invoke-DotNetRun $script:ToolDir $script:TestCred "-a $Appliance -u $script:TestObj -x -s Core -m Get -U `"Roles?filter=Name%20eq%20'$($script:TestObj)'`" -p")

Write-Host -ForegroundColor Yellow "Setting up policy for workflow..."
if (-not (Test-ReturnsSuccess $script:ToolDir $script:TestCred "-a $Appliance -u $script:TestObj -x -s Core -m Get -U `"AccessPolicies?filter=Name%20eq%20'$($script:TestObj)'`" -p"))
{
    $local:User = (Invoke-DotNetRun $script:ToolDir $script:TestCred "-a $Appliance -u $script:TestObj -x -s Core -m Get -U `"Users?filter=Name%20eq%20'$($script:CertUser)'`" -p")
    $local:Account = (Invoke-DotNetRun $script:ToolDir $script:TestCred "-a $Appliance -u $script:TestObj -x -s Core -m Get -U `"AssetAccounts?filter=Name%20eq%20'$($script:TestObj)'`" -p")
    $local:Body = @{
        Name = "$($script:TestObj)";
        Description = "test policy for SafeguardDotNet test script";
        RoleId = $local:Result.Id;
        AccessRequestProperties = @{
            AccessRequestType = "Password";
            ChangePasswordAfterCheckin = $false;
            ChangeSshKeyAfterCheckin = $false
        };
        ApproverProperties = @{
            RequireApproval = $true;
        };
        ApproverSets = @(
            @{
                RequiredApprovers = 1;
                Approvers = @(@{ Id = $local:User.Id })
            }
        );
        ScopeItems = @(
            @{
                ScopeItemType = "Account";
                Id = $local:Account.Id
            }
        )
    }
    (Get-StringEscapedBody $local:Body)
    Invoke-DotNetRun $script:ToolDir $script:TestCred "-a $Appliance -u $script:TestObj -x -s Core -m Post -U AccessPolicies -p -b `"$(Get-StringEscapedBody $local:Body)`""
}
else
{
    Write-Host "'$($script:TestObj)' policy already exists"
}

Write-Host -ForegroundColor Yellow "Creating access request..."
$local:Account = (Invoke-DotNetRun $script:ToolDir $script:TestCred "-a $Appliance -u $script:TestObj -x -s Core -m Get -U `"AssetAccounts?filter=Name%20eq%20'$($script:TestObj)'`" -p")
$local:Body = @{
    AccessRequestType = "Password";
    AssetId = $local:Account.Asset.Id;
    AccountId = $local:Account.Id
}
$local:Request = (Invoke-DotNetRun $script:ToolDir $script:TestCred "-a $Appliance -u $script:TestObj -x -s Core -m Post -U AccessRequests -p -b `"$(Get-StringEscapedBody $local:Body)`"")
Invoke-DotNetRun $script:ToolDir "a" "-a $Appliance -c $($script:UserPfx) -x -s Core -m Post -U `"AccessRequests/$($local:Request.Id)`/Approve`" -p"
Invoke-DotNetRun $script:ToolDir $script:TestCred "-a $Appliance -u $script:TestObj -x -s Core -m Post -U `"AccessRequests/$($local:Request.Id)`/CheckOutPassword`" -p"
Invoke-DotNetRun $script:ToolDir $script:TestCred "-a $Appliance -u $script:TestObj -x -s Core -m Post -U `"AccessRequests/$($local:Request.Id)`/CheckIn`" -p"
