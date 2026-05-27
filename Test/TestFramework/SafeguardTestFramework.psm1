#Requires -Version 7.0
<#
.SYNOPSIS
    SafeguardDotNet Test Framework Module

.DESCRIPTION
    Provides test context management, assertion functions, improved tool invocation,
    cleanup registration, and structured reporting for SafeguardDotNet integration tests.

    All tests run against a live Safeguard appliance. This module replaces the fragile
    Invoke-Expression / regex-based patterns from the legacy test script with proper
    process invocation using Start-Process and exit code checking.

    All exported functions use the SgDn noun prefix to avoid conflicts.
#>

# ============================================================================
# Module-scoped state
# ============================================================================

$script:TestContext = $null

# ============================================================================
# Context Management
# ============================================================================

function New-SgDnTestContext {
    <#
    .SYNOPSIS
        Creates a new test context tracking appliance info, credentials, results, and cleanup.

    .DESCRIPTION
        Initializes a PSCustomObject that carries all state for a test run: connection info,
        tool paths, certificate paths, per-suite data, cleanup stack, and result collection.
        The context is also stored at module scope so other functions can retrieve it via
        Get-SgDnTestContext.

    .PARAMETER Appliance
        Network address of the Safeguard appliance to test against.

    .PARAMETER AdminUserName
        Bootstrap admin username. Default: "admin".

    .PARAMETER AdminPassword
        Bootstrap admin password. Default: "Admin123".

    .PARAMETER SpsAppliance
        Optional network address of a Safeguard for Privileged Sessions appliance.

    .PARAMETER SpsUser
        SPS admin username. Default: "admin".

    .PARAMETER SpsPassword
        SPS admin password.

    .PARAMETER TestPrefix
        Prefix used for naming test objects on the appliance. Default: "SgDnTest".

    .EXAMPLE
        $ctx = New-SgDnTestContext -Appliance "sg.example.com" -AdminPassword "Secret123"
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Appliance,

        [Parameter()]
        [string]$AdminUserName = "admin",

        [Parameter()]
        [string]$AdminPassword = "Admin123",

        [Parameter()]
        [string]$SpsAppliance,

        [Parameter()]
        [string]$SpsUser = "admin",

        [Parameter()]
        [string]$SpsPassword,

        [Parameter()]
        [string]$TestPrefix = "SgDnTest",

        [Parameter()]
        [string]$TotpSeed
    )

    $testRoot = Split-Path -Parent $PSScriptRoot
    $context = [PSCustomObject]@{
        # Connection info
        Appliance       = $Appliance
        AdminUserName   = $AdminUserName
        AdminPassword   = $AdminPassword
        SpsAppliance    = $SpsAppliance
        SpsUser         = $SpsUser
        SpsPassword     = $SpsPassword

        # Naming
        TestPrefix      = $TestPrefix

        # MFA
        TotpSeed        = $TotpSeed

        # Paths
        TestRoot        = $testRoot
        ToolDir         = (Join-Path $testRoot "SafeguardDotNetTool")
        ExceptionTestDir = (Join-Path $testRoot "SafeguardDotNetExceptionTest")
        A2aToolDir      = (Join-Path $testRoot "SafeguardDotNetA2aTool")
        AccessRequestBrokerToolDir = (Join-Path $testRoot "SafeguardDotNetAccessRequestBrokerTool")
        EventToolDir    = (Join-Path $testRoot "SafeguardDotNetEventTool")
        SessionsToolDir = (Join-Path $testRoot "SafeguardSessionsDotNetTool")
        PkceToolDir     = (Join-Path $testRoot "SafeguardDotNetPkceNoninteractiveLoginTester")
        CertDir         = (Join-Path $testRoot "TestData" "CERTS")

        # Per-suite transient data (reset each suite)
        SuiteData       = @{}

        # Cleanup stack (LIFO)
        CleanupActions  = [System.Collections.Generic.Stack[PSCustomObject]]::new()

        # Results
        SuiteResults    = [System.Collections.Generic.List[PSCustomObject]]::new()
        StartTime       = [DateTime]::UtcNow
    }

    # Resolve certificate paths
    $context | Add-Member -NotePropertyName UserCert -NotePropertyValue (Join-Path $context.CertDir "UserCert.pem")
    $context | Add-Member -NotePropertyName UserPfx  -NotePropertyValue (Join-Path $context.CertDir "UserCert.pfx")
    $context | Add-Member -NotePropertyName RootCert -NotePropertyValue (Join-Path $context.CertDir "RootCA.pem")
    $context | Add-Member -NotePropertyName CaCert   -NotePropertyValue (Join-Path $context.CertDir "IntermediateCA.pem")

    $script:TestContext = $context
    return $context
}

function Get-SgDnTestContext {
    <#
    .SYNOPSIS
        Returns the current module-scoped test context.
    #>
    if (-not $script:TestContext) {
        throw "No test context. Call New-SgDnTestContext first."
    }
    return $script:TestContext
}

# ============================================================================
# Cleanup Registration
# ============================================================================

function Register-SgDnTestCleanup {
    <#
    .SYNOPSIS
        Registers an idempotent cleanup action that runs during suite cleanup.
        Actions execute in LIFO order. Failures are logged but do not propagate.
    .PARAMETER Description
        Human-readable description of what this cleanup does.
    .PARAMETER Action
        ScriptBlock to execute. Receives $Context as parameter.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Description,

        [Parameter(Mandatory)]
        [scriptblock]$Action
    )

    $ctx = Get-SgDnTestContext
    $ctx.CleanupActions.Push([PSCustomObject]@{
        Description = $Description
        Action      = $Action
    })
}

function Invoke-SgDnTestCleanup {
    <#
    .SYNOPSIS
        Executes all registered cleanup actions in LIFO order.
        Each action is wrapped in try/catch — failures are logged but never propagate.

    .PARAMETER Context
        The test context whose cleanup stack should be drained.

    .EXAMPLE
        Invoke-SgDnTestCleanup -Context $ctx
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [PSCustomObject]$Context
    )

    $count = $Context.CleanupActions.Count
    if ($count -eq 0) {
        Write-Host "  No cleanup actions registered." -ForegroundColor DarkGray
        return
    }

    Write-Host "  Running $count cleanup action(s)..." -ForegroundColor DarkGray
    while ($Context.CleanupActions.Count -gt 0) {
        $item = $Context.CleanupActions.Pop()
        try {
            Write-Host "    Cleanup: $($item.Description)" -ForegroundColor DarkGray
            & $item.Action $Context
        }
        catch {
            Write-Host "    Cleanup ignored failure: $($_.Exception.Message)" -ForegroundColor DarkYellow
        }
    }
}

# ============================================================================
# SafeguardDotNetTool Invocation
# ============================================================================

function Invoke-SgDnSafeguardTool {
    <#
    .SYNOPSIS
        Runs a dotnet test tool project with proper process management.

    .DESCRIPTION
        Replaces the legacy Invoke-Expression + regex approach with
        System.Diagnostics.Process for clean stdin/stdout/stderr separation and
        exit code checking. Stdout is captured asynchronously to avoid deadlocks.

    .PARAMETER ProjectDir
        Path to the dotnet project directory.

    .PARAMETER Arguments
        Arguments string to pass after 'dotnet run --'.

    .PARAMETER StdinLine
        Optional single line to pipe to stdin (typically a password).
        Only used by tools that accept -p/--ReadPassword.

    .PARAMETER ParseJson
        If set, attempts to parse stdout as JSON. Default: $true.

    .PARAMETER TimeoutSeconds
        Maximum time to wait for the process. Default: 120.

    .OUTPUTS
        PSObject if JSON parsed successfully, or raw string output.

    .EXAMPLE
        Invoke-SgDnSafeguardTool -ProjectDir $ctx.ToolDir `
            -Arguments "-a sg.example.com -A -x -s Notification -m Get -U Status"

    .EXAMPLE
        Invoke-SgDnSafeguardTool -ProjectDir $ctx.A2aToolDir `
            -Arguments "-a sg.example.com -x -c cert.pfx -A `"key`" -R -p" `
            -StdinLine "certpassword"
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$ProjectDir,

        [Parameter()]
        [string]$Arguments = "",

        [Parameter()]
        [string]$StdinLine,

        [Parameter()]
        [bool]$ParseJson = $true,

        [Parameter()]
        [int]$TimeoutSeconds = 120
    )

    $startInfo = [System.Diagnostics.ProcessStartInfo]::new()
    $startInfo.FileName = "dotnet"
    $startInfo.Arguments = "run --project `"$ProjectDir`" -- $Arguments"
    $startInfo.UseShellExecute = $false
    $startInfo.RedirectStandardOutput = $true
    $startInfo.RedirectStandardError = $true
    $startInfo.RedirectStandardInput = ($null -ne $StdinLine -and $StdinLine -ne "")
    $startInfo.CreateNoWindow = $true
    $startInfo.WorkingDirectory = $ProjectDir

    $process = [System.Diagnostics.Process]::new()
    $process.StartInfo = $startInfo

    # Capture output asynchronously to avoid deadlocks
    $stdoutBuilder = [System.Text.StringBuilder]::new()
    $stderrBuilder = [System.Text.StringBuilder]::new()

    $stdoutEvent = Register-ObjectEvent -InputObject $process -EventName OutputDataReceived -Action {
        if ($null -ne $EventArgs.Data) {
            $Event.MessageData.AppendLine($EventArgs.Data) | Out-Null
        }
    } -MessageData $stdoutBuilder

    $stderrEvent = Register-ObjectEvent -InputObject $process -EventName ErrorDataReceived -Action {
        if ($null -ne $EventArgs.Data) {
            $Event.MessageData.AppendLine($EventArgs.Data) | Out-Null
        }
    } -MessageData $stderrBuilder

    try {
        $process.Start() | Out-Null
        $process.BeginOutputReadLine()
        $process.BeginErrorReadLine()

        if ($startInfo.RedirectStandardInput) {
            $process.StandardInput.WriteLine($StdinLine)
            $process.StandardInput.Close()
        }

        $exited = $process.WaitForExit($TimeoutSeconds * 1000)
        if (-not $exited) {
            try { $process.Kill() } catch {}
            throw "Process timed out after ${TimeoutSeconds}s: dotnet run --project `"$ProjectDir`" -- $Arguments"
        }

        # Allow async output events to flush
        $process.WaitForExit()
    }
    finally {
        Unregister-Event -SourceIdentifier $stdoutEvent.Name -ErrorAction SilentlyContinue
        Unregister-Event -SourceIdentifier $stderrEvent.Name -ErrorAction SilentlyContinue
        Remove-Job -Name $stdoutEvent.Name -Force -ErrorAction SilentlyContinue
        Remove-Job -Name $stderrEvent.Name -Force -ErrorAction SilentlyContinue
    }

    $stdout = $stdoutBuilder.ToString().Trim()
    $stderr = $stderrBuilder.ToString().Trim()
    $exitCode = $process.ExitCode
    $process.Dispose()

    if ($exitCode -ne 0) {
        $errorDetail = if ($stderr) { $stderr } elseif ($stdout) { $stdout } else { "Exit code $exitCode" }
        throw "Tool failed (exit code $exitCode): $errorDetail"
    }

    if (-not $ParseJson -or [string]::IsNullOrWhiteSpace($stdout)) {
        return $stdout
    }

    # Parse JSON from stdout, filtering out dotnet SDK noise lines.
    # The dotnet CLI sometimes emits build/restore messages before the tool output.
    $lines = $stdout -split "`n" | ForEach-Object { $_.Trim() } | Where-Object { $_ -ne "" }

    # Try parsing the entire output as JSON first (most common case)
    try {
        return ($stdout | ConvertFrom-Json)
    }
    catch {
        # Fall through to noise-stripped and line-by-line parsing
    }

    # Strip leading non-JSON noise lines and try again (handles multi-line JSON with prefix noise)
    $jsonStartIndex = -1
    for ($i = 0; $i -lt $lines.Count; $i++) {
        if ($lines[$i] -match '^\s*[\[\{"]') {
            $jsonStartIndex = $i
            break
        }
    }
    if ($jsonStartIndex -gt 0) {
        $jsonRegion = ($lines[$jsonStartIndex..($lines.Count - 1)]) -join "`n"
        try {
            return ($jsonRegion | ConvertFrom-Json)
        }
        catch {
            # Fall through to line-by-line parsing
        }
    }

    # Try each line — find the last valid JSON line (tools sometimes emit logs before JSON)
    $jsonResult = $null
    foreach ($line in $lines) {
        try {
            $jsonResult = $line | ConvertFrom-Json
        }
        catch {
            # Not JSON — skip (likely dotnet SDK output or Serilog log line)
        }
    }

    if ($null -ne $jsonResult) {
        return $jsonResult
    }

    # No JSON found — return raw string
    return $stdout
}

function Invoke-SgDnSafeguardApi {
    <#
    .SYNOPSIS
        Convenience wrapper for calling Safeguard API via SafeguardDotNetTool.

    .DESCRIPTION
        Builds the argument string for SafeguardDotNetTool and invokes it.
        Handles the common patterns: appliance, auth, service, method, URL, body.

    .PARAMETER Context
        Test context (from New-SgDnTestContext). If omitted, uses module-scoped context.

    .PARAMETER Service
        Safeguard service: Core, Appliance, Notification, A2A.

    .PARAMETER Method
        HTTP method: Get, Post, Put, Delete.

    .PARAMETER RelativeUrl
        API endpoint relative URL.

    .PARAMETER Body
        Optional request body. Hashtables are auto-converted to JSON with single-quote escaping.

    .PARAMETER Username
        Username for password auth. If omitted, uses context AdminUserName.

    .PARAMETER Password
        Password for auth. If omitted, uses context AdminPassword.

    .PARAMETER CertificateFile
        Path to PFX file for certificate auth (overrides username/password).

    .PARAMETER CertificatePassword
        Password for the PFX file.

    .PARAMETER CertificateAsData
        Load PFX as data buffer instead of file path.

    .PARAMETER Thumbprint
        Certificate thumbprint for cert store auth (overrides username/password and cert file).

    .PARAMETER Anonymous
        Use anonymous authentication (no credentials).

    .PARAMETER AccessToken
        Pre-obtained access token string for authentication (overrides all other auth).

    .PARAMETER Csv
        Request CSV format response.

    .PARAMETER Full
        Use InvokeMethodFull to get StatusCode, Headers, and Body envelope.

    .PARAMETER Headers
        Hashtable of additional HTTP headers to include in the request.

    .PARAMETER Parameters
        Hashtable of query parameters to include in the request URL.

    .PARAMETER File
        Path to a file for streaming operations. POST=upload from file, GET=download to file.

    .PARAMETER ParseJson
        Whether to parse the response as JSON. Default: $true.
    #>
    [CmdletBinding()]
    param(
        [Parameter()]
        [PSCustomObject]$Context,

        [Parameter(Mandatory)]
        [ValidateSet("Core", "Appliance", "Notification", "A2A")]
        [string]$Service,

        [Parameter(Mandatory)]
        [ValidateSet("Get", "Post", "Put", "Delete")]
        [string]$Method,

        [Parameter(Mandatory)]
        [string]$RelativeUrl,

        [Parameter()]
        $Body,

        [Parameter()]
        [string]$Username,

        [Parameter()]
        [string]$Password,

        [Parameter()]
        [string]$CertificateFile,

        [Parameter()]
        [string]$CertificatePassword,

        [Parameter()]
        [switch]$CertificateAsData,

        [Parameter()]
        [string]$Thumbprint,

        [Parameter()]
        [switch]$Anonymous,

        [Parameter()]
        [string]$AccessToken,

        [Parameter()]
        [switch]$Csv,

        [Parameter()]
        [switch]$Full,

        [Parameter()]
        [hashtable]$Headers,

        [Parameter()]
        [hashtable]$Parameters,

        [Parameter()]
        [string]$File,

        [Parameter()]
        [bool]$ParseJson = $true
    )

    if (-not $Context) { $Context = Get-SgDnTestContext }

    $toolArgs = "-a $($Context.Appliance) -x -s $Service -m $Method -U `"$RelativeUrl`""

    $stdinLine = $null

    if ($Anonymous) {
        $toolArgs += " -A"
    }
    elseif ($AccessToken) {
        $toolArgs += " -k `"$AccessToken`""
    }
    elseif ($Thumbprint) {
        $toolArgs += " -t $Thumbprint -p"
        # Thumbprint auth still needs a password for the cert (or empty)
        $stdinLine = if ($CertificatePassword) { $CertificatePassword } else { "" }
    }
    elseif ($CertificateFile) {
        $toolArgs += " -c `"$CertificateFile`" -p"
        if ($CertificateAsData) { $toolArgs += " -d" }
        $stdinLine = if ($CertificatePassword) { $CertificatePassword } else { "" }
    }
    else {
        $effectiveUser = if ($Username) { $Username } else { $Context.AdminUserName }
        $effectivePass = if ($Password) { $Password } else { $Context.AdminPassword }
        $toolArgs += " -u $effectiveUser -p"
        $stdinLine = $effectivePass
    }

    if ($Body) {
        $bodyStr = if ($Body -is [hashtable] -or $Body -is [System.Collections.IDictionary]) {
            (ConvertTo-Json -Depth 12 $Body -Compress).Replace('"', "'")
        }
        elseif ($Body -is [PSCustomObject]) {
            (ConvertTo-Json -Depth 12 $Body -Compress).Replace('"', "'")
        }
        else {
            [string]$Body
        }
        $toolArgs += " -b `"$bodyStr`""
    }

    if ($Csv) { $toolArgs += " -C" }
    if ($Full) { $toolArgs += " -f" }
    if ($File) { $toolArgs += " -F `"$File`"" }

    if ($Headers -and $Headers.Count -gt 0) {
        $headerPairs = ($Headers.GetEnumerator() | ForEach-Object { "$($_.Key)=$($_.Value)" }) -join ","
        $toolArgs += " -H `"$headerPairs`""
    }

    if ($Parameters -and $Parameters.Count -gt 0) {
        $paramPairs = ($Parameters.GetEnumerator() | ForEach-Object { "$($_.Key)=$($_.Value)" }) -join ","
        $toolArgs += " -P `"$paramPairs`""
    }

    Write-Verbose "Invoke-SgDnSafeguardApi: dotnet run -- $toolArgs"

    return Invoke-SgDnSafeguardTool -ProjectDir $Context.ToolDir -Arguments $toolArgs -StdinLine $stdinLine -ParseJson $ParseJson
}

function Invoke-SgDnTokenCommand {
    <#
    .SYNOPSIS
        Runs a token management command via SafeguardDotNetTool.

    .DESCRIPTION
        Connects to the appliance and performs token-related operations:
        TokenLifetime, RefreshToken, or Logout. Returns parsed JSON output.

    .PARAMETER Context
        Test context. If omitted, uses the module-scoped context.

    .PARAMETER Command
        Token command: 'TokenLifetime', 'RefreshToken', 'Logout', or 'GetToken'.
        - TokenLifetime: returns { TokenLifetimeRemaining: N }
        - RefreshToken: refreshes then returns { TokenLifetimeRemaining: N }
        - Logout: logs out and returns { AccessToken: "...", LoggedOut: true }
        - GetToken: returns { AccessToken: "..." } without logging out

    .PARAMETER Username
        Username for auth. If omitted, uses context AdminUserName.

    .PARAMETER Password
        Password for auth. If omitted, uses context AdminPassword.

    .EXAMPLE
        $result = Invoke-SgDnTokenCommand -Command TokenLifetime
        $result.TokenLifetimeRemaining  # e.g. 1440
    #>
    [CmdletBinding()]
    param(
        [Parameter()]
        [PSCustomObject]$Context,

        [Parameter(Mandatory)]
        [ValidateSet("TokenLifetime", "RefreshToken", "Logout", "GetToken")]
        [string]$Command,

        [Parameter()]
        [string]$Username,

        [Parameter()]
        [string]$Password
    )

    if (-not $Context) { $Context = Get-SgDnTestContext }

    $toolArgs = "-a $($Context.Appliance) -x"

    $effectiveUser = if ($Username) { $Username } else { $Context.AdminUserName }
    $effectivePass = if ($Password) { $Password } else { $Context.AdminPassword }
    $toolArgs += " -u $effectiveUser -p"

    switch ($Command) {
        "TokenLifetime" { $toolArgs += " -T" }
        "RefreshToken"  { $toolArgs += " -T -R" }
        "Logout"        { $toolArgs += " -L" }
        "GetToken"      { $toolArgs += " -G" }
    }

    return Invoke-SgDnSafeguardTool -ProjectDir $Context.ToolDir -Arguments $toolArgs -StdinLine $effectivePass -ParseJson $true
}

function Invoke-SgDnSafeguardA2a {
    <#
    .SYNOPSIS
        Convenience wrapper for calling SafeguardDotNetA2aTool.

    .DESCRIPTION
        Builds the argument string for the A2A tool and invokes it via
        Invoke-SgDnSafeguardTool. Supports certificate auth from file or store.

    .PARAMETER Context
        Test context. If omitted, uses the module-scoped context.

    .PARAMETER ApiKey
        The A2A API key for the retrievable account.

    .PARAMETER CertificateFile
        Path to a PFX file for certificate authentication.

    .PARAMETER CertificatePassword
        Password for the PFX file.

    .PARAMETER CertificateAsData
        Load the PFX as a data buffer instead of a file path.

    .PARAMETER Thumbprint
        Certificate thumbprint for cert store authentication.

    .PARAMETER RetrievableAccounts
        List retrievable accounts instead of retrieving a credential.

    .PARAMETER NewPassword
        Set a new password on the account.

    .PARAMETER PrivateKey
        Retrieve the SSH private key instead of a password.

    .PARAMETER ApiKeySecret
        Retrieve the API key secret instead of a password.

    .PARAMETER KeyFormat
        SSH key format: OpenSsh, Ssh2, or Putty.

    .PARAMETER ParseJson
        Whether to parse the response as JSON. Default: $true.

    .EXAMPLE
        Invoke-SgDnSafeguardA2a -ApiKey $key -CertificateFile $ctx.UserPfx `
            -CertificatePassword "a" -RetrievableAccounts
    #>
    [CmdletBinding()]
    param(
        [Parameter()]
        [PSCustomObject]$Context,

        [Parameter(Mandatory)]
        [string]$ApiKey,

        [Parameter()]
        [string]$CertificateFile,

        [Parameter()]
        [string]$CertificatePassword,

        [Parameter()]
        [switch]$CertificateAsData,

        [Parameter()]
        [string]$Thumbprint,

        [Parameter()]
        [switch]$RetrievableAccounts,

        [Parameter()]
        [string]$Filter,

        [Parameter()]
        [switch]$NewPassword,

        [Parameter()]
        [switch]$PrivateKey,

        [Parameter()]
        [switch]$ApiKeySecret,

        [Parameter()]
        [string]$KeyFormat,

        [Parameter()]
        [bool]$ParseJson = $true
    )

    if (-not $Context) { $Context = Get-SgDnTestContext }

    $toolArgs = "-a $($Context.Appliance) -x -A `"$ApiKey`""

    $stdinLine = $null

    if ($Thumbprint) {
        $toolArgs += " -t $Thumbprint -p"
        $stdinLine = if ($CertificatePassword) { $CertificatePassword } else { "" }
    }
    elseif ($CertificateFile) {
        $toolArgs += " -c `"$CertificateFile`" -p"
        if ($CertificateAsData) { $toolArgs += " -d" }
        $stdinLine = if ($CertificatePassword) { $CertificatePassword } else { "" }
    }

    if ($RetrievableAccounts) { $toolArgs += " -R" }
    if ($Filter) { $toolArgs += " -f `"$Filter`"" }
    if ($NewPassword) { $toolArgs += " -N" }
    if ($PrivateKey) { $toolArgs += " -K" }
    if ($ApiKeySecret) { $toolArgs += " -P" }
    if ($KeyFormat) { $toolArgs += " -F $KeyFormat" }

    Write-Verbose "Invoke-SgDnSafeguardA2a: dotnet run -- $toolArgs"

    return Invoke-SgDnSafeguardTool -ProjectDir $Context.A2aToolDir -Arguments $toolArgs -StdinLine $stdinLine -ParseJson $ParseJson
}

function Invoke-SgDnSafeguardA2aBroker {
    <#
    .SYNOPSIS
        Convenience wrapper for calling SafeguardDotNetAccessRequestBrokerTool.

    .DESCRIPTION
        Builds the argument string for the A2A access request broker tool and invokes it.
        Creates a brokered access request on behalf of another user.

    .PARAMETER Context
        Test context. If omitted, uses the module-scoped context.

    .PARAMETER ApiKey
        The A2A broker API key.

    .PARAMETER ForUser
        User ID or name to create the request for.

    .PARAMETER AccessType
        Access type: Password, Ssh, or Rdp.

    .PARAMETER Asset
        Asset ID or name.

    .PARAMETER Account
        Optional account ID or name.

    .PARAMETER CertificateFile
        Path to a PFX file for certificate authentication.

    .PARAMETER CertificatePassword
        Password for the PFX file.

    .PARAMETER Thumbprint
        Certificate thumbprint for cert store auth.

    .EXAMPLE
        Invoke-SgDnSafeguardA2aBroker -ApiKey $key -ForUser "testuser" -AccessType Password `
            -Asset "myasset" -CertificateFile $ctx.UserPfx -CertificatePassword "a"
    #>
    [CmdletBinding()]
    param(
        [Parameter()]
        [PSCustomObject]$Context,

        [Parameter(Mandatory)]
        [string]$ApiKey,

        [Parameter(Mandatory)]
        [string]$ForUser,

        [Parameter(Mandatory)]
        [ValidateSet("Password", "Ssh", "Rdp")]
        [string]$AccessType,

        [Parameter(Mandatory)]
        [string]$Asset,

        [Parameter()]
        [string]$Account,

        [Parameter()]
        [string]$CertificateFile,

        [Parameter()]
        [string]$CertificatePassword,

        [Parameter()]
        [string]$Thumbprint
    )

    if (-not $Context) { $Context = Get-SgDnTestContext }

    $toolArgs = "-a $($Context.Appliance) -x -A `"$ApiKey`" -U `"$ForUser`" -Y $AccessType -S `"$Asset`""

    if ($Account) { $toolArgs += " -C `"$Account`"" }

    $stdinLine = $null
    if ($Thumbprint) {
        $toolArgs += " -t $Thumbprint"
    }
    elseif ($CertificateFile) {
        $toolArgs += " -c `"$CertificateFile`" -p"
        $stdinLine = if ($CertificatePassword) { $CertificatePassword } else { "" }
    }

    return Invoke-SgDnSafeguardTool -ProjectDir $Context.AccessRequestBrokerToolDir -Arguments $toolArgs -StdinLine $stdinLine -ParseJson $true
}

function Invoke-SgDnSafeguardSessions {
    <#
    .SYNOPSIS
        Convenience wrapper for calling SafeguardSessionsDotNetTool.

    .DESCRIPTION
        Unlike the other tools, SafeguardSessionsDotNetTool takes the password as a
        command-line argument (-p) rather than reading from stdin.

    .PARAMETER Context
        Test context. If omitted, uses the module-scoped context.

    .PARAMETER Method
        HTTP method: Get, Post, Put, Delete, or Patch.

    .PARAMETER RelativeUrl
        SPS API endpoint relative URL.

    .PARAMETER Body
        Optional request body string.

    .PARAMETER Username
        SPS username. Defaults to the context SpsUser.

    .PARAMETER Password
        SPS password. Defaults to the context SpsPassword.

    .PARAMETER ParseJson
        Whether to parse the response as JSON. Default: $true.

    .EXAMPLE
        Invoke-SgDnSafeguardSessions -Method Get -RelativeUrl "firmware/slots"
    #>
    [CmdletBinding()]
    param(
        [Parameter()]
        [PSCustomObject]$Context,

        [Parameter(Mandatory)]
        [ValidateSet("Get", "Post", "Put", "Delete", "Patch")]
        [string]$Method,

        [Parameter(Mandatory)]
        [string]$RelativeUrl,

        [Parameter()]
        [string]$Body,

        [Parameter()]
        [string]$Username,

        [Parameter()]
        [string]$Password,

        [Parameter()]
        [bool]$ParseJson = $true
    )

    if (-not $Context) { $Context = Get-SgDnTestContext }

    $effectiveUser = if ($Username) { $Username } else { $Context.SpsUser }
    $effectivePass = if ($Password) { $Password } else { $Context.SpsPassword }

    $toolArgs = "-a $($Context.SpsAppliance) -k -u $effectiveUser -p $effectivePass -m $Method -U `"$RelativeUrl`""
    if ($Body) { $toolArgs += " -b `"$Body`"" }

    Write-Verbose "Invoke-SgDnSafeguardSessions: dotnet run -- $toolArgs"

    # Sessions tool does NOT read from stdin
    return Invoke-SgDnSafeguardTool -ProjectDir $Context.SessionsToolDir -Arguments $toolArgs -ParseJson $ParseJson
}

# ============================================================================
# Build Helpers
# ============================================================================

function Build-SgDnTestProjects {
    <#
    .SYNOPSIS
        Builds all test tool projects. Throws on build failure.

    .PARAMETER Context
        Test context. If omitted, uses the module-scoped context.

    .PARAMETER Projects
        Optional array of project directory paths to build. If omitted, builds all
        default test tool projects (SafeguardDotNetTool, ExceptionTest, A2aTool,
        AccessRequestBrokerTool, EventTool).

    .EXAMPLE
        Build-SgDnTestProjects -Context $ctx

    .EXAMPLE
        Build-SgDnTestProjects -Projects @($ctx.ToolDir, $ctx.A2aToolDir)
    #>
    [CmdletBinding()]
    param(
        [Parameter()]
        [PSCustomObject]$Context,

        [Parameter()]
        [string[]]$Projects
    )

    if (-not $Context) { $Context = Get-SgDnTestContext }

    $defaultProjects = @(
        $Context.ToolDir
        $Context.ExceptionTestDir
        $Context.A2aToolDir
        $Context.AccessRequestBrokerToolDir
        $Context.EventToolDir
        $Context.PkceToolDir
    )

    $toBuild = if ($Projects) { $Projects } else { $defaultProjects }

    foreach ($projectDir in $toBuild) {
        $projectName = Split-Path $projectDir -Leaf
        Write-Host "  Building $projectName..." -ForegroundColor DarkCyan
        $result = & dotnet build $projectDir --nologo --verbosity quiet 2>&1
        if ($LASTEXITCODE -ne 0) {
            throw "Build failed for $projectName`n$($result -join "`n")"
        }
    }
}

# ============================================================================
# Assertion Functions
# ============================================================================

function Test-SgDnAssert {
    <#
    .SYNOPSIS
        Records a named test result. Pass a scriptblock that returns $true/$false or throws.

    .DESCRIPTION
        Executes the scriptblock, records pass/fail/duration, and appends to the current
        suite's test results. A return value of $false or a thrown exception counts as failure.
        All other return values (including $null) count as pass.

    .PARAMETER Name
        Human-readable name for this test assertion.

    .PARAMETER Test
        ScriptBlock to evaluate. Return $true for pass, $false for fail, or throw for fail.

    .EXAMPLE
        Test-SgDnAssert "User can log in" { (Invoke-SgDnSafeguardApi ...).Name -eq "admin" }

    .EXAMPLE
        Test-SgDnAssert "API call succeeds" { Invoke-SgDnSafeguardApi -Service Core -Method Get -RelativeUrl "Me"; $true }
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory, Position = 0)]
        [string]$Name,

        [Parameter(Mandatory, Position = 1)]
        [scriptblock]$Test
    )

    $ctx = Get-SgDnTestContext
    $result = [PSCustomObject]@{
        Name      = $Name
        Status    = "Unknown"
        Message   = ""
        Duration  = [TimeSpan]::Zero
    }

    $sw = [System.Diagnostics.Stopwatch]::StartNew()
    try {
        $testResult = & $Test
        $sw.Stop()
        $result.Duration = $sw.Elapsed

        if ($testResult -eq $false) {
            $result.Status = "Fail"
            $result.Message = "Assertion returned `$false"
            Write-Host "    FAIL: $Name — Assertion returned `$false" -ForegroundColor Red
        }
        else {
            $result.Status = "Pass"
            Write-Host "    PASS: $Name" -ForegroundColor Green
        }
    }
    catch {
        $sw.Stop()
        $result.Duration = $sw.Elapsed
        $result.Status = "Fail"
        $result.Message = $_.Exception.Message
        Write-Host "    FAIL: $Name — $($_.Exception.Message)" -ForegroundColor Red
    }

    # Append to current suite's test results (stored temporarily on context)
    if (-not $ctx.SuiteData.ContainsKey('_TestResults')) {
        $ctx.SuiteData['_TestResults'] = [System.Collections.Generic.List[PSCustomObject]]::new()
    }
    $ctx.SuiteData['_TestResults'].Add($result)
}

function Test-SgDnAssertEqual {
    <#
    .SYNOPSIS
        Asserts two values are equal.

    .PARAMETER Name
        Human-readable name for this test assertion.

    .PARAMETER Expected
        The expected value.

    .PARAMETER Actual
        The actual value to compare against Expected.

    .EXAMPLE
        Test-SgDnAssertEqual "Status is active" "Active" $user.Status
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory, Position = 0)]
        [string]$Name,

        [Parameter(Mandatory, Position = 1)]
        $Expected,

        [Parameter(Mandatory, Position = 2)]
        $Actual
    )

    Test-SgDnAssert $Name {
        if ($Expected -ne $Actual) {
            throw "Expected '$Expected' but got '$Actual'"
        }
        $true
    }
}

function Test-SgDnAssertNotNull {
    <#
    .SYNOPSIS
        Asserts a value is not null or empty.

    .PARAMETER Name
        Human-readable name for this test assertion.

    .PARAMETER Value
        The value to check for null or empty.

    .EXAMPLE
        Test-SgDnAssertNotNull "User ID is set" $user.Id
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory, Position = 0)]
        [string]$Name,

        [Parameter(Position = 1)]
        $Value
    )

    Test-SgDnAssert $Name {
        if ($null -eq $Value -or ($Value -is [string] -and [string]::IsNullOrWhiteSpace($Value))) {
            throw "Value was null or empty"
        }
        $true
    }
}

function Test-SgDnAssertContains {
    <#
    .SYNOPSIS
        Asserts a string contains a substring, or a collection contains an element.

    .PARAMETER Name
        Human-readable name for this test assertion.

    .PARAMETER Haystack
        The string or collection to search in.

    .PARAMETER Needle
        The substring or element to search for.

    .EXAMPLE
        Test-SgDnAssertContains "Has admin role" $user.AdminRoles "GlobalAdmin"

    .EXAMPLE
        Test-SgDnAssertContains "Error mentions auth" $errorMsg "authentication"
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory, Position = 0)]
        [string]$Name,

        [Parameter(Mandatory, Position = 1)]
        $Haystack,

        [Parameter(Mandatory, Position = 2)]
        $Needle
    )

    Test-SgDnAssert $Name {
        if ($Haystack -is [string]) {
            if (-not $Haystack.Contains($Needle)) {
                throw "String does not contain '$Needle'"
            }
        }
        elseif ($Haystack -is [System.Collections.IEnumerable]) {
            if ($Needle -notin $Haystack) {
                throw "Collection does not contain '$Needle'"
            }
        }
        else {
            throw "Unsupported haystack type: $($Haystack.GetType().Name)"
        }
        $true
    }
}

function Test-SgDnAssertThrows {
    <#
    .SYNOPSIS
        Asserts that a scriptblock throws an exception.

    .PARAMETER Name
        Human-readable name for this test assertion.

    .PARAMETER Action
        ScriptBlock expected to throw an exception.

    .PARAMETER ExpectedMessage
        Optional substring that the exception message must contain.

    .EXAMPLE
        Test-SgDnAssertThrows "Bad endpoint throws" { Invoke-SgDnSafeguardApi -Service Core -Method Get -RelativeUrl "NonExistent" }

    .EXAMPLE
        Test-SgDnAssertThrows "Auth failure message" -ExpectedMessage "unauthorized" { Invoke-SgDnSafeguardApi ... }
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory, Position = 0)]
        [string]$Name,

        [Parameter(Mandatory, Position = 1)]
        [scriptblock]$Action,

        [Parameter()]
        [string]$ExpectedMessage
    )

    Test-SgDnAssert $Name {
        $threw = $false
        try {
            & $Action
        }
        catch {
            $threw = $true
            if ($ExpectedMessage -and $_.Exception.Message -notlike "*$ExpectedMessage*") {
                throw "Expected exception containing '$ExpectedMessage' but got: $($_.Exception.Message)"
            }
        }
        if (-not $threw) {
            throw "Expected an exception but none was thrown"
        }
        $true
    }
}

function Test-SgDnSkip {
    <#
    .SYNOPSIS
        Records a named test as skipped with a reason.

    .PARAMETER Name
        Human-readable name for the skipped test.

    .PARAMETER Reason
        Explanation of why the test was skipped.

    .EXAMPLE
        Test-SgDnSkip "Computer cert store auth" "Requires elevation"
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory, Position = 0)]
        [string]$Name,

        [Parameter(Mandatory, Position = 1)]
        [string]$Reason
    )

    $ctx = Get-SgDnTestContext
    $result = [PSCustomObject]@{
        Name     = $Name
        Status   = "Skip"
        Message  = $Reason
        Duration = [TimeSpan]::Zero
    }

    Write-Host "    SKIP: $Name — $Reason" -ForegroundColor Yellow

    if (-not $ctx.SuiteData.ContainsKey('_TestResults')) {
        $ctx.SuiteData['_TestResults'] = [System.Collections.Generic.List[PSCustomObject]]::new()
    }
    $ctx.SuiteData['_TestResults'].Add($result)
}

# ============================================================================
# Suite Execution
# ============================================================================

function Invoke-SgDnTestSuite {
    <#
    .SYNOPSIS
        Runs a single test suite through Setup → Execute → Cleanup.

    .DESCRIPTION
        Loads a suite definition file, resets per-suite state, then runs Setup, Execute,
        and Cleanup phases. Setup failures skip Execute but Cleanup always runs.
        Results are appended to the context's SuiteResults collection.

    .PARAMETER SuiteFile
        Full path to the Suite-*.ps1 file to run.

    .PARAMETER Context
        Test context. If omitted, uses the module-scoped context.

    .EXAMPLE
        Invoke-SgDnTestSuite -SuiteFile "C:\Tests\Suites\Suite-PasswordAuth.ps1" -Context $ctx
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$SuiteFile,

        [Parameter()]
        [PSCustomObject]$Context
    )

    if (-not $Context) { $Context = Get-SgDnTestContext }

    # Load suite definition
    $suite = & $SuiteFile
    if (-not $suite -or -not $suite.Name) {
        Write-Host "  ERROR: Invalid suite file: $SuiteFile" -ForegroundColor Red
        return
    }

    $suiteName = $suite.Name
    Write-Host ""
    Write-Host "═══════════════════════════════════════════════════════" -ForegroundColor Cyan
    Write-Host "  Suite: $suiteName" -ForegroundColor Cyan
    if ($suite.Description) {
        Write-Host "  $($suite.Description)" -ForegroundColor DarkCyan
    }
    Write-Host "═══════════════════════════════════════════════════════" -ForegroundColor Cyan

    # Reset per-suite state
    $Context.SuiteData = @{}
    $Context.SuiteData['_TestResults'] = [System.Collections.Generic.List[PSCustomObject]]::new()
    $Context.CleanupActions = [System.Collections.Generic.Stack[PSCustomObject]]::new()

    $suiteResult = [PSCustomObject]@{
        Name         = $suiteName
        SetupError   = $null
        ExecuteError = $null
        CleanupError = $null
        Tests        = [System.Collections.Generic.List[PSCustomObject]]::new()
        Duration     = [TimeSpan]::Zero
    }

    $suiteSw = [System.Diagnostics.Stopwatch]::StartNew()

    # --- Setup ---
    if ($suite.Setup) {
        Write-Host "  [Setup]" -ForegroundColor DarkGray
        try {
            & $suite.Setup $Context
        }
        catch {
            $suiteResult.SetupError = $_.Exception.Message
            Write-Host "  SETUP FAILED: $($_.Exception.Message)" -ForegroundColor Red
        }
    }

    # --- Execute (only if setup succeeded) ---
    if (-not $suiteResult.SetupError -and $suite.Execute) {
        Write-Host "  [Execute]" -ForegroundColor DarkGray
        try {
            & $suite.Execute $Context
        }
        catch {
            $suiteResult.ExecuteError = $_.Exception.Message
            Write-Host "  EXECUTE ERROR: $($_.Exception.Message)" -ForegroundColor Red
        }
    }
    elseif ($suiteResult.SetupError) {
        Write-Host "  [Execute] Skipped due to setup failure" -ForegroundColor Yellow
    }

    # --- Cleanup (always runs) ---
    Write-Host "  [Cleanup]" -ForegroundColor DarkGray
    try {
        if ($suite.Cleanup) {
            & $suite.Cleanup $Context
        }
    }
    catch {
        $suiteResult.CleanupError = $_.Exception.Message
        Write-Host "  CLEANUP ERROR: $($_.Exception.Message)" -ForegroundColor DarkYellow
    }
    # Run registered cleanup actions regardless
    Invoke-SgDnTestCleanup -Context $Context

    $suiteSw.Stop()
    $suiteResult.Duration = $suiteSw.Elapsed

    # Collect test results from this suite
    if ($Context.SuiteData.ContainsKey('_TestResults')) {
        foreach ($tr in $Context.SuiteData['_TestResults']) {
            $suiteResult.Tests.Add($tr)
        }
    }

    # If setup failed and no tests were recorded, add a synthetic failure
    if ($suiteResult.SetupError -and $suiteResult.Tests.Count -eq 0) {
        $suiteResult.Tests.Add([PSCustomObject]@{
            Name     = "Suite Setup"
            Status   = "Fail"
            Message  = "Setup failed: $($suiteResult.SetupError)"
            Duration = [TimeSpan]::Zero
        })
    }

    $pass = ($suiteResult.Tests | Where-Object Status -eq "Pass").Count
    $fail = ($suiteResult.Tests | Where-Object Status -eq "Fail").Count
    $skip = ($suiteResult.Tests | Where-Object Status -eq "Skip").Count
    $statusColor = if ($fail -gt 0) { "Red" } elseif ($skip -gt 0) { "Yellow" } else { "Green" }
    Write-Host "  Result: $pass passed, $fail failed, $skip skipped ($([math]::Round($suiteResult.Duration.TotalSeconds, 1))s)" -ForegroundColor $statusColor
    Write-Host ""

    $Context.SuiteResults.Add($suiteResult)
}

# ============================================================================
# Reporting
# ============================================================================

function Write-SgDnTestReport {
    <#
    .SYNOPSIS
        Writes a formatted test report to the console.

    .DESCRIPTION
        Prints a summary table of all suite results with pass/fail/skip counts,
        overall pass rate, and a detailed list of failures.

    .PARAMETER Context
        Test context. If omitted, uses the module-scoped context.

    .OUTPUTS
        Returns the total number of failed tests (int) for use as exit code.

    .EXAMPLE
        $failCount = Write-SgDnTestReport -Context $ctx
    #>
    [CmdletBinding()]
    param(
        [Parameter()]
        [PSCustomObject]$Context
    )

    if (-not $Context) { $Context = Get-SgDnTestContext }

    $totalDuration = [DateTime]::UtcNow - $Context.StartTime

    Write-Host ""
    Write-Host ("=" * 66) -ForegroundColor Cyan
    Write-Host "  SafeguardDotNet Test Report" -ForegroundColor Cyan
    Write-Host ("=" * 66) -ForegroundColor Cyan
    Write-Host "  Appliance: $($Context.Appliance)" -ForegroundColor White
    Write-Host "  Duration:  $([math]::Floor($totalDuration.TotalMinutes))m $($totalDuration.Seconds)s" -ForegroundColor White
    Write-Host ("-" * 66) -ForegroundColor DarkGray

    $totalPass = 0
    $totalFail = 0
    $totalSkip = 0

    # Suite summary table
    $headerFmt = "  {0,-36} {1,5} {2,5} {3,5} {4,6}"
    Write-Host ($headerFmt -f "Suite", "Pass", "Fail", "Skip", "Total") -ForegroundColor White
    Write-Host ("-" * 66) -ForegroundColor DarkGray

    foreach ($suite in $Context.SuiteResults) {
        $pass = ($suite.Tests | Where-Object Status -eq "Pass").Count
        $fail = ($suite.Tests | Where-Object Status -eq "Fail").Count
        $skip = ($suite.Tests | Where-Object Status -eq "Skip").Count
        $total = $suite.Tests.Count

        $totalPass += $pass
        $totalFail += $fail
        $totalSkip += $skip

        $color = if ($fail -gt 0) { "Red" } elseif ($skip -gt 0) { "Yellow" } else { "Green" }
        Write-Host ($headerFmt -f $suite.Name, $pass, $fail, $skip, $total) -ForegroundColor $color
    }

    $grandTotal = $totalPass + $totalFail + $totalSkip
    Write-Host ("-" * 66) -ForegroundColor DarkGray
    Write-Host ($headerFmt -f "TOTAL", $totalPass, $totalFail, $totalSkip, $grandTotal) -ForegroundColor White

    if ($grandTotal -gt 0) {
        $passRate = [math]::Round(($totalPass / $grandTotal) * 100, 1)
        $execTotal = $totalPass + $totalFail
        $execPassRate = if ($execTotal -gt 0) { [math]::Round(($totalPass / $execTotal) * 100, 1) } else { 0 }
        Write-Host "  Pass Rate: ${passRate}%    (excluding skipped: ${execPassRate}%)" -ForegroundColor White
    }

    # List failures
    $failures = foreach ($suite in $Context.SuiteResults) {
        foreach ($test in $suite.Tests) {
            if ($test.Status -eq "Fail") {
                [PSCustomObject]@{
                    Suite   = $suite.Name
                    Test    = $test.Name
                    Message = $test.Message
                }
            }
        }
    }

    if ($failures) {
        Write-Host ""
        Write-Host ("-" * 66) -ForegroundColor DarkGray
        Write-Host "  FAILURES:" -ForegroundColor Red
        foreach ($f in $failures) {
            Write-Host "    [$($f.Suite)] $($f.Test)" -ForegroundColor Red
            if ($f.Message) {
                Write-Host "      $($f.Message)" -ForegroundColor DarkRed
            }
        }
    }

    Write-Host ("=" * 66) -ForegroundColor Cyan
    Write-Host ""

    return $totalFail
}

function Export-SgDnTestReport {
    <#
    .SYNOPSIS
        Exports test results to a JSON file for CI integration.

    .PARAMETER OutputPath
        File path to write the JSON report to.

    .PARAMETER Context
        Test context. If omitted, uses the module-scoped context.

    .EXAMPLE
        Export-SgDnTestReport -OutputPath "C:\results\test-report.json" -Context $ctx
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$OutputPath,

        [Parameter()]
        [PSCustomObject]$Context
    )

    if (-not $Context) { $Context = Get-SgDnTestContext }

    $report = [PSCustomObject]@{
        Appliance = $Context.Appliance
        StartTime = $Context.StartTime.ToString("o")
        EndTime   = [DateTime]::UtcNow.ToString("o")
        Suites    = foreach ($suite in $Context.SuiteResults) {
            [PSCustomObject]@{
                Name       = $suite.Name
                DurationMs = [math]::Round($suite.Duration.TotalMilliseconds)
                SetupError = $suite.SetupError
                Tests      = foreach ($test in $suite.Tests) {
                    [PSCustomObject]@{
                        Name       = $test.Name
                        Status     = $test.Status
                        Message    = $test.Message
                        DurationMs = [math]::Round($test.Duration.TotalMilliseconds)
                    }
                }
            }
        }
        Summary = [PSCustomObject]@{
            TotalPass = ($Context.SuiteResults | ForEach-Object { ($_.Tests | Where-Object Status -eq "Pass").Count } | Measure-Object -Sum).Sum
            TotalFail = ($Context.SuiteResults | ForEach-Object { ($_.Tests | Where-Object Status -eq "Fail").Count } | Measure-Object -Sum).Sum
            TotalSkip = ($Context.SuiteResults | ForEach-Object { ($_.Tests | Where-Object Status -eq "Skip").Count } | Measure-Object -Sum).Sum
        }
    }

    $report | ConvertTo-Json -Depth 10 | Set-Content -Path $OutputPath -Encoding UTF8
    Write-Host "Test report exported to: $OutputPath" -ForegroundColor DarkCyan
}

# ============================================================================
# Safeguard Object Helpers
# ============================================================================

function Remove-SgDnSafeguardTestObject {
    <#
    .SYNOPSIS
        Idempotent delete — removes an object if it exists, silently ignores if not found.

    .PARAMETER Context
        Test context (required).

    .PARAMETER RelativeUrl
        API endpoint for the DELETE call (e.g., "Users/123").

    .PARAMETER Username
        Optional username override for authentication.

    .PARAMETER Password
        Optional password override for authentication.

    .EXAMPLE
        Remove-SgDnSafeguardTestObject -Context $ctx -RelativeUrl "Users/$userId"
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [PSCustomObject]$Context,

        [Parameter(Mandatory)]
        [string]$RelativeUrl,

        [Parameter()]
        [string]$Username,

        [Parameter()]
        [string]$Password
    )

    $params = @{
        Context     = $Context
        Service     = "Core"
        Method      = "Delete"
        RelativeUrl = $RelativeUrl
        ParseJson   = $false
    }
    if ($Username) { $params.Username = $Username }
    if ($Password) { $params.Password = $Password }

    try {
        Invoke-SgDnSafeguardApi @params | Out-Null
    }
    catch {
        # Silently ignore — object may not exist
    }
}

function Remove-SgDnStaleTestObject {
    <#
    .SYNOPSIS
        Finds and deletes a Safeguard object by Name filter. Used for pre-cleanup of stale objects.

    .DESCRIPTION
        Queries the specified collection for objects whose Name matches the given value,
        then deletes each match. Errors are silently ignored — this is best-effort cleanup
        for objects left behind by previous failed test runs.

    .PARAMETER Context
        Test context (required).

    .PARAMETER Collection
        The API collection to search (e.g., "Users", "Assets", "AssetAccounts", "Roles",
        "AccessPolicies", "A2ARegistrations").

    .PARAMETER Name
        The exact Name value to search for.

    .PARAMETER NameField
        The API field name to filter on. Defaults to "Name". Use "AppName" for
        A2ARegistrations, which use AppName instead of Name.

    .PARAMETER Username
        Optional username override for authentication.

    .PARAMETER Password
        Optional password override for authentication.

    .EXAMPLE
        Remove-SgDnStaleTestObject -Context $ctx -Collection "Users" -Name "SgDnTest_A2aAdmin"

    .EXAMPLE
        Remove-SgDnStaleTestObject -Context $ctx -Collection "A2ARegistrations" -Name "SgDnTest_A2aReg" -NameField "AppName"
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [PSCustomObject]$Context,

        [Parameter(Mandatory)]
        [string]$Collection,

        [Parameter(Mandatory)]
        [string]$Name,

        [Parameter()]
        [string]$NameField = "Name",

        [Parameter()]
        [string]$Username,

        [Parameter()]
        [string]$Password
    )

    try {
        Write-Host "      Checking $Collection for '$Name'..." -ForegroundColor DarkGray
        $filterParams = @{
            Context     = $Context
            Service     = "Core"
            Method      = "Get"
            RelativeUrl = "${Collection}?filter=${NameField} eq '${Name}'"
        }
        if ($Username) { $filterParams.Username = $Username }
        if ($Password) { $filterParams.Password = $Password }

        $existing = Invoke-SgDnSafeguardApi @filterParams
        if ($existing) {
            $items = @($existing)
            foreach ($item in $items) {
                if ($item.Id) {
                    Write-Host "      Removing stale $Collection '$Name' (Id=$($item.Id))" -ForegroundColor DarkGray
                    Remove-SgDnSafeguardTestObject -Context $Context `
                        -RelativeUrl "${Collection}/$($item.Id)" `
                        -Username:$Username -Password:$Password
                }
            }
        }
    }
    catch {
        # Silently ignore — best-effort pre-cleanup
    }
}

function Remove-SgDnStaleTestCert {
    <#
    .SYNOPSIS
        Finds and deletes a trusted certificate by thumbprint. Used for pre-cleanup.

    .DESCRIPTION
        Queries TrustedCertificates for certificates matching the given thumbprint,
        then deletes each match. Errors are silently ignored.

    .PARAMETER Context
        Test context (required).

    .PARAMETER Thumbprint
        The certificate thumbprint to search for.

    .PARAMETER Username
        Optional username override for authentication.

    .PARAMETER Password
        Optional password override for authentication.

    .EXAMPLE
        Remove-SgDnStaleTestCert -Context $ctx -Thumbprint "ABC123..."
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [PSCustomObject]$Context,

        [Parameter(Mandatory)]
        [string]$Thumbprint,

        [Parameter()]
        [string]$Username,

        [Parameter()]
        [string]$Password
    )

    try {
        Write-Host "      Checking TrustedCertificates for thumbprint $($Thumbprint.Substring(0, [Math]::Min(8, $Thumbprint.Length)))..." -ForegroundColor DarkGray
        $filterParams = @{
            Context     = $Context
            Service     = "Core"
            Method      = "Get"
            RelativeUrl = "TrustedCertificates?filter=Thumbprint ieq '${Thumbprint}'"
        }
        if ($Username) { $filterParams.Username = $Username }
        if ($Password) { $filterParams.Password = $Password }

        $existing = Invoke-SgDnSafeguardApi @filterParams
        if ($existing) {
            $items = @($existing)
            foreach ($item in $items) {
                if ($item.Id) {
                    Write-Host "      Removing stale TrustedCertificate (Id=$($item.Id))" -ForegroundColor DarkGray
                    Remove-SgDnSafeguardTestObject -Context $Context `
                        -RelativeUrl "TrustedCertificates/$($item.Id)" `
                        -Username:$Username -Password:$Password
                }
            }
        }
    }
    catch {
        # Silently ignore — best-effort pre-cleanup
    }
}

function Test-SgDnSpsConfigured {
    <#
    .SYNOPSIS
        Returns $true if SPS connection parameters are configured.

    .PARAMETER Context
        Test context. If omitted, uses the module-scoped context.

    .EXAMPLE
        if (Test-SgDnSpsConfigured) { Invoke-SgDnSafeguardSessions -Method Get -RelativeUrl "firmware/slots" }
    #>
    [CmdletBinding()]
    param(
        [Parameter()]
        [PSCustomObject]$Context
    )

    if (-not $Context) { $Context = Get-SgDnTestContext }
    return ($Context.SpsAppliance -and $Context.SpsUser -and $Context.SpsPassword)
}

function Test-SgDnIsElevated {
    <#
    .SYNOPSIS
        Returns $true if the current process is running elevated (admin).
    #>
    if ($IsWindows -or $env:OS -eq "Windows_NT") {
        $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
        $principal = [Security.Principal.WindowsPrincipal]::new($identity)
        return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    }
    else {
        return (id -u) -eq 0
    }
}

function Clear-SgDnStaleTestEnvironment {
    <#
    .SYNOPSIS
        Removes all stale test objects from the appliance before a test run.

    .DESCRIPTION
        Creates a temporary admin user with full rights, then searches for and deletes
        all objects created by previous test runs (identified by the TestPrefix) in the
        correct dependency order. This handles cross-suite contamination.

        This function is best-effort — individual deletion errors are silently ignored.

    .PARAMETER Context
        Test context (required).

    .EXAMPLE
        Clear-SgDnStaleTestEnvironment -Context $ctx
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [PSCustomObject]$Context
    )

    $prefix = $Context.TestPrefix
    $cleanupAdmin = "${prefix}_CleanupAdmin"
    $cleanupPassword = "Cleanup8392!xyzABC"
    Write-Host "  Checking for stale test objects (prefix: ${prefix})..." -ForegroundColor DarkGray

    # Create a temporary admin with full rights for cleanup operations
    $adminId = $null
    try {
        # First remove any stale cleanup admin from a previous failed cleanup
        Remove-SgDnStaleTestObject -Context $Context -Collection "Users" -Name $cleanupAdmin

        $admin = Invoke-SgDnSafeguardApi -Context $Context -Service Core -Method Post `
            -RelativeUrl "Users" -Body @{
                PrimaryAuthenticationProvider = @{ Id = -1 }
                Name = $cleanupAdmin
                AdminRoles = @('GlobalAdmin','Auditor','AssetAdmin','ApplianceAdmin','PolicyAdmin','UserAdmin','HelpdeskAdmin','OperationsAdmin')
            }
        $adminId = $admin.Id
        Invoke-SgDnSafeguardApi -Context $Context -Service Core -Method Put `
            -RelativeUrl "Users/$adminId/Password" -Body "'$cleanupPassword'" -ParseJson $false
    }
    catch {
        Write-Host "  Could not create cleanup admin — skipping pre-cleanup." -ForegroundColor DarkYellow
        return
    }

    $foundAny = $false

    # Delete in dependency order: policies → roles → A2A registrations → accounts → assets → users → certs
    $collections = @(
        @{ Collection = "AccessPolicies"; NameField = "Name" },
        @{ Collection = "Roles"; NameField = "Name" },
        @{ Collection = "A2ARegistrations"; NameField = "AppName" },
        @{ Collection = "AssetAccounts"; NameField = "Name" },
        @{ Collection = "Assets"; NameField = "Name" }
    )

    foreach ($col in $collections) {
        try {
            $items = Invoke-SgDnSafeguardApi -Context $Context -Service Core -Method Get `
                -RelativeUrl "$($col.Collection)?filter=$($col.NameField) contains '${prefix}'" `
                -Username $cleanupAdmin -Password $cleanupPassword
            $list = @($items)
            foreach ($item in $list) {
                if ($item.Id) {
                    if (-not $foundAny) {
                        $foundAny = $true
                        Write-Host "  Found stale test objects — removing..." -ForegroundColor Yellow
                    }
                    $displayName = if ($item.Name) { $item.Name } elseif ($item.AppName) { $item.AppName } else { "Id=$($item.Id)" }
                    Write-Host "    Deleting $($col.Collection): $displayName" -ForegroundColor DarkYellow
                    Remove-SgDnSafeguardTestObject -Context $Context `
                        -RelativeUrl "$($col.Collection)/$($item.Id)" `
                        -Username $cleanupAdmin -Password $cleanupPassword
                }
            }
        }
        catch {
            # Silently ignore — best-effort
        }
    }

    # Delete stale test users (excluding the cleanup admin itself)
    try {
        $staleUsers = Invoke-SgDnSafeguardApi -Context $Context -Service Core -Method Get `
            -RelativeUrl "Users?filter=Name contains '${prefix}'"
        $list = @($staleUsers)
        foreach ($user in $list) {
            if ($user.Id -and $user.Id -ne $adminId) {
                if (-not $foundAny) {
                    $foundAny = $true
                    Write-Host "  Found stale test objects — removing..." -ForegroundColor Yellow
                }
                Write-Host "    Deleting user: $($user.Name) (Id=$($user.Id))" -ForegroundColor DarkYellow
                Remove-SgDnSafeguardTestObject -Context $Context `
                    -RelativeUrl "Users/$($user.Id)" `
                    -Username $cleanupAdmin -Password $cleanupPassword
            }
        }
    }
    catch {
        # Silently ignore
    }

    # Delete stale trusted certificates by test cert thumbprints
    $certPaths = @($Context.RootCert, $Context.CaCert)
    foreach ($certPath in $certPaths) {
        if (-not $certPath -or -not (Test-Path $certPath)) { continue }
        try {
            $thumbprint = (Get-PfxCertificate $certPath).Thumbprint
            Remove-SgDnStaleTestCert -Context $Context -Thumbprint $thumbprint `
                -Username $cleanupAdmin -Password $cleanupPassword
        }
        catch {
            # Silently ignore
        }
    }

    # Clean up local cert store entries from test certificates
    if ($Context.UserCert -and (Test-Path $Context.UserCert)) {
        try {
            $tp = (Get-PfxCertificate $Context.UserCert).Thumbprint
            if ($tp -and (Test-Path "Cert:\CurrentUser\My\$tp")) {
                Write-Host "    Removing stale cert from user store" -ForegroundColor DarkYellow
                Remove-Item "Cert:\CurrentUser\My\$tp" -ErrorAction SilentlyContinue
            }
        }
        catch {
            # Silently ignore
        }
    }

    # Delete the cleanup admin
    try {
        Remove-SgDnSafeguardTestObject -Context $Context -RelativeUrl "Users/$adminId"
    }
    catch {
        # Silently ignore
    }

    if (-not $foundAny) {
        Write-Host "  No stale objects found." -ForegroundColor DarkGray
    }
    Write-Host "  Pre-cleanup complete." -ForegroundColor DarkGray
}

# ============================================================================
# A2A Service Test Helpers
# ============================================================================

function Get-SgDnA2aServiceEnabled {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [PSCustomObject]$Context,

        [Parameter()]
        [string]$Username,

        [Parameter()]
        [string]$Password
    )

    $status = Invoke-SgDnSafeguardApi -Context $Context -Service Appliance -Method Get `
        -RelativeUrl "A2AService/Status" -Username $Username -Password $Password
    return (($status.IsRunning -eq $true) -or ($status.IsEnabled -eq $true) -or ($status.Enabled -eq $true))
}

function Enable-SgDnA2aServiceForSuite {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [PSCustomObject]$Context,

        [Parameter()]
        [string]$Username,

        [Parameter()]
        [string]$Password
    )

    $wasEnabled = Get-SgDnA2aServiceEnabled -Context $Context -Username $Username -Password $Password
    $Context.SuiteData["A2aWasEnabled"] = $wasEnabled
    $Context.SuiteData["A2aSuiteSetEnabled"] = $false

    if (-not $wasEnabled) {
        Invoke-SgDnSafeguardApi -Context $Context -Service Appliance -Method Post `
            -RelativeUrl "A2AService/Enable" -Username $Username -Password $Password -ParseJson $false
        $Context.SuiteData["A2aSuiteSetEnabled"] = $true
        Start-Sleep -Seconds 2
    }
}

function Restore-SgDnA2aServiceForSuite {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [PSCustomObject]$Context,

        [Parameter()]
        [string]$Username,

        [Parameter()]
        [string]$Password
    )

    if ($Context.SuiteData["A2aSuiteSetEnabled"]) {
        try {
            Invoke-SgDnSafeguardApi -Context $Context -Service Appliance -Method Post `
                -RelativeUrl "A2AService/Disable" -Username $Username -Password $Password -ParseJson $false
            Start-Sleep -Seconds 1
        }
        finally {
            $enabled = Get-SgDnA2aServiceEnabled -Context $Context -Username $Username -Password $Password
            Test-SgDnAssert "A2A service restored to disabled state" { -not $enabled }
        }
    }
}

# ============================================================================
# Module Exports
# ============================================================================

Export-ModuleMember -Function @(
    # Context
    'New-SgDnTestContext'
    'Get-SgDnTestContext'

    # Cleanup
    'Register-SgDnTestCleanup'
    'Invoke-SgDnTestCleanup'

    # Tool invocation
    'Invoke-SgDnSafeguardTool'
    'Invoke-SgDnSafeguardApi'
    'Invoke-SgDnTokenCommand'
    'Invoke-SgDnSafeguardA2a'
    'Invoke-SgDnSafeguardA2aBroker'
    'Invoke-SgDnSafeguardSessions'
    'Build-SgDnTestProjects'

    # Assertions
    'Test-SgDnAssert'
    'Test-SgDnAssertEqual'
    'Test-SgDnAssertNotNull'
    'Test-SgDnAssertContains'
    'Test-SgDnAssertThrows'
    'Test-SgDnSkip'

    # Suite execution
    'Invoke-SgDnTestSuite'

    # Reporting
    'Write-SgDnTestReport'
    'Export-SgDnTestReport'

    # Helpers
    'Get-SgDnA2aServiceEnabled'
    'Enable-SgDnA2aServiceForSuite'
    'Restore-SgDnA2aServiceForSuite'
    'Remove-SgDnSafeguardTestObject'
    'Remove-SgDnStaleTestObject'
    'Remove-SgDnStaleTestCert'
    'Clear-SgDnStaleTestEnvironment'
    'Test-SgDnSpsConfigured'
    'Test-SgDnIsElevated'
)
