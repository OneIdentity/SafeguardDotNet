@{
    Name        = "A2A Event Listeners"
    Description = "Tests A2A SignalR event listener connection and password change notification"
    Tags        = @("a2a", "events", "signalr")

    Setup = {
        param($Context)

        $prefix = $Context.TestPrefix
        $adminUser = "${prefix}_A2aEvtAdmin"
        $adminPassword = "2309aseflkasdlf209349qauerA"
        $certUser = "${prefix}_A2aEvtCertUser"

        # Compute thumbprints
        Write-Host "    Computing certificate thumbprints..." -ForegroundColor DarkGray
        $userThumbprint = (Get-PfxCertificate $Context.UserCert).Thumbprint
        $rootThumbprint = (Get-PfxCertificate $Context.RootCert).Thumbprint
        $caThumbprint   = (Get-PfxCertificate $Context.CaCert).Thumbprint

        # Pre-cleanup: remove stale objects from previous failed runs (reverse dependency order)
        Write-Host "    Removing stale objects from previous runs..." -ForegroundColor DarkGray
        Remove-SgDnStaleTestObject -Context $Context -Collection "A2ARegistrations" -Name "${prefix}_A2aEvtReg" -NameField "AppName"
        Remove-SgDnStaleTestObject -Context $Context -Collection "AssetAccounts" -Name "${prefix}_A2aEvtAccount"
        Remove-SgDnStaleTestObject -Context $Context -Collection "Assets" -Name "${prefix}_A2aEvtAsset"
        Remove-SgDnStaleTestObject -Context $Context -Collection "Users" -Name $certUser
        Remove-SgDnStaleTestCert -Context $Context -Thumbprint $caThumbprint
        Remove-SgDnStaleTestCert -Context $Context -Thumbprint $rootThumbprint
        Remove-SgDnStaleTestObject -Context $Context -Collection "Users" -Name $adminUser

        # 1. Create admin user
        Write-Host "    Creating admin user '$adminUser'..." -ForegroundColor DarkGray
        $admin = Invoke-SgDnSafeguardApi -Context $Context -Service Core -Method Post `
            -RelativeUrl "Users" -Body @{
                PrimaryAuthenticationProvider = @{ Id = -1 }
                Name = $adminUser
                AdminRoles = @('GlobalAdmin','Auditor','AssetAdmin','ApplianceAdmin','PolicyAdmin','UserAdmin','HelpdeskAdmin','OperationsAdmin')
            }
        $Context.SuiteData["AdminUserId"] = $admin.Id
        $Context.SuiteData["AdminUser"] = $adminUser
        $Context.SuiteData["AdminPassword"] = $adminPassword
        Register-SgDnTestCleanup -Description "Delete A2A event admin user" -Action {
            param($Ctx)
            Remove-SgDnSafeguardTestObject -Context $Ctx `
                -RelativeUrl "Users/$($Ctx.SuiteData['AdminUserId'])"
        }
        Invoke-SgDnSafeguardApi -Context $Context -Service Core -Method Put `
            -RelativeUrl "Users/$($admin.Id)/Password" -Body "'$adminPassword'" -ParseJson $false

        # 2. Upload cert trust chain
        Write-Host "    Uploading certificate trust chain..." -ForegroundColor DarkGray
        $rootCertData = [string](Get-Content -Raw $Context.RootCert)
        $rootCert = Invoke-SgDnSafeguardApi -Context $Context -Service Core -Method Post `
            -RelativeUrl "TrustedCertificates" `
            -Username $adminUser -Password $adminPassword `
            -Body @{ Base64CertificateData = $rootCertData }
        $Context.SuiteData["RootCertId"] = $rootCert.Id
        Register-SgDnTestCleanup -Description "Delete Root CA trust" -Action {
            param($Ctx)
            Remove-SgDnSafeguardTestObject -Context $Ctx `
                -RelativeUrl "TrustedCertificates/$($Ctx.SuiteData['RootCertId'])"
        }

        $caCertData = [string](Get-Content -Raw $Context.CaCert)
        $caCert = Invoke-SgDnSafeguardApi -Context $Context -Service Core -Method Post `
            -RelativeUrl "TrustedCertificates" `
            -Username $adminUser -Password $adminPassword `
            -Body @{ Base64CertificateData = $caCertData }
        $Context.SuiteData["CaCertId"] = $caCert.Id
        Register-SgDnTestCleanup -Description "Delete Intermediate CA trust" -Action {
            param($Ctx)
            Remove-SgDnSafeguardTestObject -Context $Ctx `
                -RelativeUrl "TrustedCertificates/$($Ctx.SuiteData['CaCertId'])"
        }

        # 3. Create certificate user
        Write-Host "    Creating certificate user '$certUser'..." -ForegroundColor DarkGray
        $cUser = Invoke-SgDnSafeguardApi -Context $Context -Service Core -Method Post `
            -RelativeUrl "Users" `
            -Username $adminUser -Password $adminPassword `
            -Body @{
                PrimaryAuthenticationProvider = @{
                    Id = -2
                    Identity = $userThumbprint
                }
                Name = $certUser
            }
        $Context.SuiteData["CertUserId"] = $cUser.Id
        Register-SgDnTestCleanup -Description "Delete A2A event certificate user" -Action {
            param($Ctx)
            Remove-SgDnSafeguardTestObject -Context $Ctx `
                -RelativeUrl "Users/$($Ctx.SuiteData['CertUserId'])"
        }

        # 4. Create asset
        Write-Host "    Creating asset '${prefix}_A2aEvtAsset'..." -ForegroundColor DarkGray
        $asset = Invoke-SgDnSafeguardApi -Context $Context -Service Core -Method Post `
            -RelativeUrl "Assets" `
            -Username $adminUser -Password $adminPassword `
            -Body @{
                Name = "${prefix}_A2aEvtAsset"
                Description = "test asset for A2A event listener"
                PlatformId = 188
                AssetPartitionId = -1
                NetworkAddress = "fake.a2aevt.address.com"
            }
        $Context.SuiteData["AssetId"] = $asset.Id
        Register-SgDnTestCleanup -Description "Delete asset" -Action {
            param($Ctx)
            Remove-SgDnSafeguardTestObject -Context $Ctx `
                -RelativeUrl "Assets/$($Ctx.SuiteData['AssetId'])" `
                -Username $Ctx.SuiteData['AdminUser'] -Password $Ctx.SuiteData['AdminPassword']
        }

        # 5. Create account on asset
        Write-Host "    Creating account '${prefix}_A2aEvtAccount' on asset..." -ForegroundColor DarkGray
        $account = Invoke-SgDnSafeguardApi -Context $Context -Service Core -Method Post `
            -RelativeUrl "AssetAccounts" `
            -Username $adminUser -Password $adminPassword `
            -Body @{
                Name = "${prefix}_A2aEvtAccount"
                Asset = @{ Id = $asset.Id }
            }
        $Context.SuiteData["AccountId"] = $account.Id
        Register-SgDnTestCleanup -Description "Delete asset account" -Action {
            param($Ctx)
            Remove-SgDnSafeguardTestObject -Context $Ctx `
                -RelativeUrl "AssetAccounts/$($Ctx.SuiteData['AccountId'])" `
                -Username $Ctx.SuiteData['AdminUser'] -Password $Ctx.SuiteData['AdminPassword']
        }

        # Set account password
        Write-Host "    Setting account password..." -ForegroundColor DarkGray
        Invoke-SgDnSafeguardApi -Context $Context -Service Core -Method Put `
            -RelativeUrl "AssetAccounts/$($account.Id)/Password" `
            -Username $adminUser -Password $adminPassword `
            -Body "'$adminPassword'" -ParseJson $false

        # 6. Create A2A registration
        Write-Host "    Creating A2A registration '${prefix}_A2aEvtReg'..." -ForegroundColor DarkGray
        $a2aReg = Invoke-SgDnSafeguardApi -Context $Context -Service Core -Method Post `
            -RelativeUrl "A2ARegistrations" `
            -Username $adminUser -Password $adminPassword `
            -Body @{
                AppName = "${prefix}_A2aEvtReg"
                VisibleToCertificateUsers = $true
                Description = "test a2a registration for A2A event listener"
                CertificateUserId = $cUser.Id
            }
        $Context.SuiteData["A2aRegId"] = $a2aReg.Id
        Register-SgDnTestCleanup -Description "Delete A2A registration" -Action {
            param($Ctx)
            Remove-SgDnSafeguardTestObject -Context $Ctx `
                -RelativeUrl "A2ARegistrations/$($Ctx.SuiteData['A2aRegId'])" `
                -Username $Ctx.SuiteData['AdminUser'] -Password $Ctx.SuiteData['AdminPassword']
        }

        # 7. Add retrievable account to A2A registration
        Write-Host "    Adding retrievable account to A2A registration..." -ForegroundColor DarkGray
        $retrievable = Invoke-SgDnSafeguardApi -Context $Context -Service Core -Method Post `
            -RelativeUrl "A2ARegistrations/$($a2aReg.Id)/RetrievableAccounts" `
            -Username $adminUser -Password $adminPassword `
            -Body @{ AccountId = $account.Id }
        $Context.SuiteData["ApiKey"] = $retrievable.ApiKey

        # 8. Enable A2A service if the shared appliance currently has it disabled.
        Write-Host "    Ensuring A2A service is enabled..." -ForegroundColor DarkGray
        Enable-SgDnA2aServiceForSuite -Context $Context -Username $adminUser -Password $adminPassword
    }

    Execute = {
        param($Context)

        $prefix        = $Context.TestPrefix
        $appliance     = $Context.Appliance
        $toolDir       = $Context.EventToolDir
        $apiKey        = $Context.SuiteData["ApiKey"]
        $certFile      = $Context.UserPfx
        $accountId     = $Context.SuiteData["AccountId"]
        $adminUser     = $Context.SuiteData["AdminUser"]
        $adminPassword = $Context.SuiteData["AdminPassword"]

        # Helper: start an A2A event listener process, optionally trigger an action,
        # check output for a pattern, then shut down.
        function Start-A2AEventListenerTest {
            param(
                [string]$ToolArgs,
                [string]$StdinLine,
                [string]$ReadyPattern,
                [scriptblock]$TriggerAction,
                [string]$ExpectPattern,
                [int]$ReadyTimeoutSec = 45,
                [int]$EventTimeoutSec = 30
            )

            $startInfo = [System.Diagnostics.ProcessStartInfo]::new()
            $startInfo.FileName = "dotnet"
            $startInfo.Arguments = "run --no-build --project `"$toolDir`" -- $ToolArgs"
            $startInfo.UseShellExecute = $false
            $startInfo.RedirectStandardOutput = $true
            $startInfo.RedirectStandardError = $true
            $startInfo.RedirectStandardInput = $true
            $startInfo.CreateNoWindow = $true
            $startInfo.WorkingDirectory = $toolDir

            $proc = [System.Diagnostics.Process]::new()
            $proc.StartInfo = $startInfo

            $stdout = [System.Text.StringBuilder]::new()
            $stderr = [System.Text.StringBuilder]::new()

            $stdoutEvt = Register-ObjectEvent -InputObject $proc -EventName OutputDataReceived -Action {
                if ($null -ne $EventArgs.Data) {
                    $Event.MessageData.AppendLine($EventArgs.Data) | Out-Null
                }
            } -MessageData $stdout

            $stderrEvt = Register-ObjectEvent -InputObject $proc -EventName ErrorDataReceived -Action {
                if ($null -ne $EventArgs.Data) {
                    $Event.MessageData.AppendLine($EventArgs.Data) | Out-Null
                }
            } -MessageData $stderr

            try {
                $proc.Start() | Out-Null
                $proc.BeginOutputReadLine()
                $proc.BeginErrorReadLine()

                # Send certificate password via stdin (keep stdin open for shutdown signal)
                $proc.StandardInput.WriteLine($StdinLine)

                # Wait for listener to become ready
                $ready = $false
                for ($i = 0; $i -lt $ReadyTimeoutSec; $i++) {
                    Start-Sleep -Seconds 1
                    $out = $stdout.ToString()
                    if ($out -match $ReadyPattern) {
                        $ready = $true
                        break
                    }
                    if ($proc.HasExited) { break }
                }

                if (-not $ready) {
                    $msg = "Listener not ready within ${ReadyTimeoutSec}s.`nStdout: $($stdout.ToString())`nStderr: $($stderr.ToString())"
                    throw $msg
                }

                # Run the trigger action (e.g., change account password)
                $triggerResult = $null
                if ($TriggerAction) {
                    $triggerResult = & $TriggerAction
                }

                # Wait for expected pattern in output
                $matched = $false
                if ($ExpectPattern) {
                    for ($i = 0; $i -lt $EventTimeoutSec; $i++) {
                        Start-Sleep -Seconds 1
                        $out = $stdout.ToString()
                        if ($out -match $ExpectPattern) {
                            $matched = $true
                            break
                        }
                    }
                } else {
                    # No event to wait for — just checking readiness was enough
                    $matched = $ready
                }

                # Gracefully stop: send a blank line (triggers Console.ReadLine() return)
                try {
                    if (-not $proc.HasExited) {
                        $proc.StandardInput.WriteLine("")
                        $proc.WaitForExit(5000) | Out-Null
                    }
                } catch {}

                return @{ Matched = $matched; Output = $stdout.ToString(); TriggerResult = $triggerResult }
            }
            finally {
                Unregister-Event -SourceIdentifier $stdoutEvt.Name -ErrorAction SilentlyContinue
                Unregister-Event -SourceIdentifier $stderrEvt.Name -ErrorAction SilentlyContinue
                if (-not $proc.HasExited) {
                    try { $proc.Kill() } catch {}
                }
                $proc.Dispose()
            }
        }

        # --- Test 1: Standard A2A event listener receives password change event ---
        Test-SgDnAssert "Standard A2A listener receives password change event" {
            $result = Start-A2AEventListenerTest `
                -ToolArgs "-a $appliance -x -A `"$apiKey`" -c `"$certFile`" -p" `
                -StdinLine "a" `
                -ReadyPattern "Press enter" `
                -TriggerAction {
                    Invoke-SgDnSafeguardApi -Context $Context -Service Core -Method Put `
                        -RelativeUrl "AssetAccounts/$accountId/Password" `
                        -Username $adminUser -Password $adminPassword `
                        -Body "'StandardA2aEvtPass1!'" -ParseJson $false
                } `
                -ExpectPattern "Received A2AHandler Event"

            $result.Matched
        }

        # --- Test 2: Persistent A2A listener receives password change event ---
        # Uses -S (state callback) and waits for Connected state before triggering,
        # because persistent Start() returns before the SignalR connection completes.
        Test-SgDnAssert "Persistent A2A listener receives password change event" {
            $result = Start-A2AEventListenerTest `
                -ToolArgs "-a $appliance -x -A `"$apiKey`" -c `"$certFile`" -P -S -p" `
                -StdinLine "a" `
                -ReadyPattern "state is: Connected" `
                -TriggerAction {
                    Invoke-SgDnSafeguardApi -Context $Context -Service Core -Method Put `
                        -RelativeUrl "AssetAccounts/$accountId/Password" `
                        -Username $adminUser -Password $adminPassword `
                        -Body "'PersistentA2aEvtPass2!'" -ParseJson $false
                } `
                -ExpectPattern "Received A2AHandler Event"

            $result.Matched
        }

        # --- Test 3: Persistent A2A listener with state callback reports Connected ---
        Test-SgDnAssert "Persistent A2A listener reports Connected state" {
            $result = Start-A2AEventListenerTest `
                -ToolArgs "-a $appliance -x -A `"$apiKey`" -c `"$certFile`" -P -S -p" `
                -StdinLine "a" `
                -ReadyPattern "Press enter" `
                -ExpectPattern "state is: Connected"

            $result.Matched
        }
    }

    Cleanup = {
        param($Context)
        $prefix = $Context.TestPrefix
        $adminUser = $Context.SuiteData["AdminUser"]
        $adminPassword = $Context.SuiteData["AdminPassword"]
        Restore-SgDnA2aServiceForSuite -Context $Context -Username $adminUser -Password $adminPassword
        Remove-SgDnStaleTestObject -Context $Context -Collection "A2ARegistrations" -Name "${prefix}_A2aEvtReg" -NameField "AppName" -Username $adminUser -Password $adminPassword
        Remove-SgDnStaleTestObject -Context $Context -Collection "AssetAccounts" -Name "${prefix}_A2aEvtAccount" -Username $adminUser -Password $adminPassword
        Remove-SgDnStaleTestObject -Context $Context -Collection "Assets" -Name "${prefix}_A2aEvtAsset" -Username $adminUser -Password $adminPassword
        Remove-SgDnStaleTestObject -Context $Context -Collection "Users" -Name "${prefix}_A2aEvtCertUser"
        Remove-SgDnStaleTestObject -Context $Context -Collection "Users" -Name "${prefix}_A2aEvtAdmin"
    }
}
