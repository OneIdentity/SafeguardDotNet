@{
    Name        = "A2A Access Request Broker"
    Description = "Tests brokered access requests via the A2A AccessRequestBroker tool and SDK"
    Tags        = @("a2a", "broker", "accessrequest")

    Setup = {
        param($Context)

        $prefix = $Context.TestPrefix
        $adminUser = "${prefix}_BrkAdmin"
        $adminPassword = "2309aseflkasdlf209349qauerA"
        $requesterUser = "${prefix}_BrkRequester"
        $requesterPassword = "xR3quester!Pass99"
        $certUserName = "${prefix}_BrkCertUser"

        Write-Host "    Computing certificate thumbprints..." -ForegroundColor DarkGray
        $userThumbprint = (Get-PfxCertificate $Context.UserCert).Thumbprint
        $rootThumbprint = (Get-PfxCertificate $Context.RootCert).Thumbprint
        $caThumbprint   = (Get-PfxCertificate $Context.CaCert).Thumbprint

        # Pre-cleanup
        Write-Host "    Removing stale objects from previous runs..." -ForegroundColor DarkGray
        Remove-SgDnStaleTestObject -Context $Context -Collection "A2ARegistrations" -Name "${prefix}_BrkA2A" -NameField "AppName"
        Remove-SgDnStaleTestObject -Context $Context -Collection "AssetAccounts" -Name "${prefix}_BrkAccount"
        Remove-SgDnStaleTestObject -Context $Context -Collection "Assets" -Name "${prefix}_BrkAsset"
        Remove-SgDnStaleTestObject -Context $Context -Collection "Users" -Name $certUserName
        Remove-SgDnStaleTestObject -Context $Context -Collection "Users" -Name $requesterUser
        Remove-SgDnStaleTestCert -Context $Context -Thumbprint $caThumbprint
        Remove-SgDnStaleTestCert -Context $Context -Thumbprint $rootThumbprint
        Remove-SgDnStaleTestObject -Context $Context -Collection "Users" -Name $adminUser

        # 1. Admin user
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
        Register-SgDnTestCleanup -Description "Delete broker admin user" -Action {
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

        # 3. Certificate user (for A2A context)
        Write-Host "    Creating certificate user '$certUserName'..." -ForegroundColor DarkGray
        $cUser = Invoke-SgDnSafeguardApi -Context $Context -Service Core -Method Post `
            -RelativeUrl "Users" `
            -Username $adminUser -Password $adminPassword `
            -Body @{
                PrimaryAuthenticationProvider = @{ Id = -2; Identity = $userThumbprint }
                Name = $certUserName
            }
        $Context.SuiteData["CertUserId"] = $cUser.Id
        Register-SgDnTestCleanup -Description "Delete cert user" -Action {
            param($Ctx)
            Remove-SgDnSafeguardTestObject -Context $Ctx `
                -RelativeUrl "Users/$($Ctx.SuiteData['CertUserId'])"
        }

        # 4. Requester user (the user the broker creates requests for)
        Write-Host "    Creating requester user '$requesterUser'..." -ForegroundColor DarkGray
        $reqUser = Invoke-SgDnSafeguardApi -Context $Context -Service Core -Method Post `
            -RelativeUrl "Users" -Body @{
                PrimaryAuthenticationProvider = @{ Id = -1 }
                Name = $requesterUser
            }
        $Context.SuiteData["RequesterId"] = $reqUser.Id
        $Context.SuiteData["RequesterUser"] = $requesterUser
        $Context.SuiteData["RequesterPassword"] = $requesterPassword
        Register-SgDnTestCleanup -Description "Delete requester user" -Action {
            param($Ctx)
            Remove-SgDnSafeguardTestObject -Context $Ctx `
                -RelativeUrl "Users/$($Ctx.SuiteData['RequesterId'])"
        }
        Invoke-SgDnSafeguardApi -Context $Context -Service Core -Method Put `
            -RelativeUrl "Users/$($reqUser.Id)/Password" -Body "'$requesterPassword'" -ParseJson $false

        # 5. Asset
        Write-Host "    Creating asset '${prefix}_BrkAsset'..." -ForegroundColor DarkGray
        $asset = Invoke-SgDnSafeguardApi -Context $Context -Service Core -Method Post `
            -RelativeUrl "Assets" `
            -Username $adminUser -Password $adminPassword `
            -Body @{
                Name = "${prefix}_BrkAsset"
                Description = "test asset for A2A broker"
                PlatformId = 188
                AssetPartitionId = -1
                NetworkAddress = "fake.brk.address.com"
            }
        $Context.SuiteData["AssetId"] = $asset.Id
        Register-SgDnTestCleanup -Description "Delete asset" -Action {
            param($Ctx)
            Remove-SgDnSafeguardTestObject -Context $Ctx `
                -RelativeUrl "Assets/$($Ctx.SuiteData['AssetId'])" `
                -Username $Ctx.SuiteData['AdminUser'] -Password $Ctx.SuiteData['AdminPassword']
        }

        # 6. Account on asset
        Write-Host "    Creating account '${prefix}_BrkAccount' on asset..." -ForegroundColor DarkGray
        $account = Invoke-SgDnSafeguardApi -Context $Context -Service Core -Method Post `
            -RelativeUrl "AssetAccounts" `
            -Username $adminUser -Password $adminPassword `
            -Body @{
                Name = "${prefix}_BrkAccount"
                Asset = @{ Id = $asset.Id }
            }
        $Context.SuiteData["AccountId"] = $account.Id
        Register-SgDnTestCleanup -Description "Delete asset account" -Action {
            param($Ctx)
            Remove-SgDnSafeguardTestObject -Context $Ctx `
                -RelativeUrl "AssetAccounts/$($Ctx.SuiteData['AccountId'])" `
                -Username $Ctx.SuiteData['AdminUser'] -Password $Ctx.SuiteData['AdminPassword']
        }
        Write-Host "    Setting account password..." -ForegroundColor DarkGray
        Invoke-SgDnSafeguardApi -Context $Context -Service Core -Method Put `
            -RelativeUrl "AssetAccounts/$($account.Id)/Password" `
            -Username $adminUser -Password $adminPassword `
            -Body "'$adminPassword'" -ParseJson $false

        # 7. Role with requester user as member
        Write-Host "    Creating role '${prefix}_BrkRole'..." -ForegroundColor DarkGray
        $role = Invoke-SgDnSafeguardApi -Context $Context -Service Core -Method Post `
            -RelativeUrl "Roles" `
            -Username $adminUser -Password $adminPassword `
            -Body @{
                Name = "${prefix}_BrkRole"
                Members = @(@{ Id = $reqUser.Id; PrincipalKind = "User" })
            }
        $Context.SuiteData["RoleId"] = $role.Id
        Register-SgDnTestCleanup -Description "Delete role" -Action {
            param($Ctx)
            Remove-SgDnSafeguardTestObject -Context $Ctx `
                -RelativeUrl "Roles/$($Ctx.SuiteData['RoleId'])" `
                -Username $Ctx.SuiteData['AdminUser'] -Password $Ctx.SuiteData['AdminPassword']
        }

        # 8. Access policy linking role to account (admin user as approver)
        Write-Host "    Creating access policy '${prefix}_BrkPolicy'..." -ForegroundColor DarkGray
        $policy = Invoke-SgDnSafeguardApi -Context $Context -Service Core -Method Post `
            -RelativeUrl "AccessPolicies" `
            -Username $adminUser -Password $adminPassword `
            -Body @{
                Name = "${prefix}_BrkPolicy"
                RoleId = $role.Id
                AccessRequestProperties = @{
                    AccessRequestType = "Password"
                    AllowSimultaneousAccess = $true
                    MaximumSimultaneousReleases = 1
                    ChangeDurationInMinutes = 90
                }
                ScopeItems = @(@{
                    ScopeItemType = "Account"
                    Id = $account.Id
                })
                ApproverProperties = @{
                    RequireApproval = $true
                }
                ApproverSets = @(
                    @{
                        RequiredApprovers = 1
                        Approvers = @(@{ Id = $admin.Id })
                    }
                )
            }
        $Context.SuiteData["PolicyId"] = $policy.Id
        Register-SgDnTestCleanup -Description "Delete access policy" -Action {
            param($Ctx)
            Remove-SgDnSafeguardTestObject -Context $Ctx `
                -RelativeUrl "AccessPolicies/$($Ctx.SuiteData['PolicyId'])" `
                -Username $Ctx.SuiteData['AdminUser'] -Password $Ctx.SuiteData['AdminPassword']
        }

        # 9. A2A registration
        Write-Host "    Creating A2A registration '${prefix}_BrkA2A'..." -ForegroundColor DarkGray
        $a2aReg = Invoke-SgDnSafeguardApi -Context $Context -Service Core -Method Post `
            -RelativeUrl "A2ARegistrations" `
            -Username $adminUser -Password $adminPassword `
            -Body @{
                AppName = "${prefix}_BrkA2A"
                CertificateUserId = $cUser.Id
            }
        $Context.SuiteData["A2aRegId"] = $a2aReg.Id
        Register-SgDnTestCleanup -Description "Delete A2A registration" -Action {
            param($Ctx)
            Remove-SgDnSafeguardTestObject -Context $Ctx `
                -RelativeUrl "A2ARegistrations/$($Ctx.SuiteData['A2aRegId'])" `
                -Username $Ctx.SuiteData['AdminUser'] -Password $Ctx.SuiteData['AdminPassword']
        }

        # 10. Configure AccessRequestBroker on the A2A registration
        Write-Host "    Configuring access request broker..." -ForegroundColor DarkGray
        # The RegistrationAlias schema uses 'UserId' (not 'Id')
        $reqUserId = [int]$Context.SuiteData["RequesterId"]
        $broker = Invoke-SgDnSafeguardApi -Context $Context -Service Core -Method Put `
            -RelativeUrl "A2ARegistrations/$($a2aReg.Id)/AccessRequestBroker" `
            -Username $adminUser -Password $adminPassword `
            -Body @{
                Users = @(@{ UserId = $reqUserId })
            }
        $Context.SuiteData["BrokerApiKey"] = $broker.ApiKey

        # 11. Enable A2A service if the shared appliance currently has it disabled.
        Write-Host "    Ensuring A2A service is enabled..." -ForegroundColor DarkGray
        Enable-SgDnA2aServiceForSuite -Context $Context -Username $adminUser -Password $adminPassword
    }

    Execute = {
        param($Context)

        $adminUser = $Context.SuiteData["AdminUser"]
        $adminPassword = $Context.SuiteData["AdminPassword"]
        $apiKey = $Context.SuiteData["BrokerApiKey"]
        $requesterId = $Context.SuiteData["RequesterId"]
        $assetId = $Context.SuiteData["AssetId"]
        $accountId = $Context.SuiteData["AccountId"]

        # --- Submit brokered access request ---
        Test-SgDnAssert "Brokered access request is created" {
            $request = Invoke-SgDnSafeguardA2aBroker -Context $Context `
                -ApiKey $apiKey `
                -ForUser $requesterId.ToString() `
                -AccessType Password `
                -Asset $assetId.ToString() `
                -Account $accountId.ToString() `
                -CertificateFile $Context.UserPfx -CertificatePassword "a"
            $Context.SuiteData["AccessRequestId"] = $request.Id

            Register-SgDnTestCleanup -Description "Close/delete brokered access request" -Action {
                param($Ctx)
                $reqId = $Ctx.SuiteData['AccessRequestId']
                if ($reqId) {
                    try {
                        $null = Invoke-SgDnSafeguardApi -Context $Ctx -Service Core -Method Post `
                            -RelativeUrl "AccessRequests/$reqId/CheckIn" `
                            -Username $Ctx.SuiteData['RequesterUser'] -Password $Ctx.SuiteData['RequesterPassword'] `
                            -ParseJson $false
                    } catch {}
                    try {
                        $null = Invoke-SgDnSafeguardApi -Context $Ctx -Service Core -Method Post `
                            -RelativeUrl "AccessRequests/$reqId/Close" `
                            -Username $Ctx.SuiteData['AdminUser'] -Password $Ctx.SuiteData['AdminPassword'] `
                            -ParseJson $false
                    } catch {}
                }
            }

            $null -ne $request.Id -and $request.Id -gt 0
        }

        # --- Verify request state is pending approval ---
        Test-SgDnAssert "Brokered request is pending approval" {
            $reqId = $Context.SuiteData["AccessRequestId"]
            $req = Invoke-SgDnSafeguardApi -Context $Context -Service Core -Method Get `
                -RelativeUrl "AccessRequests/$reqId" `
                -Username $adminUser -Password $adminPassword
            $req.State -eq "PendingApproval"
        }

        # --- Approve the request (as admin) ---
        Test-SgDnAssert "Approve brokered access request" {
            $reqId = $Context.SuiteData["AccessRequestId"]
            Invoke-SgDnSafeguardApi -Context $Context -Service Core -Method Post `
                -RelativeUrl "AccessRequests/$reqId/Approve" `
                -Username $adminUser -Password $adminPassword `
                -ParseJson $false
            $true
        }

        # --- Checkout password (as requester) ---
        Test-SgDnAssert "Checkout password from brokered request" {
            $reqId = $Context.SuiteData["AccessRequestId"]
            $password = Invoke-SgDnSafeguardApi -Context $Context -Service Core -Method Post `
                -RelativeUrl "AccessRequests/$reqId/CheckOutPassword" `
                -Username $Context.SuiteData["RequesterUser"] `
                -Password $Context.SuiteData["RequesterPassword"] `
                -ParseJson $false
            $null -ne $password -and $password.Length -gt 0
        }

        # --- Checkin (as requester) ---
        Test-SgDnAssert "Checkin brokered access request" {
            $reqId = $Context.SuiteData["AccessRequestId"]
            Invoke-SgDnSafeguardApi -Context $Context -Service Core -Method Post `
                -RelativeUrl "AccessRequests/$reqId/CheckIn" `
                -Username $Context.SuiteData["RequesterUser"] `
                -Password $Context.SuiteData["RequesterPassword"] `
                -ParseJson $false
            $true
        }
    }

    Cleanup = {
        param($Context)
        Restore-SgDnA2aServiceForSuite -Context $Context `
            -Username $Context.SuiteData['AdminUser'] -Password $Context.SuiteData['AdminPassword']
        # Registered cleanup handles everything else in LIFO order.
    }
}
