@{
    Name        = "Certificate Authentication"
    Description = "Tests certificate-based authentication via PFX file, PFX data buffer, and cert store"
    Tags        = @("auth", "certificate")

    Setup = {
        param($Context)

        $prefix = $Context.TestPrefix
        $adminUser = "${prefix}_CertSetupAdmin"
        $adminPassword = "2309aseflkasdlf209349qauerA"
        $certUser = "${prefix}_CertUser"

        # Compute thumbprints
        Write-Host "    Computing certificate thumbprints..." -ForegroundColor DarkGray
        $userThumbprint = (Get-PfxCertificate $Context.UserCert).Thumbprint
        $rootThumbprint = (Get-PfxCertificate $Context.RootCert).Thumbprint
        $caThumbprint   = (Get-PfxCertificate $Context.CaCert).Thumbprint

        $Context.SuiteData["UserThumbprint"] = $userThumbprint
        $Context.SuiteData["RootThumbprint"] = $rootThumbprint
        $Context.SuiteData["CaThumbprint"]   = $caThumbprint

        # Pre-cleanup: remove stale objects from previous failed runs (reverse dependency order)
        Write-Host "    Removing stale objects from previous runs..." -ForegroundColor DarkGray
        Remove-SgDnStaleTestObject -Context $Context -Collection "Users" -Name $certUser
        Remove-SgDnStaleTestCert -Context $Context -Thumbprint $caThumbprint
        Remove-SgDnStaleTestCert -Context $Context -Thumbprint $rootThumbprint
        Remove-SgDnStaleTestObject -Context $Context -Collection "Users" -Name $adminUser

        # 1. Create admin user for setup operations
        Write-Host "    Creating admin user '$adminUser'..." -ForegroundColor DarkGray
        $admin = Invoke-SgDnSafeguardApi -Context $Context -Service Core -Method Post `
            -RelativeUrl "Users" -Body @{
                PrimaryAuthenticationProvider = @{ Id = -1 }
                Name = $adminUser
                AdminRoles = @('GlobalAdmin','Auditor','AssetAdmin','ApplianceAdmin','PolicyAdmin','UserAdmin','HelpdeskAdmin','OperationsAdmin')
            }
        $Context.SuiteData["AdminUserId"] = $admin.Id
        Register-SgDnTestCleanup -Description "Delete cert setup admin user" -Action {
            param($Ctx)
            Remove-SgDnSafeguardTestObject -Context $Ctx `
                -RelativeUrl "Users/$($Ctx.SuiteData['AdminUserId'])"
        }
        Invoke-SgDnSafeguardApi -Context $Context -Service Core -Method Put `
            -RelativeUrl "Users/$($admin.Id)/Password" -Body "'$adminPassword'" -ParseJson $false

        # 2. Upload Root CA
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

        # 3. Upload Intermediate CA
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

        # 4. Create certificate user
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
        $Context.SuiteData["CertUserName"] = $certUser
        Register-SgDnTestCleanup -Description "Delete certificate user" -Action {
            param($Ctx)
            Remove-SgDnSafeguardTestObject -Context $Ctx `
                -RelativeUrl "Users/$($Ctx.SuiteData['CertUserId'])"
        }
        Register-SgDnTestCleanup -Description "Remove cert from user store (if imported)" -Action {
            param($Ctx)
            $tp = $Ctx.SuiteData['UserThumbprint']
            if ($tp -and (Test-Path "Cert:\CurrentUser\My\$tp")) {
                Remove-Item "Cert:\CurrentUser\My\$tp" -ErrorAction SilentlyContinue
            }
        }

        # Probe TLS 1.3 capability so the cert-over-1.3 test below can require a real
        # TLS 1.3 handshake on 9.0 and skip on 8.x (which tops out at TLS 1.2).
        $Context.SuiteData["Tls13Capable"] = Test-SgDnApplianceTls13 -ApplianceHost $Context.Appliance
    }

    Execute = {
        param($Context)

        Test-SgDnAssert "Auth as cert user from PFX file" {
            $result = Invoke-SgDnSafeguardApi -Context $Context `
                -Service Core -Method Get -RelativeUrl "Me" `
                -CertificateFile $Context.UserPfx -CertificatePassword "a"
            $result.Name -eq $Context.SuiteData["CertUserName"]
        }

        Test-SgDnAssert "Auth as cert user from PFX file as data buffer" {
            $result = Invoke-SgDnSafeguardApi -Context $Context `
                -Service Core -Method Get -RelativeUrl "Me" `
                -CertificateFile $Context.UserPfx -CertificatePassword "a" -CertificateAsData
            $result.Name -eq $Context.SuiteData["CertUserName"]
        }

        Test-SgDnAssert "Auth as cert user from User Certificate Store" {
            $tp = $Context.SuiteData["UserThumbprint"]
            # Import cert to user store
            Import-PfxCertificate $Context.UserPfx `
                -CertStoreLocation Cert:\CurrentUser\My `
                -Password (ConvertTo-SecureString -AsPlainText 'a' -Force) | Out-Null
            try {
                $result = Invoke-SgDnSafeguardApi -Context $Context `
                    -Service Core -Method Get -RelativeUrl "Me" `
                    -Thumbprint $tp -CertificatePassword "a"
                $result.Name -eq $Context.SuiteData["CertUserName"]
            }
            finally {
                # Remove cert from store immediately after test
                if (Test-Path "Cert:\CurrentUser\My\$tp") {
                    Remove-Item "Cert:\CurrentUser\My\$tp" -ErrorAction SilentlyContinue
                }
            }
        }

        if (Test-SgDnIsElevated) {
            # Computer store test requires elevation
            Test-SgDnAssert "Auth as cert user from Computer Certificate Store" {
                $tp = $Context.SuiteData["UserThumbprint"]
                Import-PfxCertificate $Context.UserPfx `
                    -CertStoreLocation Cert:\LocalMachine\My `
                    -Password (ConvertTo-SecureString -AsPlainText 'a' -Force) | Out-Null
                try {
                    $result = Invoke-SgDnSafeguardApi -Context $Context `
                        -Service Core -Method Get -RelativeUrl "Me" `
                        -Thumbprint $tp -CertificatePassword "a"
                    $result.Name -eq $Context.SuiteData["CertUserName"]
                }
                finally {
                    if (Test-Path "Cert:\LocalMachine\My\$tp") {
                        Remove-Item "Cert:\LocalMachine\My\$tp" -ErrorAction SilentlyContinue
                    }
                }
            }
        }
        else {
            Test-SgDnSkip "Auth as cert user from Computer Certificate Store" "Requires elevation"
        }

        # .NET's SslStream performs post-handshake client-certificate auth, so cert
        # auth works over real TLS 1.3 on the Standard binding with no Cert SNI
        # workaround. Prove that live on TLS 1.3-capable appliances; skip on 8.x.
        if ($Context.SuiteData["Tls13Capable"]) {
            Test-SgDnAssert "Auth as cert user over TLS 1.3 (Standard binding)" {
                $result = Invoke-SgDnSafeguardApi -Context $Context `
                    -Service Core -Method Get -RelativeUrl "Me" `
                    -CertificateFile $Context.UserPfx -CertificatePassword "a" `
                    -MinTlsVersion 1.3
                $result.Name -eq $Context.SuiteData["CertUserName"]
            }
        }
        else {
            Test-SgDnSkip "Auth as cert user over TLS 1.3 (Standard binding)" "Appliance max is TLS 1.2"
        }
    }

    Cleanup = {
        param($Context)
        # Registered cleanup handles everything.
    }
}
