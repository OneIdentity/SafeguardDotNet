@{
    Name        = "TLS Version Selection"
    Description = "Tests minimum/maximum TLS version pinning: client-side range validation and live negotiation against the appliance"
    Tags        = @("tls", "connection")

    Setup = {
        param($Context)

        # Probe the appliance's real TLS 1.3 capability with a raw handshake so the
        # assertions below can require the SDK to match what the server actually
        # supports (8.x tops out at TLS 1.2; 9.0+ negotiates TLS 1.3).
        Write-Host "    Probing appliance TLS 1.3 capability..." -ForegroundColor DarkGray
        $tls13Capable = Test-SgDnApplianceTls13 -ApplianceHost $Context.Appliance

        $Context.SuiteData["Tls13Capable"] = $tls13Capable
        $verdict = if ($tls13Capable) { "supports TLS 1.3" } else { "TLS 1.2 max" }
        Write-Host "    Appliance $($Context.Appliance) $verdict" -ForegroundColor DarkGray
    }

    Execute = {
        param($Context)

        # Range validation happens client-side before any network I/O, so it is
        # independent of the appliance's TLS capability.
        Test-SgDnAssertThrows "Reject minTlsVersion greater than maxTlsVersion" `
            -ExpectedMessage "cannot be greater than" {
            Invoke-SgDnSafeguardApi -Context $Context -Service Core -Method Get -RelativeUrl "Me" `
                -MinTlsVersion 1.3 -MaxTlsVersion 1.2
        }

        # Capping at TLS 1.2 must connect against every supported appliance.
        Test-SgDnAssert "Connect with maxTlsVersion 1.2" {
            $result = Invoke-SgDnSafeguardApi -Context $Context -Service Core -Method Get -RelativeUrl "Me" `
                -MaxTlsVersion 1.2
            $null -ne $result.Id
        }

        # A 1.2–1.3 window lets the OS negotiate the best mutually supported version.
        Test-SgDnAssert "Connect with TLS 1.2 to 1.3 window" {
            $result = Invoke-SgDnSafeguardApi -Context $Context -Service Core -Method Get -RelativeUrl "Me" `
                -MinTlsVersion 1.2 -MaxTlsVersion 1.3
            $null -ne $result.Id
        }

        if ($Context.SuiteData["Tls13Capable"]) {
            # Appliance negotiates TLS 1.3: pinning the floor at 1.3 must connect.
            Test-SgDnAssert "Connect with minTlsVersion 1.3 (appliance supports TLS 1.3)" {
                $result = Invoke-SgDnSafeguardApi -Context $Context -Service Core -Method Get -RelativeUrl "Me" `
                    -MinTlsVersion 1.3
                $null -ne $result.Id
            }
        }
        else {
            # Appliance tops out at TLS 1.2: pinning the floor at 1.3 must fail closed
            # rather than silently downgrade.
            Test-SgDnAssertThrows "Reject minTlsVersion 1.3 (appliance max is TLS 1.2)" {
                Invoke-SgDnSafeguardApi -Context $Context -Service Core -Method Get -RelativeUrl "Me" `
                    -MinTlsVersion 1.3
            }
        }
    }

    Cleanup = {
        param($Context)
        # No objects created; nothing to clean up.
    }
}
