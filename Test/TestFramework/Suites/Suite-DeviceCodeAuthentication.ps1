@{
    Name        = "Device Code Authentication"
    Description = "Tests OAuth 2.0 Device Authorization Grant (RFC 8628) login flow. The happy path test requires a human to authenticate in a browser."
    Tags        = @("auth", "devicecode")

    Setup = { }

    Execute = {
        param($Context)

        $appliance = $Context.Appliance
        $deviceCodeToolDir = Join-Path $Context.TestRoot "SafeguardDotNetDeviceCodeLoginTester"

        # ── Error path: invalid appliance (no human interaction needed) ──

        Test-SgDnAssertThrows "Device code login with invalid appliance returns connection error" {
            Invoke-SgDnSafeguardTool -ProjectDir $deviceCodeToolDir `
                -Arguments "$appliance.invalid.nonexistent true" `
                -TimeoutSeconds 30 `
                -ParseJson $false
        } -ExpectedMessage "Device authorization request failed"

        # ── Error path: grant type disabled ──
        # This test assumes Device Code grant is NOT enabled on the appliance.
        # If it IS enabled, the test will be skipped.

        Test-SgDnAssert "Device code login with grant disabled returns clear error" {
            try {
                $result = Invoke-SgDnSafeguardTool -ProjectDir $deviceCodeToolDir `
                    -Arguments "$appliance true" `
                    -TimeoutSeconds 30 `
                    -ParseJson $false
                # If we get here without error, grant is enabled — skip
                Test-SgDnSkip "Device Code grant is enabled on this appliance; skipping disabled-grant test"
                return $true
            }
            catch {
                $msg = $_.Exception.Message
                $msg -like "*OAuth2DeviceCodeNotAllowed*" -or $msg -like "*Device authorization request failed*"
            }
        }

        # ── Error path: expired code (let it time out without authenticating) ──
        # Note: This test takes ~5 minutes (300s code expiry + polling interval).
        # Only run if explicitly requested via tag filter.

        if ($Context.Tags -contains "slow") {
            Test-SgDnAssertThrows "Device code expires when user does not authenticate" {
                Invoke-SgDnSafeguardTool -ProjectDir $deviceCodeToolDir `
                    -Arguments "$appliance true" `
                    -TimeoutSeconds 330 `
                    -ParseJson $false
            } -ExpectedMessage "expired"
        }
        else {
            Test-SgDnSkip "Skipping code-expiry test (takes 5 minutes). Use -Tags 'slow' to include."
        }

        # ── Happy path: interactive (human must open URL and authenticate) ──
        # Tagged 'interactive' — only runs when explicitly requested.

        if ($Context.Tags -contains "interactive") {
            Test-SgDnAssert "Device code full flow succeeds with human authentication" {
                $result = Invoke-SgDnSafeguardTool -ProjectDir $deviceCodeToolDir `
                    -Arguments "$appliance true" `
                    -TimeoutSeconds 300 `
                    -ParseJson $false
                $result -like "*Successfully connected*"
            }
        }
        else {
            Test-SgDnSkip "Skipping interactive device code test. Use -Tags 'interactive' to include."
        }
    }

    Cleanup = {
        param($Context)
        # No test objects to clean up — suite uses pre-existing appliance configuration.
    }
}
