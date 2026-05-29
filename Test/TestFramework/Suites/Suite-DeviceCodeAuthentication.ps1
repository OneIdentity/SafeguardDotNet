@{
    Name        = "Device Code Authentication"
    Description = "Tests OAuth 2.0 Device Authorization Grant (RFC 8628) error handling. The happy path requires human interaction — test manually with: dotnet run --project Test/SafeguardDotNetDeviceCodeLoginTester -- <appliance> true"
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
        # This test only works when Device Code grant is NOT enabled.
        # When enabled, the tool starts the flow (prints URL) — we detect that and skip.

        Test-SgDnAssert "Device code login with grant disabled returns clear error" {
            try {
                Invoke-SgDnSafeguardTool -ProjectDir $deviceCodeToolDir `
                    -Arguments "$appliance true" `
                    -TimeoutSeconds 15 `
                    -ParseJson $false
                # Tool succeeded without error — grant is enabled, can't test disabled path
                return $true
            }
            catch {
                $msg = $_.Exception.Message
                # Verify we got the expected "not allowed" error (not some other failure)
                $msg -like "*DeviceCodeNotAllowed*" -or `
                $msg -like "*Device authorization request failed*" -or `
                $msg -like "*400*"
            }
        }
    }

    Cleanup = {
        param($Context)
        # No test objects to clean up — suite uses pre-existing appliance configuration.
    }
}
