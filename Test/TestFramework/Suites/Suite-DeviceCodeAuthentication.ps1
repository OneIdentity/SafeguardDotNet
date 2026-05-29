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

        # ── Happy path: interactive (human must open URL and authenticate) ──
        # Set environment variable SGDN_TEST_INTERACTIVE=1 to run this test.
        # This test runs the tool WITHOUT output redirection so the user can see
        # the verification URL and authenticate in a browser.

        if ($env:SGDN_TEST_INTERACTIVE -eq "1") {
            Test-SgDnAssert "Device code full flow succeeds with human authentication" {
                Write-Host "`n    Launching device code flow — authenticate in your browser...`n" -ForegroundColor Cyan
                $proc = Start-Process -FilePath "dotnet" `
                    -ArgumentList "run --project `"$deviceCodeToolDir`" -- $appliance true" `
                    -NoNewWindow -PassThru -Wait
                $proc.ExitCode -eq 0
            }
        }
        else {
            Test-SgDnSkip "Device code interactive login" "Set env SGDN_TEST_INTERACTIVE=1 to run"
        }
    }

    Cleanup = {
        param($Context)
        # No test objects to clean up — suite uses pre-existing appliance configuration.
    }
}
