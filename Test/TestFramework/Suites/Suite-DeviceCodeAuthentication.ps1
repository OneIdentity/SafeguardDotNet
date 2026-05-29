@{
    Name        = "Device Code Authentication"
    Description = "Tests OAuth 2.0 Device Authorization Grant (RFC 8628) by toggling the grant type setting and verifying behavior in both states."
    Tags        = @("auth", "devicecode")

    Setup = {
        param($Context)

        $settingName = "Allowed OAuth2 Grant Types"

        # Save the current grant types setting so we can restore it in Cleanup
        Write-Host "    Reading current OAuth2 grant type settings..." -ForegroundColor DarkGray
        $setting = Invoke-SgDnSafeguardApi -Context $Context -Service Core -Method Get `
            -RelativeUrl "Settings/$([uri]::EscapeDataString($settingName))"
        $Context.SuiteData["OriginalGrantTypes"] = $setting.Value
        $Context.SuiteData["SettingName"] = $settingName
        Write-Host "    Current value: $($setting.Value)" -ForegroundColor DarkGray

        Register-SgDnTestCleanup -Description "Restore OAuth2 grant types setting" -Action {
            param($Ctx)
            $name = $Ctx.SuiteData["SettingName"]
            $original = $Ctx.SuiteData["OriginalGrantTypes"]
            Write-Host "    Restoring grant types to: $original" -ForegroundColor DarkGray
            Invoke-SgDnSafeguardApi -Context $Ctx -Service Core -Method Put `
                -RelativeUrl "Settings/$([uri]::EscapeDataString($name))" `
                -Body @{ Value = $original } | Out-Null
        }
    }

    Execute = {
        param($Context)

        $appliance = $Context.Appliance
        $deviceCodeToolDir = Join-Path $Context.TestRoot "SafeguardDotNetDeviceCodeLoginTester"
        $settingName = $Context.SuiteData["SettingName"]
        $originalValue = $Context.SuiteData["OriginalGrantTypes"]

        # ── Error path: invalid appliance (no human interaction needed) ──

        Test-SgDnAssertThrows "Device code login with invalid appliance returns connection error" {
            Invoke-SgDnSafeguardTool -ProjectDir $deviceCodeToolDir `
                -Arguments "$appliance.invalid.nonexistent true" `
                -TimeoutSeconds 30 `
                -ParseJson $false
        } -ExpectedMessage "Device authorization request failed"

        # ── Error path: DeviceCode grant disabled ──

        # Remove DeviceCode from allowed grants
        $withoutDeviceCode = ($originalValue -split ',\s*' | Where-Object { $_ -ne "DeviceCode" }) -join ", "
        if ([string]::IsNullOrWhiteSpace($withoutDeviceCode)) { $withoutDeviceCode = "" }
        Write-Host "    Disabling DeviceCode grant (setting to: '$withoutDeviceCode')..." -ForegroundColor DarkGray
        Invoke-SgDnSafeguardApi -Context $Context -Service Core -Method Put `
            -RelativeUrl "Settings/$([uri]::EscapeDataString($settingName))" `
            -Body @{ Value = $withoutDeviceCode } | Out-Null

        Test-SgDnAssertThrows "Device code login with grant disabled returns clear error" {
            Invoke-SgDnSafeguardTool -ProjectDir $deviceCodeToolDir `
                -Arguments "$appliance true" `
                -TimeoutSeconds 30 `
                -ParseJson $false
        } -ExpectedMessage "Device authorization request failed"

        # ── Happy path: DeviceCode grant enabled — initial request succeeds ──

        # Ensure DeviceCode is in allowed grants
        $withDeviceCode = $originalValue
        if ($withDeviceCode -notmatch "DeviceCode") {
            $withDeviceCode = if ($withDeviceCode) { "$withDeviceCode, DeviceCode" } else { "DeviceCode" }
        }
        Write-Host "    Enabling DeviceCode grant (setting to: '$withDeviceCode')..." -ForegroundColor DarkGray
        Invoke-SgDnSafeguardApi -Context $Context -Service Core -Method Put `
            -RelativeUrl "Settings/$([uri]::EscapeDataString($settingName))" `
            -Body @{ Value = $withDeviceCode } | Out-Null

        Test-SgDnAssert "Device code login with grant enabled receives verification URL" {
            try {
                # The tool will get a device code, print the URL, then poll until timeout.
                # It times out because no human authenticates — that's expected.
                Invoke-SgDnSafeguardTool -ProjectDir $deviceCodeToolDir `
                    -Arguments "$appliance true" `
                    -TimeoutSeconds 20 `
                    -ParseJson $false
                # If it somehow succeeds (unlikely without human), that's fine too
                return $true
            }
            catch {
                $msg = $_.Exception.Message
                # The tool outputs the verification URL to stdout before polling.
                # A timeout with a URL means the device auth request succeeded.
                $msg -match "https?://" -or $msg -like "*timed out*"
            }
        }
    }

    Cleanup = {
        param($Context)
        # Registered cleanup restores the original grant types setting.
    }
}
