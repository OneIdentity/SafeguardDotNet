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
        $deviceCodeToolDir = $Context.DeviceCodeToolDir
        $settingName = $Context.SuiteData["SettingName"]
        $originalValue = $Context.SuiteData["OriginalGrantTypes"]

        # ── Error path: invalid appliance (no human interaction needed) ──

        Test-SgDnAssertThrows "Device code login with invalid appliance returns connection error" {
            Invoke-SgDnSafeguardTool -ProjectDir $deviceCodeToolDir `
                -Arguments "-a $appliance.invalid.nonexistent -x" `
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

        # The library now reactively detects the disabled grant and returns a clear
        # message instructing the operator to enable DeviceCode, rather than only the
        # generic "Device authorization request failed" text.
        Test-SgDnAssert "Device code login with grant disabled returns clear enable-DeviceCode error" {
            $threw = $false
            $msg = ""
            try {
                Invoke-SgDnSafeguardTool -ProjectDir $deviceCodeToolDir `
                    -Arguments "-a $appliance -x" `
                    -TimeoutSeconds 30 `
                    -ParseJson $false
            }
            catch {
                $threw = $true
                $msg = $_.Exception.Message
            }
            $threw -and (($msg -match "Allowed OAuth2 Grant Types") -or ($msg -match "DeviceCode grant type is not allowed"))
        }

        # ── Happy path: DeviceCode grant enabled — verification URL is issued ──

        # Ensure DeviceCode is in allowed grants
        $withDeviceCode = $originalValue
        if ($withDeviceCode -notmatch "DeviceCode") {
            $withDeviceCode = if ($withDeviceCode) { "$withDeviceCode, DeviceCode" } else { "DeviceCode" }
        }
        Write-Host "    Enabling DeviceCode grant (setting to: '$withDeviceCode')..." -ForegroundColor DarkGray
        Invoke-SgDnSafeguardApi -Context $Context -Service Core -Method Put `
            -RelativeUrl "Settings/$([uri]::EscapeDataString($settingName))" `
            -Body @{ Value = $withDeviceCode } | Out-Null

        # Require positive proof that a verification URL / device code was issued.
        # A bare timeout with no URL evidence is NOT sufficient. The tester runs in
        # non-interactive mode (-n) so it emits structured DEVICE_CODE_DATA, and the
        # framework surfaces stdout captured before the polling timeout.
        Test-SgDnAssert "Device code login with grant enabled issues a verification URL" {
            $captured = ""
            try {
                $captured = Invoke-SgDnSafeguardTool -ProjectDir $deviceCodeToolDir `
                    -Arguments "-a $appliance -x -n" `
                    -TimeoutSeconds 25 `
                    -ParseJson $false
            }
            catch {
                # On the expected polling timeout the framework includes the captured
                # output in the exception message.
                $captured = $_.Exception.Message
            }
            ($captured -match "verification_uri") -or
            ($captured -match "DEVICE_CODE_DATA") -or
            ($captured -match "https?://\S+Device")
        }

        # ── Opt-in: scripted local/no-MFA approval (best-effort, skippable) ──
        #
        # Layered on top of the baseline above so the suite still provides useful
        # coverage when this is skipped. Pinned to the local provider with no MFA and
        # gated behind an explicit opt-in because the rSTS device-approval POST
        # sequence is not proven by the existing PKCE helper.
        $scriptedApprovalOptIn = $env:SGDN_DEVICECODE_SCRIPTED_APPROVAL -eq "1"

        if (-not $scriptedApprovalOptIn) {
            Test-SgDnSkip "Device code scripted approval (local, no MFA)" `
                "Opt-in only; set SGDN_DEVICECODE_SCRIPTED_APPROVAL=1 to enable scripted approval"
        }
        elseif (-not [string]::IsNullOrEmpty($Context.TotpSeed)) {
            Test-SgDnSkip "Device code scripted approval (local, no MFA)" `
                "MFA/TOTP configured; automated single-step device approval is not supported"
        }
        else {
            # DeviceCode is already enabled above. Begin device-code login in the
            # tester (non-interactive) and capture the structured device-code data the
            # suite would drive approval against.
            $deviceData = ""
            try {
                $deviceData = Invoke-SgDnSafeguardTool -ProjectDir $deviceCodeToolDir `
                    -Arguments "-a $appliance -x -n" `
                    -TimeoutSeconds 20 `
                    -ParseJson $false
            }
            catch {
                $deviceData = $_.Exception.Message
            }

            if ($deviceData -notmatch "DEVICE_CODE_DATA") {
                Test-SgDnAssert "Device code scripted approval exposes structured device-code data" { $false }
            }
            else {
                # The tester exposes verification_uri_complete / user_code / expires_in
                # for parallel approval, but driving the live rSTS approval ceremony
                # (the LoginController loginRequestStep sequence with the
                # device-completion context) is not yet validated against an appliance,
                # so the live approval drive is skipped rather than failing the suite.
                Test-SgDnSkip "Device code scripted approval (local, no MFA)" `
                    "Structured device-code data exposed; live rSTS approval drive pending appliance validation"
            }
        }
    }

    Cleanup = {
        param($Context)
        # Registered cleanup restores the original grant types setting.
    }
}
