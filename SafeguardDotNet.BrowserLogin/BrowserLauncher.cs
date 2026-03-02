// Copyright (c) One Identity LLC. All rights reserved.

namespace OneIdentity.SafeguardDotNet.BrowserLogin
{
    using System;
    using System.Diagnostics;
    using System.Runtime.InteropServices;

    internal class BrowserLauncher
    {
        private readonly string _appliance;
        private readonly string _oauthCodeVerifier;

        public BrowserLauncher(string appliance, string oauthCodeVerifier)
        {
            _appliance = appliance;
            _oauthCodeVerifier = oauthCodeVerifier;
        }

        public void Show(string username, int port)
        {
            var redirectUri = Safeguard.AgentBasedLoginUtils.RedirectUriTcpListener;
            var codeChallenge = Safeguard.AgentBasedLoginUtils.OAuthCodeChallenge(_oauthCodeVerifier);
            var accessTokenUri = $"https://{_appliance}/RSTS/Login?response_type=code&code_challenge_method=S256&" +
                $"code_challenge={codeChallenge}&redirect_uri={redirectUri}&port={port}";

            if (!string.IsNullOrEmpty(username))
            {
                accessTokenUri += $"&login_hint={Uri.EscapeDataString(username)}";
            }

            try
            {
                var psi = new ProcessStartInfo { FileName = accessTokenUri, UseShellExecute = true };
                Process.Start(psi);
            }
            catch (Exception ex)
            {
                // hack because of this: https://github.com/dotnet/corefx/issues/10361
                if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
                {
                    accessTokenUri = accessTokenUri.Replace("&", "^&");
                    Process.Start(new ProcessStartInfo(accessTokenUri));
                }
                else if (RuntimeInformation.IsOSPlatform(OSPlatform.Linux))
                {
                    Process.Start("xdg-open", accessTokenUri);
                }
                else if (RuntimeInformation.IsOSPlatform(OSPlatform.OSX))
                {
                    Process.Start("open", accessTokenUri);
                }
                else
                {
                    throw new SafeguardDotNetException("Unable to launch default browser", ex);
                }
            }
        }
    }
}
