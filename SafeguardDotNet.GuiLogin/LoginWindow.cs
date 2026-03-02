// Copyright (c) One Identity LLC. All rights reserved.

namespace OneIdentity.SafeguardDotNet.GuiLogin
{
    using Serilog;

    /// <summary>
    /// Provides GUI-based authentication to Safeguard using OAuth2/PKCE flow with an embedded browser control.
    /// This class displays a Windows Forms dialog containing a web view for interactive user authentication.
    /// </summary>
    public static class LoginWindow
    {
        /// <summary>
        /// Connect to Safeguard by displaying a GUI login window with an embedded browser for OAuth2/PKCE authentication.
        /// The user interacts with the Safeguard login page within a Windows Forms dialog.
        /// </summary>
        /// <param name="appliance">Network address of Safeguard appliance</param>
        /// <param name="apiVersion">Target API version to use (default: 4)</param>
        /// <param name="ignoreSsl">Ignore validation of Safeguard appliance SSL certificate (default: false)</param>
        /// <returns>Reusable Safeguard API connection</returns>
        public static ISafeguardConnection Connect(string appliance, int apiVersion = Safeguard.DefaultApiVersion, bool ignoreSsl = false)
        {
            Log.Debug("Calling RSTS for primary authentication");

            var rstsWindow = new RstsWindow(appliance);

            if (rstsWindow.Show())
            {
                if (string.IsNullOrEmpty(rstsWindow.AuthorizationCode))
                {
                    throw new SafeguardDotNetException("Unable to obtain authorization code");
                }

                Log.Debug("Redeeming RSTS authorization code");

                using (var rstsAccessToken = Safeguard.AgentBasedLoginUtils.PostAuthorizationCodeFlow(
                    appliance, rstsWindow.AuthorizationCode, rstsWindow.CodeVerifier, Safeguard.AgentBasedLoginUtils.RedirectUri))
                {
                    Log.Debug("Exchanging RSTS access token");

                    var responseObject = Safeguard.AgentBasedLoginUtils.PostLoginResponse(appliance, rstsAccessToken);

                    var statusValue = responseObject.GetValue("Status")?.ToString();

                    if (string.IsNullOrEmpty(statusValue) || statusValue != "Success")
                    {
                        throw new SafeguardDotNetException($"Error response status {statusValue} from login response service");
                    }

                    using (var accessToken = responseObject.GetValue("UserToken")?.ToString().ToSecureString())
                    {
                        return Safeguard.Connect(appliance, accessToken, apiVersion, ignoreSsl);
                    }
                }
            }
            else
            {
                throw new SafeguardDotNetException("Unable to correctly manipulate browser");
            }
        }
    }
}
