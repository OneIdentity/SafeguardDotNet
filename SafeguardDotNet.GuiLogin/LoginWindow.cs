using Serilog;

namespace OneIdentity.SafeguardDotNet.GuiLogin
{
    public static class LoginWindow
    {
        private const int DefaultApiVersion = 4;
        private const string RedirectUri = "urn:InstalledApplication";
        private static RstsWindow rstsWindow;

        public static ISafeguardConnection Connect(string appliance)
        {
            Log.Debug("Calling RSTS for primary authentication");

            rstsWindow = new RstsWindow(appliance);

            if (rstsWindow.Show())
            {
                if (string.IsNullOrEmpty(rstsWindow.AuthorizationCode))
                {
                    throw new SafeguardDotNetException("Unable to obtain authorization code");
                }

                Log.Debug("Redeeming RSTS authorization code");

                using (var rstsAccessToken = Safeguard.PostAuthorizationCodeFlow(appliance, rstsWindow.AuthorizationCode, rstsWindow.CodeVerifier, RedirectUri))
                {
                    Log.Debug("Exchanging RSTS access token");

                    var responseObject = Safeguard.PostLoginResponse(appliance, rstsAccessToken);

                    var statusValue = responseObject.GetValue("Status")?.ToString();

                    if (string.IsNullOrEmpty(statusValue) || statusValue != "Success")
                    {
                        throw new SafeguardDotNetException($"Error response status {statusValue} from login response service");
                    }

                    using (var accessToken = responseObject.GetValue("UserToken")?.ToString().ToSecureString())
                    {
                        return Safeguard.Connect(appliance, accessToken, DefaultApiVersion, true);
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
