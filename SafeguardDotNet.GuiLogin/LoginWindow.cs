using System;
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

                Log.Debug("Posting RSTS access code to login response service");

                using (var rstsAccessToken = Safeguard.PostAuthorizationCodeFlow(appliance, new Tuple<string, string>(rstsWindow.AuthorizationCode, rstsWindow.CodeVerifier), RedirectUri))
                {
                    Log.Debug("Posting RSTS access token to login response service");

                    var responseObject = Safeguard.PostLoginResponse(appliance, rstsAccessToken);

                    var statusValue = responseObject.GetValue("Status")?.ToString();

                    if (statusValue != null && !statusValue.Equals("Success"))
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
