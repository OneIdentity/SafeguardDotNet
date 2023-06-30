using System;
using Serilog;

namespace OneIdentity.SafeguardDotNet.BrowserLogin
{
    public static class DefaultBrowserLogin
    {
        private const int DefaultApiVersion = 4;
        private const string RedirectUri = "urn:InstalledApplication";

        public static ISafeguardConnection Connect(string appliance, string username = "", int port = 8400)
        {
            Log.Debug("Calling RSTS for primary authentication");

            var tokenExtractor = new TokenExtractor(appliance);

            if (tokenExtractor.Show(username, port))
            {
                if (string.IsNullOrEmpty(tokenExtractor.AuthorizationCode))
                {
                    throw new SafeguardDotNetException("Unable to obtain authorization code");
                }

                Log.Debug("Posting RSTS access code to login response service");

                using (var rstsAccessToken = Safeguard.PostAuthorizationCodeFlow(appliance, new Tuple<string, string>(tokenExtractor.AuthorizationCode, tokenExtractor.CodeVerifier), RedirectUri))
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

            throw new SafeguardDotNetException("Unable to correctly manipulate the browser for Safeguard login");
        }
    }
}
