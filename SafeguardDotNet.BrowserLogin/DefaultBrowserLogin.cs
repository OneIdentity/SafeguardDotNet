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

                Log.Debug("Redeeming RSTS authorization code");

                using (var rstsAccessToken = Safeguard.PostAuthorizationCodeFlow(appliance, tokenExtractor.AuthorizationCode, tokenExtractor.CodeVerifier, RedirectUri))
                {
                    Log.Debug("Exchanging RSTS access token");

                    var responseObject = Safeguard.PostLoginResponse(appliance, rstsAccessToken);

                    var statusValue = responseObject.GetValue("Status")?.ToString();

                    if (string.IsNullOrEmpty(statusValue) || statusValue != "Success")
                    {
                        throw new SafeguardDotNetException($"Error response status {statusValue} from RSTS");
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
