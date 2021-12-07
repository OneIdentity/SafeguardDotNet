using Serilog;

namespace OneIdentity.SafeguardDotNet.BrowserLogin
{
    public static class DefaultBrowserLogin
    {
        public static ISafeguardConnection Connect(string appliance, string primaryProviderId = "", string secondaryProviderId = "", string username = "", int port = 8400)
        {
            Log.Debug("Calling RSTS for primary authentication");

            return null;

            /*
            var authorizationCode = ShowRstsWindowPrimary(appliance);
            using (var rstsAccessToken = PostAuthorizationCodeFlow(appliance, authorizationCode))
            {
                Log.Debug("Posting RSTS access token to login response service");
                var responseObject = PostLoginResponse(appliance, rstsAccessToken);
                var statusValue = responseObject.GetValue("Status")?.ToString();
                if (statusValue != null && statusValue.Equals("Needs2FA"))
                {
                    Log.Debug("Authentication requires 2FA, continuing with RSTS for secondary authentication");
                    authorizationCode = ShowRstsWindowSecondary(
                        responseObject.GetValue("PrimaryProviderId")?.ToString(),
                        responseObject.GetValue("SecondaryProviderId")?.ToString());
                    using (var secondRstsAccessToken = PostAuthorizationCodeFlow(appliance, authorizationCode))
                    {
                        Log.Debug("Posting second RSTS access token to login response service");
                        responseObject = PostLoginResponse(appliance, secondRstsAccessToken);
                        statusValue = responseObject.GetValue("Status")?.ToString();
                    }
                }
                if (statusValue != null && !statusValue.Equals("Success"))
                    throw new SafeguardDotNetException($"Error response status {statusValue} from login response service");
                using (var accessToken = responseObject.GetValue("UserToken")?.ToString().ToSecureString())
                    return Safeguard.Connect(appliance, accessToken, DefaultApiVersion, true);
            }
            */
        }
    }
}
