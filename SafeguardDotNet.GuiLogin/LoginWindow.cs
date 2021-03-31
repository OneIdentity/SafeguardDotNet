using System.Security;
using Newtonsoft.Json.Linq;
using RestSharp;
using Serilog;

namespace OneIdentity.SafeguardDotNet.GuiLogin
{
    public static class LoginWindow
    {
        private const int DefaultApiVersion = 3;

        private const string ClientId = "00000000-0000-0000-0000-000000000000";
        private const string RedirectUri = "urn:InstalledApplication";

        private static RstsWindow _rstsWindow;

        private static string ShowRstsWindow(string primaryProviderId = "", string secondaryProviderId = "")
        {
            if (_rstsWindow == null)
            {
                throw new SafeguardDotNetException("Please call primary rsts show method");
            }
            if (!_rstsWindow.Show(primaryProviderId, secondaryProviderId))
            {
                throw new SafeguardDotNetException("Unable to correctly manipulate browser");
            }
            if (string.IsNullOrEmpty(_rstsWindow.AuthorizationCode))
            {
                throw new SafeguardDotNetException("Unable to obtain authorization code");
            }
            return _rstsWindow.AuthorizationCode;
        }

        private static string ShowRstsWindowPrimary(string appliance)
        {
            _rstsWindow = new RstsWindow(appliance);
            return ShowRstsWindow(appliance);
        }

        private static string ShowRstsWindowSecondary(string primaryProviderId = "", string secondaryProviderId = "")
        {
            var authorizationCode = ShowRstsWindow(primaryProviderId, secondaryProviderId);
            _rstsWindow = null;
            return authorizationCode;
        }

        private static SecureString PostAuthorizationCodeFlow(string appliance, string authorizationCode)
        {
            var safeguardRstsUrl = $"https://{appliance}/RSTS";
            var rstsClient = new RestClient(safeguardRstsUrl);
            // The client would have already ignored certificate validation manually in the browser
            rstsClient.RemoteCertificateValidationCallback += (sender, certificate, chain, errors) => true;
            var request = new RestRequest("oauth2/token", RestSharp.Method.POST)
                .AddHeader("Accept", "application/json")
                .AddHeader("Content-type", "application/json")
                .AddJsonBody(new
                {
                    grant_type = "authorization_code",
                    client_id = ClientId,
                    redirect_uri = RedirectUri,
                    code = authorizationCode
                });
            var response = rstsClient.Execute(request);
            if (response.ResponseStatus != ResponseStatus.Completed)
                throw new SafeguardDotNetException($"Unable to connect to RSTS service {rstsClient.BaseUrl}, Error: " +
                                                   response.ErrorMessage);
            if (!response.IsSuccessful)
                throw new SafeguardDotNetException(
                    "Error using authorization code grant_type, Error: " + $"{response.StatusCode} {response.Content}",
                    response.StatusCode, response.Content);
            var jObject = JObject.Parse(response.Content);
            return jObject.GetValue("access_token")?.ToString().ToSecureString();
        }

        private static JObject PostLoginResponse(string appliance, SecureString rstsAccessToken)
        {
            var safeguardCoreUrl = $"https://{appliance}/service/core/v{DefaultApiVersion}";
            var coreClient = new RestClient(safeguardCoreUrl);
            // The client would have already ignored certificate validation manually in the browser
            coreClient.RemoteCertificateValidationCallback += (sender, certificate, chain, errors) => true;
            var request = new RestRequest("Token/LoginResponse", RestSharp.Method.POST)
                .AddHeader("Accept", "application/json")
                .AddHeader("Content-type", "application/json")
                .AddJsonBody(new
                {
                    StsAccessToken = rstsAccessToken.ToInsecureString()
                });
            var response = coreClient.Execute(request);
            if (response.ResponseStatus != ResponseStatus.Completed)
                throw new SafeguardDotNetException($"Unable to connect to core service {coreClient.BaseUrl}, Error: " +
                                                   response.ErrorMessage);
            if (!response.IsSuccessful)
                throw new SafeguardDotNetException(
                    "Error using authorization code grant_type, Error: " + $"{response.StatusCode} {response.Content}",
                    response.StatusCode, response.Content);
            return JObject.Parse(response.Content);
        }

        public static ISafeguardConnection Connect(string appliance)
        {
            Log.Debug("Calling RSTS for primary authentication");
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
        }
    }
}
