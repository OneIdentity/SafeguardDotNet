using System.Security;
using Newtonsoft.Json.Linq;
using RestSharp;
using Serilog;

namespace OneIdentity.SafeguardDotNet.BrowserLogin
{
    public static class DefaultBrowserLogin
    {
        private const int DefaultApiVersion = 3;

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

        public static ISafeguardConnection Connect(string appliance, string primaryProviderId = "", string secondaryProviderId = "", string username = "", int port = 8400)
        {
            Log.Debug("Calling RSTS for primary authentication");
            var te = new TokenExtractor(appliance);
            if (te.Show(primaryProviderId, secondaryProviderId, username, port))
            {
                if (string.IsNullOrEmpty(te.AccessToken?.ToInsecureString()))
                    throw new SafeguardDotNetException("Unable to obtain access token from redirect");
                Log.Debug("Posting second RSTS access token to login response service");
                var responseObject = PostLoginResponse(appliance, te.AccessToken);
                var statusValue = responseObject.GetValue("Status")?.ToString();
                if (statusValue != null && !statusValue.Equals("Success"))
                    throw new SafeguardDotNetException($"Error response status {statusValue} from login response service");
                using (var accessToken = responseObject.GetValue("UserToken")?.ToString().ToSecureString())
                    return Safeguard.Connect(appliance, accessToken, DefaultApiVersion, true);
            }

            throw new SafeguardDotNetException("Unable to correctly manipulate the browser for Safeguard login");
        }
    }
}
